//! WAM calls use Microsoft's generated WinRT projection, with polling matching
//! the native executable. There are no interactive calls or cache-file access.
use std::{
    ffi::c_void,
    marker::PhantomData,
    rc::Rc,
    thread,
    time::{Duration, Instant},
};

use windows::{
    core::{Error, Interface, RuntimeType, Type, HSTRING},
    Security::{
        Authentication::Web::Core::{
            FindAllWebAccountsStatus, WebAuthenticationCoreManager, WebTokenRequest,
            WebTokenRequestPromptType, WebTokenRequestResult, WebTokenRequestStatus,
        },
        Credentials::{WebAccount, WebAccountProvider, WebAccountState},
    },
    Win32::{
        Foundation::{ERROR_CANCELLED, E_FAIL, E_UNEXPECTED, RPC_E_CHANGED_MODE, WAIT_TIMEOUT},
        Globalization::{CompareStringOrdinal, CSTR_EQUAL},
        System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED},
    },
};
use windows_future::{AsyncStatus, IAsyncOperation};

use crate::{
    options::Options,
    report::{self, Account, Failure},
    PROVIDER_ID,
};

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::runtime(error.code().0)
    }
}

// RoInitialize and RoUninitialize must run on the same thread. Rc's marker
// prevents moving or sharing this guard between threads.
struct Apartment {
    uninitialize: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Apartment {
    fn initialize() -> Result<Self, Failure> {
        // SAFETY: initialize the calling thread before any WinRT activation.
        let initialized = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
        let uninitialize = match initialized {
            Ok(()) => true, // includes S_FALSE; both successes need balancing
            Err(error) if error.code() == RPC_E_CHANGED_MODE => false,
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            uninitialize,
            _thread_bound: PhantomData,
        })
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.uninitialize {
            // SAFETY: this thread owns a successful initialization and all local
            // WAM objects have been dropped before the guard is dropped.
            unsafe { RoUninitialize() };
        }
    }
}

fn wait<T: RuntimeType + 'static>(
    operation: &IAsyncOperation<T>,
    timeout: Duration,
) -> Result<(), Failure> {
    let started = Instant::now();
    loop {
        match operation.Status()? {
            AsyncStatus::Completed => return Ok(()),
            AsyncStatus::Canceled => {
                return Err(Error::from_hresult(windows::core::HRESULT::from_win32(
                    ERROR_CANCELLED.0,
                ))
                .into())
            }
            AsyncStatus::Error => {
                let code = operation.ErrorCode()?;
                // A failed async operation should have a failed HRESULT.
                return Err(Failure::runtime(if code.is_err() {
                    code.0
                } else {
                    E_FAIL.0
                }));
            }
            AsyncStatus::Started => {}
            _ => return Err(Failure::runtime(E_UNEXPECTED.0)),
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            let _ = operation.Cancel();
            // Preserve the C executable's runtime_error / exit 40 / 0x80070102.
            return Err(Failure::runtime(
                windows::core::HRESULT::from_win32(WAIT_TIMEOUT.0).0,
            ));
        }
        thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}

fn get_optional_result<T: Interface + RuntimeType + Type<T, Abi = *mut c_void> + 'static>(
    operation: &IAsyncOperation<T>,
    timeout: Duration,
) -> Result<Option<T>, Failure> {
    wait(operation, timeout)?;
    let mut raw = std::ptr::null_mut();
    // SAFETY: call the generated GetResults signature on its matching interface.
    // Its out parameter is an owned COM interface pointer or null. The public
    // GetResults wrapper rejects a successful null, which is meaningful for WAM
    // lookups. Check the HRESULT first, then transfer the non-null reference into
    // a Rust owner exactly once. A real failed HRESULT stays an error.
    unsafe {
        (operation.vtable().GetResults)(operation.as_raw(), &mut raw).ok()?;
        Ok(if raw.is_null() {
            None
        } else {
            Some(T::from_raw(raw))
        })
    }
}

fn get_result<T: Interface + RuntimeType + Type<T, Abi = *mut c_void> + 'static>(
    operation: &IAsyncOperation<T>,
    timeout: Duration,
) -> Result<T, Failure> {
    get_optional_result(operation, timeout)?.ok_or_else(|| Failure::runtime(E_UNEXPECTED.0))
}

fn account_report(account: &WebAccount) -> Result<Account, Failure> {
    let state = match account.State()? {
        WebAccountState::None => "None",
        WebAccountState::Connected => "Connected",
        WebAccountState::Error => "Error",
        _ => "Unknown",
    };
    Ok(Account {
        account_id: account.Id()?.to_string_lossy(),
        username: account.UserName()?.to_string_lossy(),
        state,
    })
}

fn find_accounts(
    provider: &WebAccountProvider,
    options: &Options,
) -> Result<Vec<WebAccount>, Failure> {
    let operation = WebAuthenticationCoreManager::FindAllAccountsWithClientIdAsync(
        provider,
        &HSTRING::from(&options.client_id),
    )?;
    let result = get_result(&operation, options.timeout)?;
    let status = result.Status()?;
    if status != FindAllWebAccountsStatus::Success {
        return Err(Failure::discovery(status.0));
    }
    let accounts = result.Accounts()?;
    let count = accounts.Size()?;
    (0..count)
        .map(|index| accounts.GetAt(index).map_err(Failure::from))
        .collect()
}

fn select_username(accounts: Vec<WebAccount>, username: &str) -> Result<WebAccount, Failure> {
    let target: Vec<u16> = username.encode_utf16().collect();
    let mut matches = Vec::new();
    for account in accounts {
        let candidate = account.UserName()?;
        // SAFETY: both slices are valid UTF-16 buffers, with their lengths passed
        // by the generated binding. Ordinal comparison matches the C client,
        // including Windows' non-ASCII case rules (Rust lowercase is different).
        let comparison = unsafe { CompareStringOrdinal(&candidate, &target, true) };
        if comparison.0 == 0 {
            return Err(Error::from_thread().into());
        }
        if comparison == CSTR_EQUAL {
            matches.push(account);
        }
    }
    report::unique_match(matches)
}

fn provider_error(result: &WebTokenRequestResult) -> Option<(u32, Option<u32>)> {
    // These are optional diagnostics; mirror C's best-effort behavior. Do not
    // print the provider's message or the claims challenge, only its length.
    let error = result.ResponseError().ok()?;
    let code = error.ErrorCode().unwrap_or(0);
    let length = error
        .ErrorMessage()
        .ok()
        .map(|message| message.len() as u32);
    Some((code, length))
}

pub fn run(options: &Options) -> Result<serde_json::Value, Failure> {
    let _apartment = Apartment::initialize()?;
    acquire(options)
    // All WinRT objects live inside acquire and are dropped before _apartment.
}

fn find_provider(options: &Options) -> Result<WebAccountProvider, Failure> {
    let operation = WebAuthenticationCoreManager::FindAccountProviderWithAuthorityAsync(
        &HSTRING::from(PROVIDER_ID),
        &HSTRING::from(&options.authority),
    )?;
    get_optional_result(&operation, options.timeout)?
        .ok_or_else(Failure::provider_unavailable)
}

/// One silent token request for a provider. With `account`, the request is
/// pinned to that account; without it, WAM picks its default account.
fn request_token(
    options: &Options,
    provider: &WebAccountProvider,
    account: Option<&WebAccount>,
) -> Result<(String, Option<Account>), Failure> {
    let spec = options.request_spec();
    let request = WebTokenRequest::CreateWithPromptType(
        provider,
        &HSTRING::from(spec.scope),
        &HSTRING::from(&options.client_id),
        WebTokenRequestPromptType::Default,
    )?;
    let properties = request.Properties()?;
    for (key, value) in spec.properties {
        properties.Insert(&HSTRING::from(key), &HSTRING::from(value))?;
    }

    let operation = match account {
        Some(account) => {
            WebAuthenticationCoreManager::GetTokenSilentlyWithWebAccountAsync(&request, account)?
        }
        None => WebAuthenticationCoreManager::GetTokenSilentlyAsync(&request)?,
    };
    let result = get_result(&operation, options.timeout)?;
    let status = result.ResponseStatus()?;
    if status != WebTokenRequestStatus::Success {
        return Err(Failure::token(status.0, provider_error(&result)));
    }
    let responses = result.ResponseData()?;
    if responses.Size()? == 0 {
        return Err(Failure::runtime(E_UNEXPECTED.0));
    }
    let response = responses.GetAt(0)?;
    let token = response.Token()?;
    let account = response
        .WebAccount()
        .ok()
        .as_ref()
        .map(account_report)
        .transpose()?;
    Ok((token.to_string_lossy(), account))
}

fn acquire(options: &Options) -> Result<serde_json::Value, Failure> {
    let provider = find_provider(options)?;

    if options.enumerate_accounts {
        let accounts = find_accounts(&provider, options)?;
        let accounts = accounts
            .iter()
            .map(account_report)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(report::accounts(
            &options.client_id,
            &options.authority,
            accounts,
        ));
    }

    let selected_account = if let Some(username) = &options.username {
        Some(select_username(
            find_accounts(&provider, options)?,
            username,
        )?)
    } else if let Some(account_id) = &options.account_id {
        let operation =
            WebAuthenticationCoreManager::FindAccountAsync(&provider, &HSTRING::from(account_id))?;
        Some(
            get_optional_result(&operation, options.timeout)?
                .ok_or_else(Failure::account_not_found)?,
        )
    } else {
        None
    };

    let (token, account) = request_token(options, &provider, selected_account.as_ref())?;
    Ok(report::token(
        options.resource.is_some(),
        options.claims.is_some(),
        &token,
        token.len(),
        options.hide_token,
        account,
    ))
}

pub struct CollectOutcome {
    pub account: Option<Account>,
    pub result: Result<String, Failure>,
}

/// A silent token request for every account WAM holds. Individual account
/// failures are collected, not fatal; only provider or account discovery
/// failures abort the whole collection.
pub fn collect(options: &Options) -> Result<Vec<CollectOutcome>, Failure> {
    let _apartment = Apartment::initialize()?;
    let provider = find_provider(options)?;
    let accounts = find_accounts(&provider, options)?;
    let mut outcomes = Vec::new();
    for account in accounts {
        let account_report = account_report(&account).ok();
        let result =
            request_token(options, &provider, Some(&account)).map(|(token, _)| token);
        outcomes.push(CollectOutcome {
            account: account_report,
            result,
        });
    }
    Ok(outcomes)
}

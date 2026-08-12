use super::WindowsHostError;
use std::fs;
use std::path::Path;
use windows::core::{IUnknown, Interface, GUID, HRESULT, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::UI::Shell::{AttachmentServices, IAttachmentExecute};

const RPC_E_CHANGED_MODE: i32 = 0x8001_0106_u32 as i32;
const ATTACHMENT_CLIENT_GUID: GUID = GUID::from_u128(0x4c8a43e6_3bd9_4786_a95c_15642af78130);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsAttachmentTrustDecision {
    Enable,
    Prompt,
    Disable,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsAttachmentTrustObservation {
    pub decision: WindowsAttachmentTrustDecision,
    pub check_policy_hresult: i64,
    pub save_hresult: i64,
    pub file_exists_after_save: bool,
    pub file_bytes_after_save: u64,
}

pub fn check_attachment_trust(
    local_path: &Path,
    source_url: &str,
) -> Result<WindowsAttachmentTrustObservation, WindowsHostError> {
    check_attachment_trust_with_referrer(local_path, source_url, source_url)
}

pub fn check_attachment_trust_with_referrer(
    local_path: &Path,
    source_url: &str,
    referrer_url: &str,
) -> Result<WindowsAttachmentTrustObservation, WindowsHostError> {
    validate_inputs(local_path, source_url, referrer_url)?;
    let canonical = fs::canonicalize(local_path).map_err(|error| {
        WindowsHostError::new(format!("attachment path resolve failed: {error}"))
    })?;
    let before = fs::metadata(&canonical)
        .map_err(|error| WindowsHostError::new(format!("attachment metadata failed: {error}")))?;
    if !before.is_file() || before.len() == 0 {
        return Err(WindowsHostError::new(
            "attachment trust requires a non-empty regular file",
        ));
    }
    let initialization = ComInitialization::new()?;
    // SAFETY: COM is initialized for this thread and the in-process class/interface
    // identifiers are fixed Windows Attachment Services values.
    let attachment: IAttachmentExecute = match unsafe {
        CoCreateInstance(&AttachmentServices, None::<&IUnknown>, CLSCTX_INPROC_SERVER)
    } {
        Ok(value) => value,
        Err(error) => {
            drop(initialization);
            return Ok(WindowsAttachmentTrustObservation {
                decision: WindowsAttachmentTrustDecision::Unavailable,
                check_policy_hresult: i64::from(error.code().0),
                save_hresult: 0,
                file_exists_after_save: canonical.exists(),
                file_bytes_after_save: before.len(),
            });
        }
    };
    let path = wide_null(&canonical.to_string_lossy());
    let filename_value = canonical
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| WindowsHostError::new("attachment filename is not Unicode"))?;
    let filename = wide_null(filename_value);
    let source = wide_null(source_url);
    let referrer = wide_null(referrer_url);
    let title = wide_null("D2I controlled download");
    // SAFETY: all COM strings are NUL-terminated and live for each call.
    unsafe {
        attachment
            .SetClientGuid(&ATTACHMENT_CLIENT_GUID)
            .map_err(|error| com_error("SetClientGuid", error))?;
        attachment
            .SetClientTitle(PCWSTR(title.as_ptr()))
            .map_err(|error| com_error("SetClientTitle", error))?;
        attachment
            .SetLocalPath(PCWSTR(path.as_ptr()))
            .map_err(|error| com_error("SetLocalPath", error))?;
        attachment
            .SetFileName(PCWSTR(filename.as_ptr()))
            .map_err(|error| com_error("SetFileName", error))?;
        attachment
            .SetSource(PCWSTR(source.as_ptr()))
            .map_err(|error| com_error("SetSource", error))?;
        attachment
            .SetReferrer(PCWSTR(referrer.as_ptr()))
            .map_err(|error| com_error("SetReferrer", error))?;
    }
    let interface = Interface::as_raw(&attachment);
    let vtable = Interface::vtable(&attachment);
    // SAFETY: interface and vtable belong to the live IAttachmentExecute instance.
    let check_policy = unsafe { (vtable.CheckPolicy)(interface) };
    let (decision, save_hresult) = if check_policy.0 == 0 {
        // SAFETY: Save is called only after an S_OK policy decision on this instance.
        let save = unsafe { (vtable.Save)(interface) };
        if save.is_ok() {
            (WindowsAttachmentTrustDecision::Enable, save)
        } else {
            (WindowsAttachmentTrustDecision::Disable, save)
        }
    } else if check_policy.0 == 1 {
        (WindowsAttachmentTrustDecision::Prompt, HRESULT(0))
    } else {
        (WindowsAttachmentTrustDecision::Disable, HRESULT(0))
    };
    drop(attachment);
    drop(initialization);
    let after = fs::metadata(&canonical).ok();
    Ok(WindowsAttachmentTrustObservation {
        decision,
        check_policy_hresult: i64::from(check_policy.0),
        save_hresult: i64::from(save_hresult.0),
        file_exists_after_save: after.as_ref().is_some_and(fs::Metadata::is_file),
        file_bytes_after_save: after.map_or(0, |value| value.len()),
    })
}

struct ComInitialization {
    uninitialize: bool,
}

impl ComInitialization {
    fn new() -> Result<Self, WindowsHostError> {
        // SAFETY: null reserved pointer and the documented STA mode are supplied.
        let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if result.is_err() && result.0 != RPC_E_CHANGED_MODE {
            return Err(WindowsHostError::new(format!(
                "CoInitializeEx failed: {result:?}"
            )));
        }
        Ok(Self {
            uninitialize: result.is_ok(),
        })
    }
}

impl Drop for ComInitialization {
    fn drop(&mut self) {
        if self.uninitialize {
            // SAFETY: this balances the successful CoInitializeEx on the same thread.
            unsafe { CoUninitialize() };
        }
    }
}

fn validate_inputs(
    local_path: &Path,
    source_url: &str,
    referrer_url: &str,
) -> Result<(), WindowsHostError> {
    if !local_path.is_absolute()
        || source_url.len() > 4096
        || referrer_url.len() > 4096
        || !source_url.starts_with("https://")
        || !referrer_url.starts_with("https://")
        || source_url.chars().any(char::is_control)
        || referrer_url.chars().any(char::is_control)
    {
        return Err(WindowsHostError::new(
            "attachment trust input must be an absolute file and public HTTPS source",
        ));
    }
    let metadata = fs::symlink_metadata(local_path).map_err(|error| {
        WindowsHostError::new(format!("attachment path inspect failed: {error}"))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(WindowsHostError::new(
            "attachment trust path cannot be a symbolic link",
        ));
    }
    Ok(())
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn com_error(operation: &str, error: windows::core::Error) -> WindowsHostError {
    WindowsHostError::new(format!("IAttachmentExecute::{operation} failed: {error}"))
}

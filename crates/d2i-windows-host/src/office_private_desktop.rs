use super::WindowsHostError;
use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::GetShortPathNameW;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CreateDesktopW, GetThreadDesktop, SetThreadDesktop, DESKTOP_CONTROL_FLAGS,
    DESKTOP_CREATEWINDOW, DESKTOP_ENUMERATE, DESKTOP_READOBJECTS, DESKTOP_WRITEOBJECTS, HDESK,
};
use windows::Win32::System::Threading::GetCurrentThreadId;

pub(crate) struct OfficePrivateDesktop {
    original: HDESK,
    private: HDESK,
    active: bool,
}

impl OfficePrivateDesktop {
    pub(crate) fn enter(application: &str) -> Result<Self, WindowsHostError> {
        let name = format!(
            "d2i-office500-{}-{}",
            application.to_ascii_lowercase(),
            std::process::id()
        );
        let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        // SAFETY: GetCurrentThreadId has no preconditions and GetThreadDesktop borrows the
        // desktop associated with that live thread.
        let original = unsafe { GetThreadDesktop(GetCurrentThreadId()) }.map_err(|error| {
            WindowsHostError::new(format!(
                "{application} original desktop lookup failed: {error}"
            ))
        })?;
        let access = DESKTOP_CREATEWINDOW.0
            | DESKTOP_ENUMERATE.0
            | DESKTOP_READOBJECTS.0
            | DESKTOP_WRITEOBJECTS.0;
        // SAFETY: the name is null-terminated and the returned handle remains owned here.
        let private = unsafe {
            CreateDesktopW(
                PCWSTR(name.as_ptr()),
                PCWSTR::null(),
                None,
                DESKTOP_CONTROL_FLAGS(0),
                access,
                None,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!(
                "{application} private desktop creation failed: {error}"
            ))
        })?;
        // SAFETY: this thread has not created windows and private is a valid owned desktop.
        if let Err(error) = unsafe { SetThreadDesktop(private) } {
            // SAFETY: assignment failed, so no thread uses the owned private desktop.
            let _ = unsafe { CloseDesktop(private) };
            return Err(WindowsHostError::new(format!(
                "{application} private desktop assignment failed: {error}"
            )));
        }
        Ok(Self {
            original,
            private,
            active: true,
        })
    }

    pub(crate) fn leave(mut self) -> Result<(), WindowsHostError> {
        self.release()
    }

    fn release(&mut self) -> Result<(), WindowsHostError> {
        if !self.active {
            return Ok(());
        }
        // SAFETY: original is the borrowed desktop captured before switching this thread.
        unsafe { SetThreadDesktop(self.original) }.map_err(|error| {
            WindowsHostError::new(format!("Office desktop restore failed: {error}"))
        })?;
        // SAFETY: this thread has been restored and private is owned by this wrapper.
        unsafe { CloseDesktop(self.private) }.map_err(|error| {
            WindowsHostError::new(format!("Office private desktop cleanup failed: {error}"))
        })?;
        self.active = false;
        Ok(())
    }
}

impl Drop for OfficePrivateDesktop {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

pub(crate) fn office_export_output_path(path: &Path) -> Result<PathBuf, WindowsHostError> {
    let filename = path
        .file_name()
        .ok_or_else(|| WindowsHostError::new("Office output filename is absent"))?;
    let parent = path
        .parent()
        .ok_or_else(|| WindowsHostError::new("Office output parent is absent"))?
        .canonicalize()
        .map_err(|error| {
            WindowsHostError::new(format!(
                "Office output parent canonicalization failed: {error}"
            ))
        })?;
    let parent_text = parent.to_string_lossy();
    let parent_text = parent_text.strip_prefix(r"\\?\").unwrap_or(&parent_text);
    let wide = parent_text
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: the parent is an existing canonical directory and wide is NUL-terminated.
    let required = unsafe { GetShortPathNameW(PCWSTR(wide.as_ptr()), None) };
    if required == 0 {
        return Ok(PathBuf::from(parent_text).join(filename));
    }
    let capacity = usize::try_from(required)
        .map_err(|_| WindowsHostError::new("Office short path length overflow"))?
        .saturating_add(1);
    let mut short = vec![0_u16; capacity];
    // SAFETY: short has the capacity reported by the first GetShortPathNameW call.
    let written = unsafe { GetShortPathNameW(PCWSTR(wide.as_ptr()), Some(&mut short)) };
    let written = usize::try_from(written)
        .map_err(|_| WindowsHostError::new("Office short path conversion overflow"))?;
    if written == 0 || written >= short.len() {
        return Ok(PathBuf::from(parent_text).join(filename));
    }
    short.truncate(written);
    Ok(PathBuf::from(String::from_utf16_lossy(&short)).join(filename))
}

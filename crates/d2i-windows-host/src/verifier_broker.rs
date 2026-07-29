//! Least-privilege Windows service and named-pipe primitives for WFP verification.

use crate::{WindowsAppContainerChild, WindowsHostError};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Installed identity of the dedicated demand-start verifier service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsVerifierServiceIdentity {
    pub service_name: String,
    pub service_sid: String,
}

/// Kernel-observed identity of one connected named-pipe client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsVerifierPipeCaller {
    pub process_id: u32,
    pub user_sid: String,
    pub session_id: u32,
    pub integrity_level_rid: u32,
    pub elevation_type: String,
    pub is_appcontainer: bool,
    pub appcontainer_sid: Option<String>,
    pub executable: PathBuf,
}

/// One connected pipe instance and its kernel-observed caller.
pub struct WindowsVerifierPipeConnection {
    stream: File,
    caller: WindowsVerifierPipeCaller,
}

impl WindowsVerifierPipeConnection {
    /// Returns the authenticated client identity observed at connection time.
    pub fn caller(&self) -> &WindowsVerifierPipeCaller {
        &self.caller
    }

    /// Reads one length-prefixed bounded request before the deadline.
    pub fn read_message(
        &self,
        maximum_message_bytes: u32,
        timeout: Duration,
    ) -> Result<Vec<u8>, WindowsHostError> {
        platform::read_pipe_message(&self.stream, maximum_message_bytes, timeout)
    }

    /// Writes one length-prefixed bounded response before the deadline.
    pub fn write_message(
        &self,
        message: &[u8],
        maximum_message_bytes: u32,
        timeout: Duration,
    ) -> Result<(), WindowsHostError> {
        self.verify_destination()?;
        platform::write_pipe_message(&self.stream, message, maximum_message_bytes, timeout)
    }

    /// Rechecks that the connected destination still has the same process ID.
    pub fn verify_destination(&self) -> Result<(), WindowsHostError> {
        platform::verify_pipe_destination(&self.stream, self.caller.process_id)
    }
}

/// Installs a LocalService, demand-start, own-process verifier with a Service SID.
pub fn install_verifier_service(
    service_name: &str,
    executable: &Path,
    configuration: &Path,
    owner_sid: &str,
) -> Result<WindowsVerifierServiceIdentity, WindowsHostError> {
    platform::install_verifier_service(service_name, executable, configuration, owner_sid)
}

/// Starts the already-installed demand-start verifier service.
pub fn start_verifier_service(service_name: &str) -> Result<(), WindowsHostError> {
    platform::start_verifier_service(service_name)
}

/// Stops and deletes the dedicated verifier service.
pub fn remove_verifier_service(service_name: &str) -> Result<(), WindowsHostError> {
    platform::remove_verifier_service(service_name)
}

/// Runs a process entry point under the Windows Service Control Manager.
pub fn run_verifier_service_dispatcher(
    service_name: &str,
    entry: fn() -> Result<(), u32>,
) -> Result<(), WindowsHostError> {
    platform::run_verifier_service_dispatcher(service_name, entry)
}

/// Creates one first-instance local pipe and accepts one caller before the deadline.
pub fn accept_verifier_pipe(
    pipe_name: &str,
    service_sid: &str,
    owner_sid: &str,
    maximum_message_bytes: u32,
    timeout: Duration,
) -> Result<WindowsVerifierPipeConnection, WindowsHostError> {
    platform::accept_verifier_pipe(
        pipe_name,
        service_sid,
        owner_sid,
        maximum_message_bytes,
        timeout,
    )
}

/// Connects with identification-only SQOS so the server cannot impersonate the caller.
pub fn connect_verifier_pipe(pipe_name: &str, timeout: Duration) -> Result<File, WindowsHostError> {
    platform::connect_verifier_pipe(pipe_name, timeout)
}

/// Reads one bounded response from a connected verifier pipe before a deadline.
pub fn read_verifier_pipe_message(
    stream: &File,
    maximum_message_bytes: u32,
    timeout: Duration,
) -> Result<Vec<u8>, WindowsHostError> {
    platform::read_pipe_message(stream, maximum_message_bytes, timeout)
}

/// Writes one bounded request to a connected verifier pipe before a deadline.
pub fn write_verifier_pipe_message(
    stream: &File,
    message: &[u8],
    maximum_message_bytes: u32,
    timeout: Duration,
) -> Result<(), WindowsHostError> {
    platform::write_pipe_message(stream, message, maximum_message_bytes, timeout)
}

/// Protects bytes for this machine using DPAPI and purpose entropy.
pub fn protect_local_machine(
    plaintext: &[u8],
    purpose: &[u8],
) -> Result<Vec<u8>, WindowsHostError> {
    platform::protect_local_machine(plaintext, purpose)
}

/// Unprotects machine-bound DPAPI bytes using purpose entropy.
pub fn unprotect_local_machine(
    protected: &[u8],
    purpose: &[u8],
) -> Result<Vec<u8>, WindowsHostError> {
    platform::unprotect_local_machine(protected, purpose)
}

/// Replaces a deployment path DACL with SYSTEM/Administrators full access and
/// verifier Service SID read access.
pub fn harden_path_for_verifier_service(
    path: &Path,
    service_sid: &str,
    inherit_to_children: bool,
) -> Result<Vec<u8>, WindowsHostError> {
    platform::harden_path_for_verifier_service(path, service_sid, inherit_to_children)
}

/// Replaces a dedicated verifier image DACL with SYSTEM/Administrators full
/// access and verifier Service SID read/execute access.
pub fn harden_executable_for_verifier_service(
    path: &Path,
    service_sid: &str,
) -> Result<Vec<u8>, WindowsHostError> {
    platform::harden_executable_for_verifier_service(path, service_sid)
}

/// Checks whether the current process token contains the expected enabled SID.
pub fn current_process_has_sid(sid: &str) -> Result<bool, WindowsHostError> {
    platform::current_process_has_sid(sid)
}

/// Grants only process-query access on the current relay to a verifier Service SID.
pub fn grant_current_process_query_to_verifier(service_sid: &str) -> Result<(), WindowsHostError> {
    platform::grant_current_process_query_to_verifier(service_sid)
}

/// Grants only process-query access on one owned AppContainer child to a
/// verifier Service SID.
pub fn grant_appcontainer_child_query_to_verifier(
    child: &WindowsAppContainerChild,
    service_sid: &str,
) -> Result<(), WindowsHostError> {
    platform::grant_appcontainer_child_query_to_verifier(child, service_sid)
}

/// Observes a fixed process token and executable identity without impersonation.
pub fn inspect_verifier_process(
    process_id: u32,
) -> Result<WindowsVerifierPipeCaller, WindowsHostError> {
    platform::inspect_verifier_process(process_id)
}

/// Returns the kernel snapshot parent process ID for one fixed process.
pub fn process_parent_id(process_id: u32) -> Result<u32, WindowsHostError> {
    platform::process_parent_id(process_id)
}

#[cfg(windows)]
mod platform {
    use super::{
        WindowsAppContainerChild, WindowsHostError, WindowsVerifierPipeCaller,
        WindowsVerifierPipeConnection, WindowsVerifierServiceIdentity,
    };
    use std::ffi::OsStr;
    use std::fs::File;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};
    use windows::core::{HRESULT, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED,
        ERROR_SERVICE_ALREADY_RUNNING, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertStringSidToSidW, GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo,
        EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SDDL_REVISION_1, SE_KERNEL_OBJECT,
        TRUSTEE_IS_SID, TRUSTEE_W,
    };
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
        CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    use windows::Win32::Security::{
        CheckTokenMembership, GetFileSecurityW, GetSidSubAuthority, GetSidSubAuthorityCount,
        GetTokenInformation, LookupAccountNameW, SetFileSecurityW, TokenAppContainerSid,
        TokenElevationType, TokenElevationTypeDefault, TokenElevationTypeFull,
        TokenElevationTypeLimited, TokenIntegrityLevel, TokenIsAppContainer, TokenUser, ACE_FLAGS,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_ACCESS_MASK,
        TOKEN_APPCONTAINER_INFORMATION, TOKEN_ELEVATION_TYPE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_FIRST_PIPE_INSTANCE,
        FILE_FLAG_OVERLAPPED, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_SHARE_MODE,
        OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, WaitNamedPipeW,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Services::{
        ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
        OpenSCManagerW, OpenServiceW, RegisterServiceCtrlHandlerExW, SetServiceObjectSecurity,
        SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW, SC_MANAGER_CONNECT,
        SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
        SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS, SERVICE_REQUIRED_PRIVILEGES_INFOW,
        SERVICE_SID_INFO, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED,
        SERVICE_WIN32_OWN_PROCESS,
    };
    use windows::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
        WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    const MAX_TOKEN_INFORMATION_BYTES: u32 = 1024 * 1024;
    const MAX_PIPE_MESSAGE_BYTES: u32 = 64 * 1024;
    const SERVICE_FULL_ACCESS_MASK: u32 = 0x000f_01ff;
    const SERVICE_RUNTIME_ACCESS_MASK: u32 = 0x0002_0014;
    const SERVICE_DELETE_ACCESS: u32 = 0x0001_0000;
    const SERVICE_SID_TYPE_RESTRICTED_VALUE: u32 = 3;
    const ERROR_SERVICE_NOT_ACTIVE_CODE: u32 = 1062;
    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
    const WRITE_DAC_ACCESS: u32 = 0x0004_0000;

    static SERVICE_NAME: OnceLock<String> = OnceLock::new();
    static SERVICE_ENTRY: OnceLock<fn() -> Result<(), u32>> = OnceLock::new();

    struct ServiceHandle(windows::Win32::System::Services::SC_HANDLE);

    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            // SAFETY: this guard owns the SCM or service handle.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }

    struct LocalDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalDescriptor {
        fn drop(&mut self) {
            // SAFETY: descriptor was allocated by LocalAlloc through SDDL conversion.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
        }
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: this guard owns a live kernel handle.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    pub(super) fn install_verifier_service(
        service_name: &str,
        executable: &Path,
        configuration: &Path,
        owner_sid: &str,
    ) -> Result<WindowsVerifierServiceIdentity, WindowsHostError> {
        validate_service_name(service_name)?;
        validate_sid(owner_sid, "service owner SID", "S-1-")?;
        let executable = canonical_regular_file(executable, "verifier executable")?;
        let configuration = canonical_future_file(configuration, "verifier configuration")?;
        let command = format!(
            "\"{}\" __windows-wfp-broker-service \"{}\"",
            quote_free_path(&executable)?,
            quote_free_path(&configuration)?
        );
        let manager = {
            // SAFETY: null machine/database select the local active SCM database.
            let handle = unsafe {
                OpenSCManagerW(
                    PCWSTR::null(),
                    PCWSTR::null(),
                    SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
                )
            }
            .map_err(|error| {
                WindowsHostError::new(format!("OpenSCManagerW(create) failed: {error}"))
            })?;
            ServiceHandle(handle)
        };
        let service_name_wide = wide(service_name)?;
        let display_name_wide = wide("D2I WFP Verifier Broker")?;
        let command_wide = wide(&command)?;
        let local_service_wide = wide(r"NT AUTHORITY\LocalService")?;
        let service = {
            // SAFETY: all strings are NUL-terminated and live for this call.
            let handle = unsafe {
                CreateServiceW(
                    manager.0,
                    PCWSTR(service_name_wide.as_ptr()),
                    PCWSTR(display_name_wide.as_ptr()),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    PCWSTR(command_wide.as_ptr()),
                    PCWSTR::null(),
                    None,
                    PCWSTR::null(),
                    PCWSTR(local_service_wide.as_ptr()),
                    PCWSTR::null(),
                )
            }
            .map_err(|error| {
                WindowsHostError::new(format!("CreateServiceW verifier failed: {error}"))
            })?;
            ServiceHandle(handle)
        };
        let sid_info = SERVICE_SID_INFO {
            dwServiceSidType: SERVICE_SID_TYPE_RESTRICTED_VALUE,
        };
        // SAFETY: sid_info has the exact layout required by SERVICE_CONFIG_SERVICE_SID_INFO.
        unsafe {
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_SERVICE_SID_INFO,
                Some((&raw const sid_info).cast()),
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!("service SID configuration failed: {error}"))
        })?;
        let mut no_privileges = [0_u16, 0_u16];
        let privileges = SERVICE_REQUIRED_PRIVILEGES_INFOW {
            pmszRequiredPrivileges: PWSTR(no_privileges.as_mut_ptr()),
        };
        // SAFETY: no_privileges is a live empty MULTI_SZ.
        unsafe {
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                Some((&raw const privileges).cast()),
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!("service privilege restriction failed: {error}"))
        })?;
        let service_sid = lookup_account_sid(&format!(r"NT SERVICE\{service_name}"))?;
        set_service_dacl(service.0, owner_sid)?;
        Ok(WindowsVerifierServiceIdentity {
            service_name: service_name.to_owned(),
            service_sid,
        })
    }

    pub(super) fn start_verifier_service(service_name: &str) -> Result<(), WindowsHostError> {
        validate_service_name(service_name)?;
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_service(&manager, service_name, SERVICE_START | SERVICE_QUERY_STATUS)?;
        // SAFETY: service is an installed service handle and no arguments are supplied.
        match unsafe { StartServiceW(service.0, None) } {
            Ok(()) => Ok(()),
            Err(error) if error.code() == HRESULT::from_win32(ERROR_SERVICE_ALREADY_RUNNING.0) => {
                Err(WindowsHostError::new(
                    "verifier service is already running; concurrent reuse is rejected",
                ))
            }
            Err(error) => Err(WindowsHostError::new(format!(
                "StartServiceW verifier failed: {error}"
            ))),
        }
    }

    pub(super) fn remove_verifier_service(service_name: &str) -> Result<(), WindowsHostError> {
        validate_service_name(service_name)?;
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_service(
            &manager,
            service_name,
            SERVICE_DELETE_ACCESS
                | windows::Win32::System::Services::SERVICE_STOP
                | SERVICE_QUERY_STATUS,
        )?;
        let mut status = SERVICE_STATUS::default();
        let stopped = {
            // SAFETY: status is writable and the service handle is live.
            unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &raw mut status) }
        };
        if let Err(error) = stopped {
            if error.code() != HRESULT::from_win32(ERROR_SERVICE_NOT_ACTIVE_CODE) {
                return Err(WindowsHostError::new(format!(
                    "ControlService verifier stop failed: {error}"
                )));
            }
        }
        // SAFETY: service is an owned installed service handle.
        unsafe { DeleteService(service.0) }.map_err(|error| {
            WindowsHostError::new(format!("DeleteService verifier failed: {error}"))
        })
    }

    pub(super) fn run_verifier_service_dispatcher(
        service_name: &str,
        entry: fn() -> Result<(), u32>,
    ) -> Result<(), WindowsHostError> {
        validate_service_name(service_name)?;
        SERVICE_NAME
            .set(service_name.to_owned())
            .map_err(|_| WindowsHostError::new("service dispatcher was initialized twice"))?;
        SERVICE_ENTRY
            .set(entry)
            .map_err(|_| WindowsHostError::new("service entry was initialized twice"))?;
        let mut name = wide(service_name)?;
        let table = [
            windows::Win32::System::Services::SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(name.as_mut_ptr()),
                lpServiceProc: Some(service_main),
            },
            windows::Win32::System::Services::SERVICE_TABLE_ENTRYW::default(),
        ];
        // SAFETY: table remains live until the dispatcher returns and is null-terminated.
        unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }.map_err(|error| {
            WindowsHostError::new(format!("StartServiceCtrlDispatcherW failed: {error}"))
        })
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
        let Some(name) = SERVICE_NAME.get() else {
            return;
        };
        let Ok(name_wide) = wide(name) else {
            return;
        };
        // SAFETY: the service name is live for the registration call and no context is used.
        let Ok(status_handle) = (unsafe {
            RegisterServiceCtrlHandlerExW(
                PCWSTR(name_wide.as_ptr()),
                Some(service_control_handler),
                None,
            )
        }) else {
            return;
        };
        let mut status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_START_PENDING,
            dwControlsAccepted: 0,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 1,
            dwWaitHint: 10_000,
        };
        // SAFETY: status_handle was returned for this service and status is initialized.
        let _ = unsafe { SetServiceStatus(status_handle, &raw const status) };
        status.dwCurrentState = windows::Win32::System::Services::SERVICE_RUNNING;
        status.dwCheckPoint = 0;
        status.dwWaitHint = 0;
        // SAFETY: status_handle remains registered for this callback.
        let _ = unsafe { SetServiceStatus(status_handle, &raw const status) };
        let result = SERVICE_ENTRY.get().map_or(Err(1), |entry| entry());
        status.dwCurrentState = SERVICE_STOPPED;
        match result {
            Ok(()) => {
                status.dwWin32ExitCode = 0;
                status.dwServiceSpecificExitCode = 0;
            }
            Err(code) => {
                status.dwWin32ExitCode = 1066;
                status.dwServiceSpecificExitCode = code.max(1);
            }
        }
        // SAFETY: this is the terminal service status update.
        let _ = unsafe { SetServiceStatus(status_handle, &raw const status) };
    }

    unsafe extern "system" fn service_control_handler(
        _control: u32,
        _event_type: u32,
        _event_data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> u32 {
        0
    }

    pub(super) fn accept_verifier_pipe(
        pipe_name: &str,
        service_sid: &str,
        owner_sid: &str,
        maximum_message_bytes: u32,
        timeout: Duration,
    ) -> Result<WindowsVerifierPipeConnection, WindowsHostError> {
        validate_pipe_name(pipe_name)?;
        validate_sid(service_sid, "verifier Service SID", "S-1-5-80-")?;
        validate_sid(owner_sid, "verifier owner SID", "S-1-")?;
        if maximum_message_bytes == 0 || maximum_message_bytes > MAX_PIPE_MESSAGE_BYTES {
            return Err(WindowsHostError::new(
                "verifier pipe message bound must be within 1..=65536 bytes",
            ));
        }
        let full_name = pipe_path(pipe_name);
        let full_name_wide = wide(&full_name)?;
        let sddl = format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;{service_sid})(A;;GRGW;;;{owner_sid})\
             S:(ML;;NW;;;ME)"
        );
        let descriptor = descriptor_from_sddl(&sddl)?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| WindowsHostError::new("security attributes size overflow"))?,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: false.into(),
        };
        // SAFETY: name, attributes, and descriptor remain live; one local byte-stream
        // first-instance pipe is requested.
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(full_name_wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                maximum_message_bytes,
                maximum_message_bytes,
                0,
                Some(&raw mut attributes),
            )
        };
        if handle.is_invalid() {
            return Err(WindowsHostError::new(format!(
                "CreateNamedPipeW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let pipe = OwnedHandle(handle);
        let event = {
            // SAFETY: an unnamed manual-reset event is requested.
            let handle = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
                .map_err(|error| WindowsHostError::new(format!("CreateEventW failed: {error}")))?;
            OwnedHandle(handle)
        };
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        // SAFETY: pipe and overlapped/event remain live through completion or cancellation.
        match unsafe { ConnectNamedPipe(pipe.0, Some(&raw mut overlapped)) } {
            Ok(()) => {}
            Err(error) if error.code() == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) => {}
            Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
                let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
                // SAFETY: event is the live OVERLAPPED completion event.
                let wait = unsafe { WaitForSingleObject(event.0, milliseconds) };
                if wait == WAIT_TIMEOUT {
                    // SAFETY: this cancels only the pending connect operation.
                    let _ = unsafe { CancelIoEx(pipe.0, Some(&raw const overlapped)) };
                    return Err(WindowsHostError::new(
                        "verifier pipe accept exceeded its deadline",
                    ));
                }
                if wait != WAIT_OBJECT_0 {
                    return Err(WindowsHostError::new(format!(
                        "verifier pipe accept wait failed with code {}",
                        wait.0
                    )));
                }
                let mut transferred = 0_u32;
                // SAFETY: wait completed and overlapped remains live.
                unsafe {
                    GetOverlappedResult(pipe.0, &raw const overlapped, &raw mut transferred, false)
                }
                .map_err(|error| {
                    WindowsHostError::new(format!(
                        "verifier pipe connect completion failed: {error}"
                    ))
                })?;
            }
            Err(error) => {
                return Err(WindowsHostError::new(format!(
                    "ConnectNamedPipe failed: {error}"
                )));
            }
        }
        let mut process_id = 0_u32;
        // SAFETY: pipe is connected and process_id is writable.
        unsafe { GetNamedPipeClientProcessId(pipe.0, &raw mut process_id) }.map_err(|error| {
            WindowsHostError::new(format!("GetNamedPipeClientProcessId failed: {error}"))
        })?;
        let caller = process_identity(process_id)?;
        let raw = pipe.0 .0;
        std::mem::forget(pipe);
        // SAFETY: ownership of the connected pipe handle transfers to File exactly once.
        let stream = unsafe { File::from_raw_handle(raw) };
        Ok(WindowsVerifierPipeConnection { stream, caller })
    }

    pub(super) fn connect_verifier_pipe(
        pipe_name: &str,
        timeout: Duration,
    ) -> Result<File, WindowsHostError> {
        validate_pipe_name(pipe_name)?;
        let full_name = pipe_path(pipe_name);
        let full_name_wide = wide(&full_name)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| WindowsHostError::new("verifier pipe deadline overflow"))?;
        loop {
            // SAFETY: name is NUL-terminated; identification SQOS prevents impersonation.
            match unsafe {
                CreateFileW(
                    PCWSTR(full_name_wide.as_ptr()),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(
                        FILE_FLAG_OVERLAPPED.0
                            | SECURITY_SQOS_PRESENT.0
                            | SECURITY_IDENTIFICATION.0,
                    ),
                    None,
                )
            } {
                Ok(handle) => {
                    // SAFETY: ownership of the newly opened pipe transfers to File.
                    return Ok(unsafe { File::from_raw_handle(handle.0) });
                }
                Err(error) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(WindowsHostError::new(format!(
                            "verifier pipe unavailable before deadline: {error}"
                        )));
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    let milliseconds = u32::try_from(remaining.as_millis().min(250)).unwrap_or(250);
                    // SAFETY: name remains live and the wait is bounded.
                    let _ =
                        unsafe { WaitNamedPipeW(PCWSTR(full_name_wide.as_ptr()), milliseconds) };
                }
            }
        }
    }

    pub(super) fn verify_pipe_destination(
        stream: &File,
        expected_process_id: u32,
    ) -> Result<(), WindowsHostError> {
        let handle = HANDLE(stream.as_raw_handle());
        let mut observed = 0_u32;
        // SAFETY: stream owns a connected server-side named-pipe handle.
        unsafe { GetNamedPipeClientProcessId(handle, &raw mut observed) }.map_err(|error| {
            WindowsHostError::new(format!("pipe destination recheck failed: {error}"))
        })?;
        if observed != expected_process_id {
            return Err(WindowsHostError::new(
                "named-pipe response destination process changed",
            ));
        }
        Ok(())
    }

    pub(super) fn read_pipe_message(
        stream: &File,
        maximum_message_bytes: u32,
        timeout: Duration,
    ) -> Result<Vec<u8>, WindowsHostError> {
        validate_message_bound(maximum_message_bytes)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| WindowsHostError::new("pipe read deadline overflow"))?;
        let mut length = [0_u8; 4];
        read_exact_overlapped(stream, &mut length, deadline)?;
        let length = u32::from_le_bytes(length);
        if length == 0 || length > maximum_message_bytes {
            return Err(WindowsHostError::new(
                "verifier request length is outside its bound",
            ));
        }
        let mut message = vec![0_u8; length as usize];
        read_exact_overlapped(stream, &mut message, deadline)?;
        Ok(message)
    }

    pub(super) fn write_pipe_message(
        stream: &File,
        message: &[u8],
        maximum_message_bytes: u32,
        timeout: Duration,
    ) -> Result<(), WindowsHostError> {
        validate_message_bound(maximum_message_bytes)?;
        if message.is_empty() || message.len() > maximum_message_bytes as usize {
            return Err(WindowsHostError::new(
                "verifier response length is outside its bound",
            ));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| WindowsHostError::new("pipe write deadline overflow"))?;
        let length = u32::try_from(message.len())
            .map_err(|_| WindowsHostError::new("verifier response length overflow"))?;
        write_all_overlapped(stream, &length.to_le_bytes(), deadline)?;
        write_all_overlapped(stream, message, deadline)
    }

    pub(super) fn protect_local_machine(
        plaintext: &[u8],
        purpose: &[u8],
    ) -> Result<Vec<u8>, WindowsHostError> {
        dpapi_protect(plaintext, purpose)
    }

    pub(super) fn unprotect_local_machine(
        protected: &[u8],
        purpose: &[u8],
    ) -> Result<Vec<u8>, WindowsHostError> {
        validate_dpapi_input(protected, purpose)?;
        let input = blob(protected)?;
        let entropy = blob(purpose)?;
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input/entropy remain live and output is writable.
        unsafe {
            CryptUnprotectData(
                &raw const input,
                None,
                Some(&raw const entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!("machine CryptUnprotectData failed: {error}"))
        })?;
        copy_and_free_blob(output)
    }

    pub(super) fn harden_path_for_verifier_service(
        path: &Path,
        service_sid: &str,
        inherit_to_children: bool,
    ) -> Result<Vec<u8>, WindowsHostError> {
        validate_sid(service_sid, "verifier Service SID", "S-1-5-80-")?;
        if !path.is_absolute() {
            return Err(WindowsHostError::new(
                "verifier deployment path must be absolute",
            ));
        }
        let inherit = if inherit_to_children { "OICI" } else { "" };
        let sddl = format!(
            "D:P(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)\
             (A;{inherit};0x{:08x};;;{service_sid})",
            FILE_GENERIC_READ.0
        );
        let descriptor = descriptor_from_sddl(&sddl)?;
        let path_wide = wide_os(path.as_os_str())?;
        // SAFETY: path and descriptor remain live for the call.
        let result = unsafe {
            SetFileSecurityW(
                PCWSTR(path_wide.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        };
        if !result.as_bool() {
            return Err(WindowsHostError::new(format!(
                "SetFileSecurityW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        path_security_descriptor(path)
    }

    pub(super) fn harden_executable_for_verifier_service(
        path: &Path,
        service_sid: &str,
    ) -> Result<Vec<u8>, WindowsHostError> {
        validate_sid(service_sid, "verifier Service SID", "S-1-5-80-")?;
        if !path.is_absolute() {
            return Err(WindowsHostError::new(
                "verifier executable path must be absolute",
            ));
        }
        let service_access = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;
        let sddl =
            format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{service_access:08x};;;{service_sid})");
        let descriptor = descriptor_from_sddl(&sddl)?;
        let path_wide = wide_os(path.as_os_str())?;
        // SAFETY: path and descriptor remain live for this atomic DACL replacement.
        let result = unsafe {
            SetFileSecurityW(
                PCWSTR(path_wide.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        };
        if !result.as_bool() {
            return Err(WindowsHostError::new(format!(
                "verifier executable SetFileSecurityW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        path_security_descriptor(path)
    }

    pub(super) fn current_process_has_sid(sid: &str) -> Result<bool, WindowsHostError> {
        validate_sid(sid, "current process membership SID", "S-1-")?;
        let sid_wide = wide(sid)?;
        let mut converted = PSID::default();
        // SAFETY: SID text is NUL-terminated and output is writable.
        unsafe { ConvertStringSidToSidW(PCWSTR(sid_wide.as_ptr()), &raw mut converted) }.map_err(
            |error| WindowsHostError::new(format!("ConvertStringSidToSidW failed: {error}")),
        )?;
        let mut member = windows::core::BOOL::default();
        // SAFETY: converted is a live SID and null token means current effective token.
        let result = unsafe { CheckTokenMembership(None, converted, &raw mut member) };
        // SAFETY: ConvertStringSidToSidW allocated the SID with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(converted.0))) };
        result
            .map_err(|error| WindowsHostError::new(format!("CheckTokenMembership failed: {error}")))
            .map(|()| member.as_bool())
    }

    pub(super) fn grant_current_process_query_to_verifier(
        service_sid: &str,
    ) -> Result<(), WindowsHostError> {
        // SAFETY: the pseudo-handle names the current process and is not closed.
        grant_process_query_to_verifier(unsafe { GetCurrentProcess() }, service_sid)
    }

    pub(super) fn grant_appcontainer_child_query_to_verifier(
        child: &WindowsAppContainerChild,
        service_sid: &str,
    ) -> Result<(), WindowsHostError> {
        grant_process_query_to_verifier(child.handle, service_sid)
    }

    fn grant_process_query_to_verifier(
        process: HANDLE,
        service_sid: &str,
    ) -> Result<(), WindowsHostError> {
        validate_sid(service_sid, "verifier Service SID", "S-1-5-80-")?;
        grant_kernel_object_access(
            process,
            service_sid,
            PROCESS_QUERY_LIMITED_INFORMATION.0,
            "process",
        )?;
        let mut token = HANDLE::default();
        let token_access =
            TOKEN_ACCESS_MASK(TOKEN_QUERY.0 | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS);
        // SAFETY: process is an owned or current-process handle and token is writable.
        unsafe { OpenProcessToken(process, token_access, &raw mut token) }.map_err(|error| {
            WindowsHostError::new(format!(
                "relay OpenProcessToken for ACL update failed: {error}"
            ))
        })?;
        let token = OwnedHandle(token);
        grant_kernel_object_access(token.0, service_sid, TOKEN_QUERY.0, "token")
    }

    fn grant_kernel_object_access(
        object: HANDLE,
        service_sid: &str,
        access: u32,
        object_kind: &str,
    ) -> Result<(), WindowsHostError> {
        let sid_wide = wide(service_sid)?;
        let mut sid = PSID::default();
        // SAFETY: SID text is NUL-terminated and output is writable.
        unsafe { ConvertStringSidToSidW(PCWSTR(sid_wide.as_ptr()), &raw mut sid) }.map_err(
            |error| WindowsHostError::new(format!("verifier SID conversion failed: {error}")),
        )?;
        let result = (|| {
            let mut old_acl = std::ptr::null_mut();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            // SAFETY: object is an owned or current-process handle with
            // READ_CONTROL; outputs are writable and remain live until cleanup.
            let status = unsafe {
                GetSecurityInfo(
                    object,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(&raw mut old_acl),
                    None,
                    Some(&raw mut descriptor),
                )
            };
            if status != ERROR_SUCCESS {
                return Err(WindowsHostError::new(format!(
                    "{object_kind} GetSecurityInfo failed with code {}",
                    status.0
                )));
            }
            let entry = EXPLICIT_ACCESS_W {
                grfAccessPermissions: access,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: ACE_FLAGS(0),
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: Default::default(),
                    ptstrName: PWSTR(sid.0.cast()),
                },
            };
            let mut new_acl = std::ptr::null_mut();
            // SAFETY: entry references the live SID and old_acl remains owned by
            // descriptor through this call.
            let acl_status =
                unsafe { SetEntriesInAclW(Some(&[entry]), Some(old_acl), &raw mut new_acl) };
            let set_result = if acl_status != ERROR_SUCCESS {
                Err(WindowsHostError::new(format!(
                    "{object_kind} SetEntriesInAclW failed with code {}",
                    acl_status.0
                )))
            } else {
                // SAFETY: object has WRITE_DAC and new_acl preserves the old
                // DACL while adding one query-only Service SID ACE.
                let set_status = unsafe {
                    SetSecurityInfo(
                        object,
                        SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        None,
                        None,
                        Some(new_acl),
                        None,
                    )
                };
                if set_status == ERROR_SUCCESS {
                    Ok(())
                } else {
                    Err(WindowsHostError::new(format!(
                        "{object_kind} SetSecurityInfo failed with code {}",
                        set_status.0
                    )))
                }
            };
            if !new_acl.is_null() {
                // SAFETY: SetEntriesInAclW allocated this ACL with LocalAlloc.
                let _ = unsafe { LocalFree(Some(HLOCAL(new_acl.cast()))) };
            }
            if !descriptor.0.is_null() {
                // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
                let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
            }
            set_result
        })();
        // SAFETY: ConvertStringSidToSidW allocated the SID with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(sid.0))) };
        result
    }

    fn dpapi_protect(plaintext: &[u8], purpose: &[u8]) -> Result<Vec<u8>, WindowsHostError> {
        validate_dpapi_input(plaintext, purpose)?;
        let input = blob(plaintext)?;
        let entropy = blob(purpose)?;
        let description = wide("D2I machine-bound WFP verifier key")?;
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input/entropy remain live and output is writable.
        unsafe {
            CryptProtectData(
                &raw const input,
                PCWSTR(description.as_ptr()),
                Some(&raw const entropy),
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!("machine CryptProtectData failed: {error}"))
        })?;
        copy_and_free_blob(output)
    }

    fn read_exact_overlapped(
        stream: &File,
        mut output: &mut [u8],
        deadline: Instant,
    ) -> Result<(), WindowsHostError> {
        while !output.is_empty() {
            let transferred = read_overlapped_once(stream, output, deadline)?;
            if transferred == 0 {
                return Err(WindowsHostError::new(
                    "verifier pipe was truncated while reading",
                ));
            }
            let (_, remaining) = output.split_at_mut(transferred);
            output = remaining;
        }
        Ok(())
    }

    fn write_all_overlapped(
        stream: &File,
        mut input: &[u8],
        deadline: Instant,
    ) -> Result<(), WindowsHostError> {
        while !input.is_empty() {
            let transferred = write_overlapped_once(stream, input, deadline)?;
            if transferred == 0 {
                return Err(WindowsHostError::new(
                    "verifier pipe wrote zero response bytes",
                ));
            }
            input = &input[transferred..];
        }
        Ok(())
    }

    fn read_overlapped_once(
        stream: &File,
        output: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, WindowsHostError> {
        let handle = HANDLE(stream.as_raw_handle());
        let event = create_io_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        let mut transferred = 0_u32;
        // SAFETY: output, overlapped, event, and stream remain live through completion.
        let result = unsafe {
            ReadFile(
                handle,
                Some(output),
                Some(&raw mut transferred),
                Some(&raw mut overlapped),
            )
        };
        complete_overlapped_io(
            handle,
            &overlapped,
            result,
            &mut transferred,
            deadline,
            "ReadFile",
        )?;
        usize::try_from(transferred)
            .map_err(|_| WindowsHostError::new("pipe read byte count overflow"))
    }

    fn write_overlapped_once(
        stream: &File,
        input: &[u8],
        deadline: Instant,
    ) -> Result<usize, WindowsHostError> {
        let handle = HANDLE(stream.as_raw_handle());
        let event = create_io_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        let mut transferred = 0_u32;
        // SAFETY: input, overlapped, event, and stream remain live through completion.
        let result = unsafe {
            WriteFile(
                handle,
                Some(input),
                Some(&raw mut transferred),
                Some(&raw mut overlapped),
            )
        };
        complete_overlapped_io(
            handle,
            &overlapped,
            result,
            &mut transferred,
            deadline,
            "WriteFile",
        )?;
        usize::try_from(transferred)
            .map_err(|_| WindowsHostError::new("pipe write byte count overflow"))
    }

    fn complete_overlapped_io(
        handle: HANDLE,
        overlapped: &OVERLAPPED,
        result: windows::core::Result<()>,
        transferred: &mut u32,
        deadline: Instant,
        operation: &str,
    ) -> Result<(), WindowsHostError> {
        match result {
            Ok(()) => Ok(()),
            Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
                let now = Instant::now();
                if now >= deadline {
                    // SAFETY: cancels only this pending operation.
                    let _ = unsafe { CancelIoEx(handle, Some(overlapped)) };
                    return Err(WindowsHostError::new(format!(
                        "{operation} exceeded its deadline"
                    )));
                }
                let milliseconds =
                    u32::try_from(deadline.saturating_duration_since(now).as_millis())
                        .unwrap_or(u32::MAX);
                // SAFETY: hEvent belongs to the live OVERLAPPED operation.
                let wait = unsafe { WaitForSingleObject(overlapped.hEvent, milliseconds) };
                if wait == WAIT_TIMEOUT {
                    // SAFETY: cancels only this pending operation.
                    let _ = unsafe { CancelIoEx(handle, Some(overlapped)) };
                    return Err(WindowsHostError::new(format!(
                        "{operation} exceeded its deadline"
                    )));
                }
                if wait != WAIT_OBJECT_0 {
                    return Err(WindowsHostError::new(format!(
                        "{operation} wait failed with code {}",
                        wait.0
                    )));
                }
                // SAFETY: completion event signaled and pointers remain live.
                unsafe { GetOverlappedResult(handle, overlapped, transferred, false) }.map_err(
                    |error| {
                        WindowsHostError::new(format!("{operation} completion failed: {error}"))
                    },
                )
            }
            Err(error) => Err(WindowsHostError::new(format!(
                "{operation} failed: {error}"
            ))),
        }
    }

    fn create_io_event() -> Result<OwnedHandle, WindowsHostError> {
        // SAFETY: an unnamed manual-reset event is requested.
        let handle = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(|error| WindowsHostError::new(format!("CreateEventW failed: {error}")))?;
        Ok(OwnedHandle(handle))
    }

    fn validate_message_bound(maximum_message_bytes: u32) -> Result<(), WindowsHostError> {
        if maximum_message_bytes == 0 || maximum_message_bytes > MAX_PIPE_MESSAGE_BYTES {
            return Err(WindowsHostError::new(
                "verifier pipe message bound must be within 1..=65536 bytes",
            ));
        }
        Ok(())
    }

    pub(super) fn inspect_verifier_process(
        process_id: u32,
    ) -> Result<WindowsVerifierPipeCaller, WindowsHostError> {
        process_identity(process_id)
    }

    pub(super) fn process_parent_id(process_id: u32) -> Result<u32, WindowsHostError> {
        if process_id == 0 {
            return Err(WindowsHostError::new("process ID is zero"));
        }
        let snapshot = {
            // SAFETY: a read-only process snapshot is requested.
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        }
        .map_err(|error| {
            WindowsHostError::new(format!("CreateToolhelp32Snapshot failed: {error}"))
        })?;
        let snapshot = OwnedHandle(snapshot);
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(size_of::<PROCESSENTRY32W>())
                .map_err(|_| WindowsHostError::new("PROCESSENTRY32W size overflow"))?,
            ..Default::default()
        };
        // SAFETY: snapshot is live and entry has the required size.
        unsafe { Process32FirstW(snapshot.0, &raw mut entry) }
            .map_err(|error| WindowsHostError::new(format!("Process32FirstW failed: {error}")))?;
        loop {
            if entry.th32ProcessID == process_id {
                if entry.th32ParentProcessID == 0 {
                    return Err(WindowsHostError::new(
                        "process snapshot reports a zero parent process ID",
                    ));
                }
                return Ok(entry.th32ParentProcessID);
            }
            // SAFETY: snapshot and entry remain live for iteration.
            if unsafe { Process32NextW(snapshot.0, &raw mut entry) }.is_err() {
                break;
            }
        }
        Err(WindowsHostError::new(
            "process ID was not present in the kernel process snapshot",
        ))
    }

    fn process_identity(process_id: u32) -> Result<WindowsVerifierPipeCaller, WindowsHostError> {
        if process_id == 0 {
            return Err(WindowsHostError::new("pipe client process ID is zero"));
        }
        // SAFETY: a query-only handle is requested for the kernel-reported PID.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
            .map_err(|error| {
                WindowsHostError::new(format!("OpenProcess(pipe client) failed: {error}"))
            })?;
        let process = OwnedHandle(process);
        let mut token = HANDLE::default();
        // SAFETY: process is live and token is writable.
        unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &raw mut token) }.map_err(|error| {
            WindowsHostError::new(format!("OpenProcessToken(pipe client) failed: {error}"))
        })?;
        let token = OwnedHandle(token);
        let user = token_information(token.0, TokenUser)?;
        // SAFETY: aligned token storage contains TOKEN_USER.
        let user_sid = sid_to_string(unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid })?;
        let integrity = token_information(token.0, TokenIntegrityLevel)?;
        // SAFETY: aligned token storage contains TOKEN_MANDATORY_LABEL and its live SID.
        let integrity_sid = unsafe {
            (*(integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()))
                .Label
                .Sid
        };
        // SAFETY: integrity_sid is token-owned and valid for the storage lifetime.
        let count = unsafe { *GetSidSubAuthorityCount(integrity_sid) };
        if count == 0 {
            return Err(WindowsHostError::new(
                "process token integrity SID has no sub-authority",
            ));
        }
        // SAFETY: count is nonzero and the final sub-authority is the integrity RID.
        let integrity_level_rid =
            unsafe { *GetSidSubAuthority(integrity_sid, u32::from(count - 1)) };
        let elevation = token_information(token.0, TokenElevationType)?;
        // SAFETY: aligned token storage contains TOKEN_ELEVATION_TYPE.
        let elevation = unsafe { *elevation.as_ptr().cast::<TOKEN_ELEVATION_TYPE>() };
        let elevation_type = if elevation == TokenElevationTypeDefault {
            "default"
        } else if elevation == TokenElevationTypeFull {
            "full"
        } else if elevation == TokenElevationTypeLimited {
            "limited"
        } else {
            return Err(WindowsHostError::new(
                "process token elevation type is unsupported",
            ));
        }
        .to_owned();
        let is_appcontainer_bytes = token_information(token.0, TokenIsAppContainer)?;
        // SAFETY: token storage contains a DWORD boolean.
        let is_appcontainer = unsafe { *is_appcontainer_bytes.as_ptr().cast::<u32>() } != 0;
        let appcontainer_sid = if is_appcontainer {
            let information = token_information(token.0, TokenAppContainerSid)?;
            // SAFETY: aligned token storage contains TOKEN_APPCONTAINER_INFORMATION.
            let sid = unsafe {
                (*(information
                    .as_ptr()
                    .cast::<TOKEN_APPCONTAINER_INFORMATION>()))
                .TokenAppContainer
            };
            Some(sid_to_string(sid)?)
        } else {
            None
        };
        let mut session_id = 0_u32;
        // SAFETY: process_id came from the connected pipe and session_id is writable.
        unsafe { ProcessIdToSessionId(process_id, &raw mut session_id) }.map_err(|error| {
            WindowsHostError::new(format!("ProcessIdToSessionId(pipe client) failed: {error}"))
        })?;
        let executable = process_image_path(process.0)?;
        Ok(WindowsVerifierPipeCaller {
            process_id,
            user_sid,
            session_id,
            integrity_level_rid,
            elevation_type,
            is_appcontainer,
            appcontainer_sid,
            executable,
        })
    }

    fn process_image_path(process: HANDLE) -> Result<PathBuf, WindowsHostError> {
        let mut buffer = vec![0_u16; 32_768];
        let mut length = u32::try_from(buffer.len())
            .map_err(|_| WindowsHostError::new("process path buffer overflow"))?;
        // SAFETY: process has query access and buffer is writable.
        unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &raw mut length,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!("QueryFullProcessImageNameW failed: {error}"))
        })?;
        buffer.truncate(
            usize::try_from(length)
                .map_err(|_| WindowsHostError::new("process path length overflow"))?,
        );
        Ok(PathBuf::from(String::from_utf16(&buffer).map_err(
            |error| WindowsHostError::new(format!("process path is invalid UTF-16: {error}")),
        )?))
    }

    fn token_information(
        token: HANDLE,
        class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> Result<Vec<usize>, WindowsHostError> {
        let mut required = 0_u32;
        // SAFETY: first call requests the required buffer size.
        let _ = unsafe { GetTokenInformation(token, class, None, 0, &raw mut required) };
        if required == 0 || required > MAX_TOKEN_INFORMATION_BYTES {
            return Err(WindowsHostError::new(
                "pipe client token information size is invalid",
            ));
        }
        let words = usize::try_from(required)
            .ok()
            .and_then(|value| value.checked_add(size_of::<usize>() - 1))
            .and_then(|value| value.checked_div(size_of::<usize>()))
            .ok_or_else(|| WindowsHostError::new("token information size overflow"))?;
        let mut storage = vec![0_usize; words];
        // SAFETY: storage is aligned and has the requested capacity.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(storage.as_mut_ptr().cast()),
                required,
                &raw mut required,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!("GetTokenInformation(pipe client) failed: {error}"))
        })?;
        Ok(storage)
    }

    fn set_service_dacl(
        service: windows::Win32::System::Services::SC_HANDLE,
        owner_sid: &str,
    ) -> Result<(), WindowsHostError> {
        let sddl = format!(
            "D:P(A;;0x{SERVICE_FULL_ACCESS_MASK:08x};;;SY)\
             (A;;0x{SERVICE_FULL_ACCESS_MASK:08x};;;BA)\
             (A;;0x{SERVICE_RUNTIME_ACCESS_MASK:08x};;;{owner_sid})"
        );
        let descriptor = descriptor_from_sddl(&sddl)?;
        // SAFETY: service has WRITE_DAC via SERVICE_ALL_ACCESS and descriptor is live.
        unsafe {
            SetServiceObjectSecurity(
                service,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        }
        .map_err(|error| WindowsHostError::new(format!("SetServiceObjectSecurity failed: {error}")))
    }

    fn lookup_account_sid(account: &str) -> Result<String, WindowsHostError> {
        let account = wide(account)?;
        let mut sid_bytes = 0_u32;
        let mut domain_chars = 0_u32;
        let mut use_type = SID_NAME_USE::default();
        // SAFETY: first call requests buffer sizes.
        let _ = unsafe {
            LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(account.as_ptr()),
                None,
                &raw mut sid_bytes,
                None,
                &raw mut domain_chars,
                &raw mut use_type,
            )
        };
        if sid_bytes == 0 || sid_bytes > 64 * 1024 || domain_chars > 32_768 {
            return Err(WindowsHostError::new(
                "service SID lookup returned invalid buffer sizes",
            ));
        }
        let words = usize::try_from(sid_bytes)
            .ok()
            .and_then(|value| value.checked_add(size_of::<usize>() - 1))
            .and_then(|value| value.checked_div(size_of::<usize>()))
            .ok_or_else(|| WindowsHostError::new("service SID size overflow"))?;
        let mut sid = vec![0_usize; words];
        let mut domain = vec![0_u16; domain_chars as usize];
        // SAFETY: buffers have the exact requested sizes.
        unsafe {
            LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(account.as_ptr()),
                Some(PSID(sid.as_mut_ptr().cast())),
                &raw mut sid_bytes,
                Some(PWSTR(domain.as_mut_ptr())),
                &raw mut domain_chars,
                &raw mut use_type,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!("LookupAccountNameW(service SID) failed: {error}"))
        })?;
        sid_to_string(PSID(sid.as_mut_ptr().cast()))
    }

    fn sid_to_string(sid: PSID) -> Result<String, WindowsHostError> {
        if sid.0.is_null() {
            return Err(WindowsHostError::new("SID pointer is null"));
        }
        let mut value = PWSTR::null();
        // SAFETY: SID remains live and value is writable.
        unsafe { ConvertSidToStringSidW(sid, &raw mut value) }.map_err(|error| {
            WindowsHostError::new(format!("ConvertSidToStringSidW failed: {error}"))
        })?;
        // SAFETY: API returned a NUL-terminated LocalAlloc string.
        let converted = unsafe { value.to_string() }
            .map_err(|error| WindowsHostError::new(format!("SID is invalid UTF-16: {error}")));
        // SAFETY: conversion API allocated with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(value.0.cast()))) };
        converted
    }

    fn open_manager(access: u32) -> Result<ServiceHandle, WindowsHostError> {
        // SAFETY: null machine/database select the local active SCM database.
        let handle = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
            .map_err(|error| WindowsHostError::new(format!("OpenSCManagerW failed: {error}")))?;
        Ok(ServiceHandle(handle))
    }

    fn open_service(
        manager: &ServiceHandle,
        service_name: &str,
        access: u32,
    ) -> Result<ServiceHandle, WindowsHostError> {
        let name = wide(service_name)?;
        // SAFETY: name is NUL-terminated and manager is live.
        let handle = unsafe { OpenServiceW(manager.0, PCWSTR(name.as_ptr()), access) }
            .map_err(|error| WindowsHostError::new(format!("OpenServiceW failed: {error}")))?;
        Ok(ServiceHandle(handle))
    }

    fn descriptor_from_sddl(sddl: &str) -> Result<LocalDescriptor, WindowsHostError> {
        let sddl = wide(sddl)?;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: SDDL is NUL-terminated and output is writable.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|error| WindowsHostError::new(format!("SDDL conversion failed: {error}")))?;
        Ok(LocalDescriptor(descriptor))
    }

    fn path_security_descriptor(path: &Path) -> Result<Vec<u8>, WindowsHostError> {
        let path = wide_os(path.as_os_str())?;
        let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut required = 0_u32;
        // SAFETY: first call requests descriptor size.
        let _ = unsafe {
            GetFileSecurityW(
                PCWSTR(path.as_ptr()),
                information.0,
                None,
                0,
                &raw mut required,
            )
        };
        if required == 0 || required > 1024 * 1024 {
            return Err(WindowsHostError::new(
                "verifier path security descriptor size is invalid",
            ));
        }
        let mut bytes = vec![0_u8; required as usize];
        // SAFETY: bytes is writable for the requested descriptor.
        let result = unsafe {
            GetFileSecurityW(
                PCWSTR(path.as_ptr()),
                information.0,
                Some(PSECURITY_DESCRIPTOR(bytes.as_mut_ptr().cast())),
                required,
                &raw mut required,
            )
        };
        if !result.as_bool() {
            return Err(WindowsHostError::new(format!(
                "GetFileSecurityW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        bytes.truncate(required as usize);
        Ok(bytes)
    }

    fn blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, WindowsHostError> {
        Ok(CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len())
                .map_err(|_| WindowsHostError::new("DPAPI input is too large"))?,
            pbData: bytes.as_ptr().cast_mut(),
        })
    }

    fn copy_and_free_blob(blob: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, WindowsHostError> {
        if blob.pbData.is_null() || blob.cbData == 0 || blob.cbData > 1024 * 1024 {
            if !blob.pbData.is_null() {
                // SAFETY: DPAPI allocated the output with LocalAlloc.
                let _ = unsafe { LocalFree(Some(HLOCAL(blob.pbData.cast()))) };
            }
            return Err(WindowsHostError::new("DPAPI output size is invalid"));
        }
        // SAFETY: DPAPI returned cbData initialized bytes.
        let output =
            unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec() };
        // SAFETY: DPAPI allocated the output with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(blob.pbData.cast()))) };
        Ok(output)
    }

    fn validate_dpapi_input(bytes: &[u8], purpose: &[u8]) -> Result<(), WindowsHostError> {
        if bytes.is_empty()
            || bytes.len() > 1024 * 1024
            || purpose.is_empty()
            || purpose.len() > 4096
        {
            return Err(WindowsHostError::new(
                "DPAPI payload or purpose is outside bounded limits",
            ));
        }
        Ok(())
    }

    fn canonical_regular_file(path: &Path, field: &str) -> Result<PathBuf, WindowsHostError> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| WindowsHostError::new(format!("{field} metadata failed: {error}")))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(WindowsHostError::new(format!(
                "{field} must be a regular non-symlink file"
            )));
        }
        std::fs::canonicalize(path)
            .map_err(|error| WindowsHostError::new(format!("{field} canonicalize failed: {error}")))
    }

    fn canonical_future_file(path: &Path, field: &str) -> Result<PathBuf, WindowsHostError> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(WindowsHostError::new(format!(
                "{field} must be an absolute file path"
            )));
        }
        if path.exists() {
            return canonical_regular_file(path, field);
        }
        let parent = path
            .parent()
            .ok_or_else(|| WindowsHostError::new(format!("{field} has no parent")))?;
        let parent = std::fs::canonicalize(parent).map_err(|error| {
            WindowsHostError::new(format!("{field} parent canonicalize failed: {error}"))
        })?;
        let name = path
            .file_name()
            .ok_or_else(|| WindowsHostError::new(format!("{field} has no file name")))?;
        Ok(parent.join(name))
    }

    fn quote_free_path(path: &Path) -> Result<String, WindowsHostError> {
        let value = path.display().to_string();
        if value.contains('"') {
            return Err(WindowsHostError::new(
                "service command path contains a quote",
            ));
        }
        Ok(value)
    }

    fn validate_service_name(value: &str) -> Result<(), WindowsHostError> {
        if value.is_empty()
            || value.len() > 80
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(WindowsHostError::new(
                "verifier service name is outside the fixed syntax",
            ));
        }
        Ok(())
    }

    fn validate_pipe_name(value: &str) -> Result<(), WindowsHostError> {
        if value.is_empty()
            || value.len() > 80
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(WindowsHostError::new(
                "verifier pipe name is outside the fixed syntax",
            ));
        }
        Ok(())
    }

    fn validate_sid(value: &str, field: &str, prefix: &str) -> Result<(), WindowsHostError> {
        if value.len() > 256
            || !value.starts_with(prefix)
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && byte != b'-' && byte != b'S')
        {
            return Err(WindowsHostError::new(format!("{field} is invalid")));
        }
        Ok(())
    }

    fn pipe_path(pipe_name: &str) -> String {
        format!(r"\\.\pipe\LOCAL\{pipe_name}")
    }

    fn wide(value: &str) -> Result<Vec<u16>, WindowsHostError> {
        if value.contains('\0') {
            return Err(WindowsHostError::new("Windows string contains NUL"));
        }
        Ok(OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect())
    }

    fn wide_os(value: &OsStr) -> Result<Vec<u16>, WindowsHostError> {
        let value: Vec<u16> = value.encode_wide().collect();
        if value.contains(&0) {
            return Err(WindowsHostError::new("Windows path contains NUL"));
        }
        Ok(value.into_iter().chain(std::iter::once(0)).collect())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn machine_dpapi_is_purpose_bound() {
        let plaintext = b"d2i-wfp-verifier-test-seed";
        let protected = protect_local_machine(plaintext, b"d2i-purpose-a")
            .unwrap_or_else(|error| panic!("machine DPAPI protect failed: {error}"));
        let recovered = unprotect_local_machine(&protected, b"d2i-purpose-a")
            .unwrap_or_else(|error| panic!("machine DPAPI unprotect failed: {error}"));
        assert_eq!(recovered, plaintext);
        assert!(unprotect_local_machine(&protected, b"d2i-purpose-b").is_err());
    }

    #[test]
    fn unavailable_pipe_obeys_its_deadline() {
        let pipe = format!("d2i-wfp-verifier-absent-{}", std::process::id());
        let started = Instant::now();
        assert!(connect_verifier_pipe(&pipe, Duration::from_millis(100)).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn fixed_process_identity_and_parent_are_observable_without_impersonation() {
        let identity = inspect_verifier_process(std::process::id())
            .unwrap_or_else(|error| panic!("current process inspection failed: {error}"));
        assert_eq!(identity.process_id, std::process::id());
        assert!(!identity.user_sid.is_empty());
        assert!(identity.executable.is_absolute());
        assert!(
            process_parent_id(identity.process_id)
                .unwrap_or_else(|error| panic!("current parent inspection failed: {error}"))
                > 0
        );
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{
        WindowsAppContainerChild, WindowsHostError, WindowsVerifierPipeConnection,
        WindowsVerifierServiceIdentity,
    };
    use std::fs::File;
    use std::path::Path;
    use std::time::Duration;

    fn unavailable() -> WindowsHostError {
        WindowsHostError::new("Windows verifier broker is unavailable on this platform")
    }

    pub(super) fn install_verifier_service(
        _service_name: &str,
        _executable: &Path,
        _configuration: &Path,
        _owner_sid: &str,
    ) -> Result<WindowsVerifierServiceIdentity, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn start_verifier_service(_service_name: &str) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn remove_verifier_service(_service_name: &str) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn run_verifier_service_dispatcher(
        _service_name: &str,
        _entry: fn() -> Result<(), u32>,
    ) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn accept_verifier_pipe(
        _pipe_name: &str,
        _service_sid: &str,
        _owner_sid: &str,
        _maximum_message_bytes: u32,
        _timeout: Duration,
    ) -> Result<WindowsVerifierPipeConnection, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn connect_verifier_pipe(
        _pipe_name: &str,
        _timeout: Duration,
    ) -> Result<File, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn verify_pipe_destination(
        _stream: &File,
        _expected_process_id: u32,
    ) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn read_pipe_message(
        _stream: &File,
        _maximum_message_bytes: u32,
        _timeout: Duration,
    ) -> Result<Vec<u8>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn write_pipe_message(
        _stream: &File,
        _message: &[u8],
        _maximum_message_bytes: u32,
        _timeout: Duration,
    ) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn protect_local_machine(
        _plaintext: &[u8],
        _purpose: &[u8],
    ) -> Result<Vec<u8>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn unprotect_local_machine(
        _protected: &[u8],
        _purpose: &[u8],
    ) -> Result<Vec<u8>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn harden_path_for_verifier_service(
        _path: &Path,
        _service_sid: &str,
        _inherit_to_children: bool,
    ) -> Result<Vec<u8>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn harden_executable_for_verifier_service(
        _path: &Path,
        _service_sid: &str,
    ) -> Result<Vec<u8>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn current_process_has_sid(_sid: &str) -> Result<bool, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn grant_current_process_query_to_verifier(
        _service_sid: &str,
    ) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn grant_appcontainer_child_query_to_verifier(
        _child: &WindowsAppContainerChild,
        _service_sid: &str,
    ) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn inspect_verifier_process(
        _process_id: u32,
    ) -> Result<super::WindowsVerifierPipeCaller, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn process_parent_id(_process_id: u32) -> Result<u32, WindowsHostError> {
        Err(unavailable())
    }
}

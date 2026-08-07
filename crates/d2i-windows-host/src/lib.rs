//! Narrow Win32 FFI wrappers used by the isolated desktop worker.

mod verifier_broker;
mod wfp;

pub use verifier_broker::{
    accept_verifier_pipe, connect_verifier_pipe, current_process_has_sid,
    grant_appcontainer_child_query_to_verifier, grant_current_process_query_to_verifier,
    harden_executable_for_verifier_service, harden_path_for_verifier_service,
    inspect_verifier_process, install_verifier_service, process_parent_id, protect_local_machine,
    read_verifier_pipe_message, remove_verifier_service, run_verifier_service_dispatcher,
    start_verifier_service, unprotect_local_machine, write_verifier_pipe_message,
    WindowsVerifierPipeCaller, WindowsVerifierPipeConnection, WindowsVerifierServiceIdentity,
};
pub use wfp::{
    install_wfp_loopback_policy, install_wfp_loopback_policy_with_verifier_network_denial,
    remove_wfp_loopback_policy, verify_wfp_loopback_policy,
    verify_wfp_loopback_policy_with_verifier_network_denial, WindowsWfpLoopbackPolicyIdentity,
};

use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::Duration;

/// Safe error returned by a platform observation or containment operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsHostError {
    message: String,
}

impl WindowsHostError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for WindowsHostError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WindowsHostError {}

/// Exact Windows version and interactive-session identity observed by a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsHostIdentity {
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub architecture: String,
    pub session_id: u32,
    pub user_sid: String,
    pub integrity_level_rid: u32,
    pub elevation_type: String,
    pub is_appcontainer: bool,
}

/// Stable identity of one per-user AppContainer profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsAppContainerProfile {
    pub profile_name: String,
    pub profile_sid: String,
}

/// Access granted to an AppContainer SID for a deployment path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsAppContainerPathAccess {
    ReadExecute,
    ReadWrite,
}

/// Resource bounds applied to one worker process tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsJobLimits {
    pub active_process_limit: u32,
    pub per_process_memory_bytes: u64,
}

/// Read-only memory accounting captured by a Windows Job Object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsJobMemoryAccounting {
    pub peak_process_memory_bytes: u64,
    pub peak_job_memory_bytes: u64,
}

impl WindowsJobLimits {
    /// Validates conservative worker bounds.
    pub fn validate(self) -> Result<Self, WindowsHostError> {
        if self.active_process_limit == 0 || self.active_process_limit > 64 {
            return Err(WindowsHostError::new(
                "active process limit must be within 1..=64",
            ));
        }
        if self.per_process_memory_bytes < 16 * 1024 * 1024
            || self.per_process_memory_bytes > 8 * 1024 * 1024 * 1024
        {
            return Err(WindowsHostError::new(
                "per-process memory limit must be within 16 MiB..=8 GiB",
            ));
        }
        Ok(self)
    }
}

/// Owning Windows Job Object. Closing it terminates its assigned process tree.
#[cfg(windows)]
pub struct WindowsJob {
    handle: windows::Win32::Foundation::HANDLE,
}

#[cfg(not(windows))]
pub struct WindowsJob;

/// Owning handle for a zero-capability AppContainer child process.
#[cfg(windows)]
pub struct WindowsAppContainerChild {
    handle: windows::Win32::Foundation::HANDLE,
    process_id: u32,
}

#[cfg(not(windows))]
pub struct WindowsAppContainerChild;

impl WindowsJob {
    /// Creates a kill-on-close job with active-process and memory limits.
    pub fn create(limits: WindowsJobLimits) -> Result<Self, WindowsHostError> {
        platform::create_job(limits.validate()?)
    }

    /// Assigns a child before any request is sent to it.
    pub fn assign_child(&self, child: &Child) -> Result<(), WindowsHostError> {
        platform::assign_child(self, child)
    }

    /// Terminates every process in this worker tree.
    pub fn terminate(&self) -> Result<(), WindowsHostError> {
        platform::terminate_job(self)
    }

    /// Returns peak memory counters for this job without changing its limits.
    pub fn memory_accounting(&self) -> Result<WindowsJobMemoryAccounting, WindowsHostError> {
        platform::job_memory_accounting(self)
    }
}

impl WindowsAppContainerChild {
    /// Returns the operating-system process identifier.
    pub fn id(&self) -> u32 {
        platform::appcontainer_child_id(self)
    }

    /// Returns an exit code when the child has completed.
    pub fn try_wait(&self) -> Result<Option<u32>, WindowsHostError> {
        platform::appcontainer_child_try_wait(self)
    }

    /// Waits for completion up to the supplied duration.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<Option<u32>, WindowsHostError> {
        platform::appcontainer_child_wait_timeout(self, timeout)
    }

    /// Terminates the child and waits for its process object to signal.
    pub fn terminate(&self) -> Result<(), WindowsHostError> {
        platform::terminate_appcontainer_child(self)
    }
}

/// Collects exact Windows version, architecture, and current session identity.
pub fn host_identity() -> Result<WindowsHostIdentity, WindowsHostError> {
    platform::host_identity()
}

/// Creates or resolves a per-user AppContainer profile with no capabilities.
pub fn provision_appcontainer_profile(
    profile_name: &str,
) -> Result<WindowsAppContainerProfile, WindowsHostError> {
    platform::provision_appcontainer_profile(profile_name)
}

/// Resolves an existing per-user AppContainer profile.
pub fn appcontainer_profile(
    profile_name: &str,
) -> Result<WindowsAppContainerProfile, WindowsHostError> {
    platform::appcontainer_profile(profile_name)
}

/// Deletes a per-user AppContainer profile.
pub fn delete_appcontainer_profile(profile_name: &str) -> Result<(), WindowsHostError> {
    platform::delete_appcontainer_profile(profile_name)
}

/// Grants a profile SID explicit access to a file or directory.
pub fn grant_appcontainer_path_access(
    profile_name: &str,
    path: &Path,
    access: WindowsAppContainerPathAccess,
    inherit_to_children: bool,
) -> Result<(), WindowsHostError> {
    platform::grant_appcontainer_path_access(profile_name, path, access, inherit_to_children)
}

/// Starts one child in the named zero-capability AppContainer.
pub fn spawn_zero_capability_appcontainer(
    profile_name: &str,
    expected_profile_sid: &str,
    executable: &Path,
    arguments: &[String],
    working_directory: &Path,
) -> Result<WindowsAppContainerChild, WindowsHostError> {
    platform::spawn_zero_capability_appcontainer(
        profile_name,
        expected_profile_sid,
        executable,
        arguments,
        working_directory,
        None,
        None,
    )
}

/// Starts one zero-capability AppContainer child suspended, assigns it to the
/// supplied Job Object, verifies its identity, and only then resumes it.
pub fn spawn_zero_capability_appcontainer_in_job(
    profile_name: &str,
    expected_profile_sid: &str,
    executable: &Path,
    arguments: &[String],
    working_directory: &Path,
    job: &WindowsJob,
) -> Result<WindowsAppContainerChild, WindowsHostError> {
    platform::spawn_zero_capability_appcontainer(
        profile_name,
        expected_profile_sid,
        executable,
        arguments,
        working_directory,
        None,
        Some(job),
    )
}

/// Starts one zero-capability AppContainer child in a Job Object with only the
/// explicitly supplied environment variables.
pub fn spawn_zero_capability_appcontainer_in_job_with_environment(
    profile_name: &str,
    expected_profile_sid: &str,
    executable: &Path,
    arguments: &[String],
    working_directory: &Path,
    environment: &[(String, String)],
    job: &WindowsJob,
) -> Result<WindowsAppContainerChild, WindowsHostError> {
    platform::spawn_zero_capability_appcontainer(
        profile_name,
        expected_profile_sid,
        executable,
        arguments,
        working_directory,
        Some(environment),
        Some(job),
    )
}

/// Protects bytes with current-user, current-machine DPAPI and optional entropy.
pub fn protect_current_user(plaintext: &[u8], purpose: &[u8]) -> Result<Vec<u8>, WindowsHostError> {
    platform::protect_current_user(plaintext, purpose)
}

/// Unprotects bytes with current-user, current-machine DPAPI.
pub fn unprotect_current_user(
    protected: &[u8],
    purpose: &[u8],
) -> Result<Vec<u8>, WindowsHostError> {
    platform::unprotect_current_user(protected, purpose)
}

/// Fills a bounded buffer from the Windows system-preferred cryptographic RNG.
pub fn secure_random_bytes<const N: usize>() -> Result<[u8; N], WindowsHostError> {
    platform::secure_random_bytes()
}

/// Returns milliseconds elapsed since Windows boot for monotonic receipt ordering.
pub fn monotonic_milliseconds() -> Result<u64, WindowsHostError> {
    platform::monotonic_milliseconds()
}

/// Replaces a path DACL with protected full-control entries for SYSTEM and the
/// current user, then returns its owner/DACL security descriptor bytes.
pub fn harden_path_for_current_user(path: &Path) -> Result<Vec<u8>, WindowsHostError> {
    platform::harden_path_for_current_user(path)
}

/// Returns stable owner/DACL security descriptor bytes for a path.
pub fn path_security_descriptor(path: &Path) -> Result<Vec<u8>, WindowsHostError> {
    platform::path_security_descriptor(path)
}

/// Resolves the executable image path for a process.
pub fn process_image_path(process_id: u32) -> Result<PathBuf, WindowsHostError> {
    platform::process_image_path(process_id)
}

/// Resolves the Windows session that owns a process.
pub fn process_session_id(process_id: u32) -> Result<u32, WindowsHostError> {
    platform::process_session_id(process_id)
}

/// Returns the four-part product version embedded in a Windows executable.
pub fn file_product_version(path: &Path) -> Result<String, WindowsHostError> {
    platform::file_product_version(path)
}

/// Reports whether a path itself is a Windows reparse point.
pub fn is_reparse_point(path: &Path) -> Result<bool, WindowsHostError> {
    platform::is_reparse_point(path)
}

/// Atomically moves a same-volume file, optionally replacing the destination.
pub fn atomic_move(
    source: &Path,
    destination: &Path,
    replace: bool,
) -> Result<(), WindowsHostError> {
    platform::atomic_move(source, destination, replace)
}

#[cfg(windows)]
mod platform {
    use super::{
        WindowsAppContainerChild, WindowsAppContainerPathAccess, WindowsAppContainerProfile,
        WindowsHostError, WindowsHostIdentity, WindowsJob, WindowsJobLimits,
        WindowsJobMemoryAccounting,
    };
    use std::ffi::OsStr;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::process::Child;
    use std::time::Duration;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Wdk::System::SystemServices::RtlGetVersion;
    use windows::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL, STILL_ACTIVE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
        GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SDDL_REVISION_1, SE_FILE_OBJECT, TRUSTEE_IS_SID,
        TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows::Win32::Security::Cryptography::{
        BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    use windows::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeleteAppContainerProfile,
        DeriveAppContainerSidFromAppContainerName,
    };
    use windows::Win32::Security::{
        FreeSid, GetFileSecurityW, GetSidSubAuthority, GetSidSubAuthorityCount,
        GetTokenInformation, TokenAppContainerSid, TokenElevationType, TokenElevationTypeDefault,
        TokenElevationTypeFull, TokenElevationTypeLimited, TokenIntegrityLevel,
        TokenIsAppContainer, TokenUser, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_APPCONTAINER_INFORMATION, TOKEN_ELEVATION_TYPE,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::Storage::FileSystem::{
        GetFileAttributesW, GetFileVersionInfoSizeW, GetFileVersionInfoW, MoveFileExW,
        VerQueryValueW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH, VS_FIXEDFILEINFO,
    };
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::SystemInformation::GetTickCount64;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetCurrentProcessId,
        GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcess, OpenProcessToken,
        QueryFullProcessImageNameW, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
        WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW,
    };

    pub(super) fn create_job(limits: WindowsJobLimits) -> Result<WindowsJob, WindowsHostError> {
        // SAFETY: null security attributes and name request an unnamed job. The returned
        // owned handle is closed by Drop.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|error| WindowsHostError::new(format!("CreateJobObjectW failed: {error}")))?;
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        information.BasicLimitInformation.ActiveProcessLimit = limits.active_process_limit;
        information.ProcessMemoryLimit =
            usize::try_from(limits.per_process_memory_bytes).map_err(|_| {
                WindowsHostError::new("per-process memory limit does not fit this architecture")
            })?;
        // SAFETY: information points to a fully initialized structure with its exact size.
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const information).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(|_| WindowsHostError::new("job structure size overflow"))?,
            )
        };
        if let Err(error) = configured {
            // SAFETY: handle is owned by this function and has not been closed.
            let _ = unsafe { CloseHandle(handle) };
            return Err(WindowsHostError::new(format!(
                "SetInformationJobObject failed: {error}"
            )));
        }
        Ok(WindowsJob { handle })
    }

    pub(super) fn assign_child(job: &WindowsJob, child: &Child) -> Result<(), WindowsHostError> {
        let raw = child.as_raw_handle();
        let process = HANDLE(raw);
        // SAFETY: the Child owns a live process handle for the duration of this call.
        unsafe { AssignProcessToJobObject(job.handle, process) }.map_err(|error| {
            WindowsHostError::new(format!("AssignProcessToJobObject failed: {error}"))
        })
    }

    pub(super) fn terminate_job(job: &WindowsJob) -> Result<(), WindowsHostError> {
        // SAFETY: job.handle is a live owned Job Object handle.
        unsafe { TerminateJobObject(job.handle, 1) }
            .map_err(|error| WindowsHostError::new(format!("TerminateJobObject failed: {error}")))
    }

    pub(super) fn job_memory_accounting(
        job: &WindowsJob,
    ) -> Result<WindowsJobMemoryAccounting, WindowsHostError> {
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: information is writable for the exact structure size and the job handle
        // remains owned and live for this call.
        unsafe {
            QueryInformationJobObject(
                Some(job.handle),
                JobObjectExtendedLimitInformation,
                (&raw mut information).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(|_| WindowsHostError::new("job structure size overflow"))?,
                None,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!("QueryInformationJobObject failed: {error}"))
        })?;
        Ok(WindowsJobMemoryAccounting {
            peak_process_memory_bytes: u64::try_from(information.PeakProcessMemoryUsed)
                .map_err(|_| WindowsHostError::new("peak process memory overflow"))?,
            peak_job_memory_bytes: u64::try_from(information.PeakJobMemoryUsed)
                .map_err(|_| WindowsHostError::new("peak job memory overflow"))?,
        })
    }

    pub(super) fn host_identity() -> Result<WindowsHostIdentity, WindowsHostError> {
        let mut version = OSVERSIONINFOW {
            dwOSVersionInfoSize: u32::try_from(size_of::<OSVERSIONINFOW>())
                .map_err(|_| WindowsHostError::new("OS version structure size overflow"))?,
            ..Default::default()
        };
        // SAFETY: version points to a writable structure with the required size initialized.
        let status = unsafe { RtlGetVersion(&raw mut version) };
        if status.0 < 0 {
            return Err(WindowsHostError::new(format!(
                "RtlGetVersion failed with NTSTATUS {}",
                status.0
            )));
        }
        let mut session_id = 0_u32;
        // SAFETY: session_id is writable and GetCurrentProcessId returns the caller PID.
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &raw mut session_id) }.map_err(
            |error| WindowsHostError::new(format!("ProcessIdToSessionId failed: {error}")),
        )?;
        let (user_sid, integrity_level_rid, elevation_type, is_appcontainer) =
            current_token_identity()?;
        Ok(WindowsHostIdentity {
            major_version: version.dwMajorVersion,
            minor_version: version.dwMinorVersion,
            build_number: version.dwBuildNumber,
            architecture: std::env::consts::ARCH.to_owned(),
            session_id,
            user_sid,
            integrity_level_rid,
            elevation_type,
            is_appcontainer,
        })
    }

    pub(super) fn provision_appcontainer_profile(
        profile_name: &str,
    ) -> Result<WindowsAppContainerProfile, WindowsHostError> {
        validate_profile_name(profile_name)?;
        let name = wide_string(profile_name)?;
        let display = wide_string(&format!("D2I {profile_name}"))?;
        let description = wide_string("D2I zero-capability process sandbox")?;
        // SAFETY: all strings are NUL-terminated and no capability array is supplied.
        let created = unsafe {
            CreateAppContainerProfile(
                PCWSTR(name.as_ptr()),
                PCWSTR(display.as_ptr()),
                PCWSTR(description.as_ptr()),
                None,
            )
        };
        if let Ok(sid) = created {
            let profile_sid = sid_to_string(sid)?;
            // SAFETY: CreateAppContainerProfile returns a SID released with FreeSid.
            let _ = unsafe { FreeSid(sid) };
            return Ok(WindowsAppContainerProfile {
                profile_name: profile_name.to_owned(),
                profile_sid,
            });
        }
        appcontainer_profile(profile_name).map_err(|derive_error| {
            WindowsHostError::new(format!(
                "AppContainer profile creation and lookup failed: {derive_error}"
            ))
        })
    }

    pub(super) fn appcontainer_profile(
        profile_name: &str,
    ) -> Result<WindowsAppContainerProfile, WindowsHostError> {
        validate_profile_name(profile_name)?;
        let name = wide_string(profile_name)?;
        // SAFETY: name is a valid NUL-terminated AppContainer profile name.
        let sid = unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(name.as_ptr())) }
            .map_err(|error| {
                WindowsHostError::new(format!(
                    "DeriveAppContainerSidFromAppContainerName failed: {error}"
                ))
            })?;
        let profile_sid = sid_to_string(sid)?;
        // SAFETY: DeriveAppContainerSidFromAppContainerName returns a SID released with FreeSid.
        let _ = unsafe { FreeSid(sid) };
        Ok(WindowsAppContainerProfile {
            profile_name: profile_name.to_owned(),
            profile_sid,
        })
    }

    pub(super) fn delete_appcontainer_profile(profile_name: &str) -> Result<(), WindowsHostError> {
        validate_profile_name(profile_name)?;
        let name = wide_string(profile_name)?;
        // SAFETY: name is a valid NUL-terminated AppContainer profile name.
        unsafe { DeleteAppContainerProfile(PCWSTR(name.as_ptr())) }.map_err(|error| {
            WindowsHostError::new(format!("DeleteAppContainerProfile failed: {error}"))
        })
    }

    pub(super) fn grant_appcontainer_path_access(
        profile_name: &str,
        path: &Path,
        access: WindowsAppContainerPathAccess,
        inherit_to_children: bool,
    ) -> Result<(), WindowsHostError> {
        validate_deployment_path(path)?;
        let profile_name = wide_string(profile_name)?;
        let sid =
            // SAFETY: profile_name is NUL-terminated and validated by the platform API.
            unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(profile_name.as_ptr())) }
                .map_err(|error| {
                    WindowsHostError::new(format!(
                        "DeriveAppContainerSidFromAppContainerName failed: {error}"
                    ))
                })?;
        let path_wide = wide_path(path)?;
        let mut old_acl = std::ptr::null_mut();
        let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: output pointers are writable and path_wide remains live for the call.
        let get_status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&raw mut old_acl),
                None,
                &raw mut security_descriptor,
            )
        };
        if get_status != ERROR_SUCCESS {
            // SAFETY: sid is owned by this function.
            let _ = unsafe { FreeSid(sid) };
            return Err(WindowsHostError::new(format!(
                "GetNamedSecurityInfoW failed with code {}",
                get_status.0
            )));
        }
        let permissions = match access {
            WindowsAppContainerPathAccess::ReadExecute => {
                FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0
            }
            WindowsAppContainerPathAccess::ReadWrite => {
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0
            }
        };
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: permissions,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: if inherit_to_children {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                Default::default()
            },
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(sid.0.cast()),
            },
        };
        let mut new_acl = std::ptr::null_mut();
        // SAFETY: entry references the live profile SID and old_acl belongs to the
        // security descriptor until cleanup below.
        let acl_status =
            unsafe { SetEntriesInAclW(Some(&[entry]), Some(old_acl), &raw mut new_acl) };
        let result = if acl_status != ERROR_SUCCESS {
            Err(WindowsHostError::new(format!(
                "SetEntriesInAclW failed with code {}",
                acl_status.0
            )))
        } else {
            // SAFETY: new_acl is the ACL produced above and path_wide remains live.
            let set_status = unsafe {
                SetNamedSecurityInfoW(
                    PCWSTR(path_wide.as_ptr()),
                    SE_FILE_OBJECT,
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
                    "SetNamedSecurityInfoW failed with code {}",
                    set_status.0
                )))
            }
        };
        if !new_acl.is_null() {
            // SAFETY: SetEntriesInAclW allocates new_acl with LocalAlloc.
            let _ = unsafe { LocalFree(Some(HLOCAL(new_acl.cast()))) };
        }
        if !security_descriptor.0.is_null() {
            // SAFETY: GetNamedSecurityInfoW allocates this descriptor with LocalAlloc.
            let _ = unsafe { LocalFree(Some(HLOCAL(security_descriptor.0))) };
        }
        // SAFETY: sid is owned by this function.
        let _ = unsafe { FreeSid(sid) };
        result
    }

    pub(super) fn spawn_zero_capability_appcontainer(
        profile_name: &str,
        expected_profile_sid: &str,
        executable: &Path,
        arguments: &[String],
        working_directory: &Path,
        environment: Option<&[(String, String)]>,
        job: Option<&WindowsJob>,
    ) -> Result<WindowsAppContainerChild, WindowsHostError> {
        validate_deployment_path(executable)?;
        validate_deployment_path(working_directory)?;
        let profile = appcontainer_profile(profile_name)?;
        if profile.profile_sid != expected_profile_sid {
            return Err(WindowsHostError::new(
                "AppContainer profile SID differs from the reviewed configuration",
            ));
        }
        let profile_name_wide = wide_string(profile_name)?;
        // SAFETY: profile_name_wide is a valid NUL-terminated profile name.
        let sid = unsafe {
            DeriveAppContainerSidFromAppContainerName(PCWSTR(profile_name_wide.as_ptr()))
        }
        .map_err(|error| {
            WindowsHostError::new(format!(
                "DeriveAppContainerSidFromAppContainerName failed: {error}"
            ))
        })?;
        let mut attribute_size = 0_usize;
        // SAFETY: the first call intentionally requests the required allocation size.
        let _ =
            unsafe { InitializeProcThreadAttributeList(None, 1, None, &raw mut attribute_size) };
        if attribute_size == 0 {
            // SAFETY: sid is owned by this function.
            let _ = unsafe { FreeSid(sid) };
            return Err(WindowsHostError::new(
                "AppContainer process attribute size is zero",
            ));
        }
        let words = attribute_size
            .checked_add(size_of::<usize>() - 1)
            .and_then(|value| value.checked_div(size_of::<usize>()))
            .ok_or_else(|| WindowsHostError::new("process attribute size overflow"))?;
        let mut attribute_storage = vec![0_usize; words];
        let attribute_list = LPPROC_THREAD_ATTRIBUTE_LIST(attribute_storage.as_mut_ptr().cast());
        // SAFETY: attribute_storage is aligned and sized by the preceding API query.
        if let Err(error) = unsafe {
            InitializeProcThreadAttributeList(
                Some(attribute_list),
                1,
                None,
                &raw mut attribute_size,
            )
        } {
            // SAFETY: sid is owned by this function.
            let _ = unsafe { FreeSid(sid) };
            return Err(WindowsHostError::new(format!(
                "InitializeProcThreadAttributeList failed: {error}"
            )));
        }
        let capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: sid,
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        // SAFETY: attribute_list is initialized and capabilities remains live through
        // CreateProcessW.
        let update = unsafe {
            UpdateProcThreadAttribute(
                attribute_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some((&raw const capabilities).cast()),
                size_of::<SECURITY_CAPABILITIES>(),
                None,
                None,
            )
        };
        if let Err(error) = update {
            // SAFETY: attribute_list and sid are owned by this function.
            unsafe { DeleteProcThreadAttributeList(attribute_list) };
            // SAFETY: sid is owned by this function and has not been freed.
            let _ = unsafe { FreeSid(sid) };
            return Err(WindowsHostError::new(format!(
                "UpdateProcThreadAttribute failed: {error}"
            )));
        }
        let executable_wide = wide_path(executable)?;
        let working_directory_wide = wide_path(working_directory)?;
        let mut command_line = windows_command_line(executable.as_os_str(), arguments)?;
        let environment_block = environment.map(windows_environment_block).transpose()?;
        let environment_pointer = environment_block
            .as_ref()
            .map(|value| value.as_ptr().cast());
        let mut creation_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW;
        if environment_block.is_some() {
            creation_flags |= CREATE_UNICODE_ENVIRONMENT;
        }
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
            .map_err(|_| WindowsHostError::new("STARTUPINFOEXW size overflow"))?;
        startup.lpAttributeList = attribute_list;
        let mut process_information = PROCESS_INFORMATION::default();
        // SAFETY: every pointer references initialized storage that remains live for
        // the call. The exact application path is supplied separately from argv.
        let created = unsafe {
            CreateProcessW(
                PCWSTR(executable_wide.as_ptr()),
                Some(PWSTR(command_line.as_mut_ptr())),
                None,
                None,
                false,
                creation_flags,
                environment_pointer,
                PCWSTR(working_directory_wide.as_ptr()),
                &raw const startup.StartupInfo,
                &raw mut process_information,
            )
        };
        // SAFETY: the attribute list and profile SID are no longer needed after
        // CreateProcessW returns.
        unsafe { DeleteProcThreadAttributeList(attribute_list) };
        // SAFETY: sid is owned by this function and has not been freed.
        let _ = unsafe { FreeSid(sid) };
        if let Err(error) = created {
            return Err(WindowsHostError::new(format!(
                "AppContainer CreateProcessW failed: {error}"
            )));
        }
        let verification =
            verify_appcontainer_process(process_information.hProcess, expected_profile_sid);
        if let Err(error) = verification {
            // SAFETY: both handles were returned by CreateProcessW and are live.
            let _ = unsafe { TerminateProcess(process_information.hProcess, 1) };
            // SAFETY: hThread is live and owned by this function.
            let _ = unsafe { CloseHandle(process_information.hThread) };
            // SAFETY: hProcess is live and owned by this function.
            let _ = unsafe { CloseHandle(process_information.hProcess) };
            return Err(error);
        }
        if let Some(job) = job {
            // SAFETY: both handles are live and owned by the caller/function. The
            // process is still suspended, so no descendant can escape assignment.
            let assignment =
                unsafe { AssignProcessToJobObject(job.handle, process_information.hProcess) };
            if let Err(error) = assignment {
                // SAFETY: both handles were returned by CreateProcessW and are live.
                let _ = unsafe { TerminateProcess(process_information.hProcess, 1) };
                // SAFETY: hThread is live and owned by this function.
                let _ = unsafe { CloseHandle(process_information.hThread) };
                // SAFETY: hProcess is live and owned by this function.
                let _ = unsafe { CloseHandle(process_information.hProcess) };
                return Err(WindowsHostError::new(format!(
                    "AssignProcessToJobObject for AppContainer failed: {error}"
                )));
            }
        }
        // SAFETY: hThread is the suspended primary thread returned by CreateProcessW.
        let resume_result = unsafe { ResumeThread(process_information.hThread) };
        // SAFETY: the primary thread handle is no longer needed after resume.
        let _ = unsafe { CloseHandle(process_information.hThread) };
        if resume_result == u32::MAX {
            // SAFETY: hProcess is live and owned by this function.
            let _ = unsafe { TerminateProcess(process_information.hProcess, 1) };
            // SAFETY: hProcess is live and owned by this function.
            let _ = unsafe { CloseHandle(process_information.hProcess) };
            return Err(WindowsHostError::new(format!(
                "ResumeThread failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(WindowsAppContainerChild {
            handle: process_information.hProcess,
            process_id: process_information.dwProcessId,
        })
    }

    pub(super) fn appcontainer_child_id(child: &WindowsAppContainerChild) -> u32 {
        child.process_id
    }

    pub(super) fn appcontainer_child_try_wait(
        child: &WindowsAppContainerChild,
    ) -> Result<Option<u32>, WindowsHostError> {
        let mut exit_code = 0_u32;
        // SAFETY: child.handle is a live owned process handle.
        unsafe { GetExitCodeProcess(child.handle, &raw mut exit_code) }.map_err(|error| {
            WindowsHostError::new(format!("GetExitCodeProcess failed: {error}"))
        })?;
        if exit_code == STILL_ACTIVE.0 as u32 {
            Ok(None)
        } else {
            Ok(Some(exit_code))
        }
    }

    pub(super) fn appcontainer_child_wait_timeout(
        child: &WindowsAppContainerChild,
        timeout: Duration,
    ) -> Result<Option<u32>, WindowsHostError> {
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: child.handle is a live process handle.
        let wait = unsafe { WaitForSingleObject(child.handle, milliseconds) };
        if wait == WAIT_TIMEOUT {
            return Ok(None);
        }
        if wait != WAIT_OBJECT_0 {
            return Err(WindowsHostError::new(format!(
                "WaitForSingleObject failed with code {}",
                wait.0
            )));
        }
        appcontainer_child_try_wait(child)
    }

    pub(super) fn terminate_appcontainer_child(
        child: &WindowsAppContainerChild,
    ) -> Result<(), WindowsHostError> {
        // SAFETY: child.handle is a live process handle owned by the wrapper.
        unsafe { TerminateProcess(child.handle, 1) }
            .map_err(|error| WindowsHostError::new(format!("TerminateProcess failed: {error}")))?;
        let _ = appcontainer_child_wait_timeout(child, Duration::from_secs(5))?;
        Ok(())
    }

    pub(super) fn protect_current_user(
        plaintext: &[u8],
        purpose: &[u8],
    ) -> Result<Vec<u8>, WindowsHostError> {
        validate_dpapi_input(plaintext, purpose)?;
        let input = blob(plaintext)?;
        let entropy = blob(purpose)?;
        let description = wide_string("D2I current-user protected key")?;
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input and entropy point to live caller slices; output is writable.
        unsafe {
            CryptProtectData(
                &raw const input,
                PCWSTR(description.as_ptr()),
                Some(&raw const entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        }
        .map_err(|error| WindowsHostError::new(format!("CryptProtectData failed: {error}")))?;
        copy_and_free_blob(output)
    }

    pub(super) fn unprotect_current_user(
        protected: &[u8],
        purpose: &[u8],
    ) -> Result<Vec<u8>, WindowsHostError> {
        validate_dpapi_input(protected, purpose)?;
        let input = blob(protected)?;
        let entropy = blob(purpose)?;
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input and entropy point to live caller slices; output is writable.
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
        .map_err(|error| WindowsHostError::new(format!("CryptUnprotectData failed: {error}")))?;
        copy_and_free_blob(output)
    }

    pub(super) fn secure_random_bytes<const N: usize>() -> Result<[u8; N], WindowsHostError> {
        if N == 0 || N > 4096 {
            return Err(WindowsHostError::new(
                "secure random request must be within 1..=4096 bytes",
            ));
        }
        let mut output = [0_u8; N];
        // SAFETY: the system-preferred RNG accepts a null algorithm handle and
        // writes exactly the supplied mutable slice.
        unsafe { BCryptGenRandom(None, &mut output, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
            .ok()
            .map_err(|error| WindowsHostError::new(format!("BCryptGenRandom failed: {error}")))?;
        Ok(output)
    }

    pub(super) fn monotonic_milliseconds() -> Result<u64, WindowsHostError> {
        // SAFETY: GetTickCount64 takes no pointers and cannot fail.
        let value = unsafe { GetTickCount64() };
        if value == 0 {
            return Err(WindowsHostError::new(
                "Windows monotonic clock returned zero",
            ));
        }
        Ok(value)
    }

    pub(super) fn harden_path_for_current_user(path: &Path) -> Result<Vec<u8>, WindowsHostError> {
        validate_deployment_path(path)?;
        let (user_sid, _, _, _) = current_token_identity()?;
        let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user_sid})");
        let sddl = wide_string(&sddl)?;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: sddl is a valid NUL-terminated string and descriptor is writable.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {error}"
            ))
        })?;
        let path_wide = wide_path(path)?;
        // SAFETY: descriptor is a valid security descriptor and path remains live.
        let set_result = unsafe {
            windows::Win32::Security::SetFileSecurityW(
                PCWSTR(path_wide.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        // SAFETY: the conversion API allocates descriptor with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        if !set_result.as_bool() {
            return Err(WindowsHostError::new(format!(
                "SetFileSecurityW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        path_security_descriptor(path)
    }

    pub(super) fn path_security_descriptor(path: &Path) -> Result<Vec<u8>, WindowsHostError> {
        validate_deployment_path(path)?;
        let path_wide = wide_path(path)?;
        let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut required = 0_u32;
        // SAFETY: the first call requests the required self-relative descriptor size.
        let _ = unsafe {
            GetFileSecurityW(
                PCWSTR(path_wide.as_ptr()),
                information.0,
                None,
                0,
                &raw mut required,
            )
        };
        if required == 0 || required > 1024 * 1024 {
            return Err(WindowsHostError::new(
                "path security descriptor size is invalid",
            ));
        }
        let mut bytes = vec![0_u8; required as usize];
        // SAFETY: bytes is writable for the exact size requested by the first call.
        let result = unsafe {
            GetFileSecurityW(
                PCWSTR(path_wide.as_ptr()),
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

    pub(super) fn process_image_path(process_id: u32) -> Result<PathBuf, WindowsHostError> {
        if process_id == 0 {
            return Err(WindowsHostError::new("process id must be nonzero"));
        }
        let handle = {
            // SAFETY: access rights are read-only and no handle inheritance is requested.
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
        }
        .map_err(|error| WindowsHostError::new(format!("OpenProcess failed: {error}")))?;
        let result = (|| {
            let mut buffer = vec![0_u16; 32_768];
            let mut length = u32::try_from(buffer.len())
                .map_err(|_| WindowsHostError::new("process path buffer overflow"))?;
            // SAFETY: buffer and length describe a writable UTF-16 allocation.
            unsafe {
                QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_WIN32,
                    PWSTR(buffer.as_mut_ptr()),
                    &raw mut length,
                )
            }
            .map_err(|error| {
                WindowsHostError::new(format!("QueryFullProcessImageNameW failed: {error}"))
            })?;
            let used = usize::try_from(length)
                .map_err(|_| WindowsHostError::new("process path length overflow"))?;
            buffer.truncate(used);
            Ok(PathBuf::from(String::from_utf16(&buffer).map_err(
                |error| WindowsHostError::new(format!("process path is invalid UTF-16: {error}")),
            )?))
        })();
        // SAFETY: handle is owned by this function and has not been closed.
        let _ = unsafe { CloseHandle(handle) };
        result
    }

    pub(super) fn process_session_id(process_id: u32) -> Result<u32, WindowsHostError> {
        if process_id == 0 {
            return Err(WindowsHostError::new("process id must be nonzero"));
        }
        let mut session_id = 0_u32;
        // SAFETY: session_id is writable and the caller supplied a nonzero process ID.
        unsafe { ProcessIdToSessionId(process_id, &raw mut session_id) }.map_err(|error| {
            WindowsHostError::new(format!("ProcessIdToSessionId failed: {error}"))
        })?;
        Ok(session_id)
    }

    pub(super) fn file_product_version(path: &Path) -> Result<String, WindowsHostError> {
        let path = wide_path(path)?;
        // SAFETY: `path` is NUL-terminated and all output pointers refer to
        // writable storage that remains alive for each Win32 call.
        unsafe {
            let size = GetFileVersionInfoSizeW(PCWSTR(path.as_ptr()), None);
            if size == 0 || size > 16 * 1024 * 1024 {
                return Err(WindowsHostError::new(format!(
                    "GetFileVersionInfoSizeW failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let mut bytes = vec![0_u8; size as usize];
            GetFileVersionInfoW(PCWSTR(path.as_ptr()), None, size, bytes.as_mut_ptr().cast())
                .map_err(|error| WindowsHostError::new(format!("GetFileVersionInfoW: {error}")))?;
            let root = [b'\\' as u16, 0];
            let mut value = std::ptr::null_mut();
            let mut length = 0_u32;
            if !VerQueryValueW(
                bytes.as_ptr().cast(),
                PCWSTR(root.as_ptr()),
                &mut value,
                &mut length,
            )
            .as_bool()
                || value.is_null()
                || length < size_of::<VS_FIXEDFILEINFO>() as u32
            {
                return Err(WindowsHostError::new(
                    "VerQueryValueW returned no fixed product version",
                ));
            }
            let info = &*value.cast::<VS_FIXEDFILEINFO>();
            if info.dwSignature != 0xFEEF04BD {
                return Err(WindowsHostError::new(
                    "file version resource has an invalid signature",
                ));
            }
            Ok(format!(
                "{}.{}.{}.{}",
                info.dwProductVersionMS >> 16,
                info.dwProductVersionMS & 0xffff,
                info.dwProductVersionLS >> 16,
                info.dwProductVersionLS & 0xffff
            ))
        }
    }

    pub(super) fn is_reparse_point(path: &Path) -> Result<bool, WindowsHostError> {
        let wide = wide_path(path)?;
        // SAFETY: wide is NUL-terminated and remains live for the call.
        let attributes = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            return Err(WindowsHostError::new(format!(
                "GetFileAttributesW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0)
    }

    pub(super) fn atomic_move(
        source: &Path,
        destination: &Path,
        replace: bool,
    ) -> Result<(), WindowsHostError> {
        let source = wide_path(source)?;
        let destination = wide_path(destination)?;
        let mut flags = MOVEFILE_WRITE_THROUGH;
        if replace {
            flags |= MOVEFILE_REPLACE_EXISTING;
        }
        // SAFETY: both path buffers are NUL-terminated and remain live for the call.
        unsafe { MoveFileExW(PCWSTR(source.as_ptr()), PCWSTR(destination.as_ptr()), flags) }
            .map_err(|error| WindowsHostError::new(format!("MoveFileExW failed: {error}")))
    }

    fn current_token_identity() -> Result<(String, u32, String, bool), WindowsHostError> {
        let mut token = HANDLE::default();
        // SAFETY: GetCurrentProcess returns a pseudo-handle and token is writable.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
            .map_err(|error| WindowsHostError::new(format!("OpenProcessToken failed: {error}")))?;
        let result = (|| {
            let user = token_information(token, TokenUser)?;
            // SAFETY: token_information returns aligned storage containing TOKEN_USER.
            let user_sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
            let user_sid = sid_to_string(user_sid)?;

            let integrity = token_information(token, TokenIntegrityLevel)?;
            // SAFETY: aligned storage contains TOKEN_MANDATORY_LABEL and a live SID.
            let integrity_sid = unsafe {
                (*(integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()))
                    .Label
                    .Sid
            };
            // SAFETY: integrity_sid is a valid token-owned SID for the storage lifetime.
            let count = unsafe { *GetSidSubAuthorityCount(integrity_sid) };
            if count == 0 {
                return Err(WindowsHostError::new(
                    "token integrity SID has no sub-authority",
                ));
            }
            // SAFETY: count is nonzero and the final sub-authority is the integrity RID.
            let integrity_level_rid =
                unsafe { *GetSidSubAuthority(integrity_sid, u32::from(count - 1)) };

            let elevation = token_information(token, TokenElevationType)?;
            // SAFETY: aligned storage contains TOKEN_ELEVATION_TYPE.
            let elevation = unsafe { *elevation.as_ptr().cast::<TOKEN_ELEVATION_TYPE>() };
            let elevation_type = if elevation == TokenElevationTypeDefault {
                "default"
            } else if elevation == TokenElevationTypeFull {
                "full"
            } else if elevation == TokenElevationTypeLimited {
                "limited"
            } else {
                return Err(WindowsHostError::new("token elevation type is unsupported"));
            }
            .to_owned();

            let appcontainer = token_information(token, TokenIsAppContainer)?;
            // SAFETY: aligned storage contains a DWORD boolean.
            let is_appcontainer = unsafe { *appcontainer.as_ptr().cast::<u32>() } != 0;
            Ok((
                user_sid,
                integrity_level_rid,
                elevation_type,
                is_appcontainer,
            ))
        })();
        // SAFETY: token is an owned handle returned by OpenProcessToken.
        let _ = unsafe { CloseHandle(token) };
        result
    }

    fn verify_appcontainer_process(
        process: HANDLE,
        expected_profile_sid: &str,
    ) -> Result<(), WindowsHostError> {
        let mut token = HANDLE::default();
        // SAFETY: process is a live child handle and token is writable.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.map_err(|error| {
            WindowsHostError::new(format!("child OpenProcessToken failed: {error}"))
        })?;
        let result = (|| {
            let appcontainer = token_information(token, TokenIsAppContainer)?;
            // SAFETY: aligned storage contains a DWORD boolean.
            if unsafe { *appcontainer.as_ptr().cast::<u32>() } == 0 {
                return Err(WindowsHostError::new(
                    "created child token is not an AppContainer",
                ));
            }
            let information = token_information(token, TokenAppContainerSid)?;
            // SAFETY: aligned storage contains TOKEN_APPCONTAINER_INFORMATION.
            let sid = unsafe {
                (*(information
                    .as_ptr()
                    .cast::<TOKEN_APPCONTAINER_INFORMATION>()))
                .TokenAppContainer
            };
            if sid_to_string(sid)? != expected_profile_sid {
                return Err(WindowsHostError::new(
                    "created child AppContainer SID differs from configuration",
                ));
            }
            Ok(())
        })();
        // SAFETY: token is an owned handle returned by OpenProcessToken.
        let _ = unsafe { CloseHandle(token) };
        result
    }

    fn token_information(
        token: HANDLE,
        class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> Result<Vec<usize>, WindowsHostError> {
        let mut required = 0_u32;
        // SAFETY: the first call requests the required buffer size.
        let _ = unsafe { GetTokenInformation(token, class, None, 0, &raw mut required) };
        if required == 0 || required > 1024 * 1024 {
            return Err(WindowsHostError::new("token information size is invalid"));
        }
        let words = usize::try_from(required)
            .ok()
            .and_then(|value| value.checked_add(size_of::<usize>() - 1))
            .and_then(|value| value.checked_div(size_of::<usize>()))
            .ok_or_else(|| WindowsHostError::new("token information size overflow"))?;
        let mut storage = vec![0_usize; words];
        // SAFETY: storage is aligned and has at least required writable bytes.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(storage.as_mut_ptr().cast()),
                required,
                &raw mut required,
            )
        }
        .map_err(|error| WindowsHostError::new(format!("GetTokenInformation failed: {error}")))?;
        Ok(storage)
    }

    fn sid_to_string(sid: PSID) -> Result<String, WindowsHostError> {
        if sid.0.is_null() {
            return Err(WindowsHostError::new("SID pointer is null"));
        }
        let mut value = PWSTR::null();
        // SAFETY: sid is valid for the call and value is writable.
        unsafe { ConvertSidToStringSidW(sid, &raw mut value) }.map_err(|error| {
            WindowsHostError::new(format!("ConvertSidToStringSidW failed: {error}"))
        })?;
        // SAFETY: the API returned a NUL-terminated string allocated with LocalAlloc.
        let converted = unsafe { value.to_string() }
            .map_err(|error| WindowsHostError::new(format!("SID is invalid UTF-16: {error}")));
        // SAFETY: ConvertSidToStringSidW allocates value with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(value.0.cast()))) };
        converted
    }

    fn validate_profile_name(profile_name: &str) -> Result<(), WindowsHostError> {
        if profile_name.is_empty()
            || profile_name.len() > 64
            || !profile_name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b' ')
            })
        {
            return Err(WindowsHostError::new(
                "AppContainer profile name is outside the supported syntax",
            ));
        }
        Ok(())
    }

    fn validate_deployment_path(path: &Path) -> Result<(), WindowsHostError> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| WindowsHostError::new(format!("path metadata failed: {error}")))?;
        if metadata.file_type().is_symlink() {
            return Err(WindowsHostError::new(
                "deployment security paths must not be symlinks",
            ));
        }
        Ok(())
    }

    fn windows_command_line(
        executable: &OsStr,
        arguments: &[String],
    ) -> Result<Vec<u16>, WindowsHostError> {
        if arguments.len() > 128 {
            return Err(WindowsHostError::new(
                "AppContainer argument count exceeds 128",
            ));
        }
        let mut output = Vec::new();
        append_windows_argument(&mut output, executable)?;
        for argument in arguments {
            output.push(b' ' as u16);
            append_windows_argument(&mut output, OsStr::new(argument))?;
        }
        if output.len() >= 32_767 {
            return Err(WindowsHostError::new(
                "AppContainer command line exceeds Windows bounds",
            ));
        }
        output.push(0);
        Ok(output)
    }

    fn windows_environment_block(
        environment: &[(String, String)],
    ) -> Result<Vec<u16>, WindowsHostError> {
        if environment.is_empty() || environment.len() > 32 {
            return Err(WindowsHostError::new(
                "AppContainer environment count is outside 1..=32",
            ));
        }
        let mut entries = environment.to_vec();
        entries.sort_by_key(|(name, _)| name.to_ascii_uppercase());
        for pair in entries.windows(2) {
            if pair[0].0.eq_ignore_ascii_case(&pair[1].0) {
                return Err(WindowsHostError::new(
                    "AppContainer environment contains a duplicate name",
                ));
            }
        }
        let mut output = Vec::new();
        for (name, value) in entries {
            if name.is_empty()
                || name.len() > 128
                || !name.bytes().enumerate().all(|(index, byte)| {
                    if index == 0 {
                        byte.is_ascii_alphabetic() || byte == b'_'
                    } else {
                        byte.is_ascii_alphanumeric() || byte == b'_'
                    }
                })
                || value.len() > 32_768
                || value.contains('\0')
            {
                return Err(WindowsHostError::new(
                    "AppContainer environment entry is outside supported bounds",
                ));
            }
            output.extend(OsStr::new(&name).encode_wide());
            output.push(b'=' as u16);
            output.extend(OsStr::new(&value).encode_wide());
            output.push(0);
        }
        output.push(0);
        if output.len() >= 32_767 {
            return Err(WindowsHostError::new(
                "AppContainer environment block exceeds Windows bounds",
            ));
        }
        Ok(output)
    }

    fn append_windows_argument(
        output: &mut Vec<u16>,
        argument: &OsStr,
    ) -> Result<(), WindowsHostError> {
        let units: Vec<u16> = argument.encode_wide().collect();
        if units.contains(&0) {
            return Err(WindowsHostError::new("AppContainer argument contains NUL"));
        }
        let requires_quotes =
            units.is_empty() || units.iter().any(|unit| matches!(*unit, 0x09 | 0x20 | 0x22));
        if !requires_quotes {
            output.extend_from_slice(&units);
            return Ok(());
        }
        output.push(b'"' as u16);
        let mut backslashes = 0_usize;
        for unit in units {
            if unit == b'\\' as u16 {
                backslashes = backslashes.saturating_add(1);
                continue;
            }
            if unit == b'"' as u16 {
                output.extend(std::iter::repeat_n(
                    b'\\' as u16,
                    backslashes.saturating_mul(2).saturating_add(1),
                ));
                output.push(unit);
            } else {
                output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
                output.push(unit);
            }
            backslashes = 0;
        }
        output.extend(std::iter::repeat_n(
            b'\\' as u16,
            backslashes.saturating_mul(2),
        ));
        output.push(b'"' as u16);
        Ok(())
    }

    fn validate_dpapi_input(bytes: &[u8], purpose: &[u8]) -> Result<(), WindowsHostError> {
        if bytes.is_empty()
            || bytes.len() > 1024 * 1024
            || purpose.is_empty()
            || purpose.len() > 4096
        {
            return Err(WindowsHostError::new(
                "DPAPI input or purpose is outside bounds",
            ));
        }
        Ok(())
    }

    fn blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, WindowsHostError> {
        Ok(CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len())
                .map_err(|_| WindowsHostError::new("DPAPI blob length overflow"))?,
            pbData: bytes.as_ptr().cast_mut(),
        })
    }

    fn copy_and_free_blob(blob: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, WindowsHostError> {
        if blob.cbData == 0 || blob.cbData > 1024 * 1024 || blob.pbData.is_null() {
            if !blob.pbData.is_null() {
                // SAFETY: DPAPI allocated the output with LocalAlloc.
                let _ = unsafe { LocalFree(Some(HLOCAL(blob.pbData.cast()))) };
            }
            return Err(WindowsHostError::new("DPAPI output is outside bounds"));
        }
        // SAFETY: DPAPI returned cbData initialized bytes at pbData.
        let output =
            unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec() };
        // SAFETY: DPAPI allocated the output with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(blob.pbData.cast()))) };
        Ok(output)
    }

    fn wide_string(value: &str) -> Result<Vec<u16>, WindowsHostError> {
        let mut wide: Vec<u16> = value.encode_utf16().collect();
        if wide.is_empty() || wide.contains(&0) {
            return Err(WindowsHostError::new(
                "Windows string is empty or contains NUL",
            ));
        }
        wide.push(0);
        Ok(wide)
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, WindowsHostError> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) {
            return Err(WindowsHostError::new(
                "Windows path is empty or contains NUL",
            ));
        }
        wide.push(0);
        Ok(wide)
    }

    impl Drop for WindowsJob {
        fn drop(&mut self) {
            // SAFETY: handle is uniquely owned by this value.
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }

    impl Drop for WindowsAppContainerChild {
        fn drop(&mut self) {
            if matches!(appcontainer_child_try_wait(self), Ok(None)) {
                // SAFETY: handle is live and uniquely owned by this value.
                let _ = unsafe { TerminateProcess(self.handle, 1) };
            }
            // SAFETY: handle is uniquely owned by this value.
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{
        WindowsAppContainerChild, WindowsAppContainerPathAccess, WindowsAppContainerProfile,
        WindowsHostError, WindowsHostIdentity, WindowsJob, WindowsJobLimits,
    };
    use std::path::{Path, PathBuf};
    use std::process::Child;
    use std::time::Duration;

    fn unavailable() -> WindowsHostError {
        WindowsHostError::new("Windows host integration is unavailable on this platform")
    }

    pub(super) fn create_job(_limits: WindowsJobLimits) -> Result<WindowsJob, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn assign_child(_job: &WindowsJob, _child: &Child) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn terminate_job(_job: &WindowsJob) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn job_memory_accounting(
        _job: &WindowsJob,
    ) -> Result<WindowsJobMemoryAccounting, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn host_identity() -> Result<WindowsHostIdentity, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn provision_appcontainer_profile(
        _profile_name: &str,
    ) -> Result<WindowsAppContainerProfile, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn appcontainer_profile(
        _profile_name: &str,
    ) -> Result<WindowsAppContainerProfile, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn delete_appcontainer_profile(_profile_name: &str) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn grant_appcontainer_path_access(
        _profile_name: &str,
        _path: &Path,
        _access: WindowsAppContainerPathAccess,
        _inherit_to_children: bool,
    ) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn spawn_zero_capability_appcontainer(
        _profile_name: &str,
        _expected_profile_sid: &str,
        _executable: &Path,
        _arguments: &[String],
        _working_directory: &Path,
        _environment: Option<&[(String, String)]>,
        _job: Option<&WindowsJob>,
    ) -> Result<WindowsAppContainerChild, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn appcontainer_child_id(_child: &WindowsAppContainerChild) -> u32 {
        0
    }

    pub(super) fn appcontainer_child_try_wait(
        _child: &WindowsAppContainerChild,
    ) -> Result<Option<u32>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn appcontainer_child_wait_timeout(
        _child: &WindowsAppContainerChild,
        _timeout: Duration,
    ) -> Result<Option<u32>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn terminate_appcontainer_child(
        _child: &WindowsAppContainerChild,
    ) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn protect_current_user(
        _plaintext: &[u8],
        _purpose: &[u8],
    ) -> Result<Vec<u8>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn unprotect_current_user(
        _protected: &[u8],
        _purpose: &[u8],
    ) -> Result<Vec<u8>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn secure_random_bytes<const N: usize>() -> Result<[u8; N], WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn monotonic_milliseconds() -> Result<u64, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn harden_path_for_current_user(_path: &Path) -> Result<Vec<u8>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn path_security_descriptor(_path: &Path) -> Result<Vec<u8>, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn process_image_path(_process_id: u32) -> Result<PathBuf, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn process_session_id(_process_id: u32) -> Result<u32, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn file_product_version(_path: &Path) -> Result<String, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn is_reparse_point(_path: &Path) -> Result<bool, WindowsHostError> {
        Err(unavailable())
    }

    pub(super) fn atomic_move(
        _source: &Path,
        _destination: &Path,
        _replace: bool,
    ) -> Result<(), WindowsHostError> {
        Err(unavailable())
    }
}

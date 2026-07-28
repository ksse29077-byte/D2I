//! Exact Windows Filtering Platform policy for a loopback-only application.

use crate::WindowsHostError;
use std::path::Path;

/// Stable identity of the D2I WFP objects installed for one browser image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsWfpLoopbackPolicyIdentity {
    pub provider_key: String,
    pub sublayer_key: String,
    pub filter_keys: [String; 4],
    pub verifier_sid: String,
    pub engine_security_descriptor_sddl: String,
    pub security_descriptor_sddl: String,
}

/// Installs the persistent, application-scoped loopback-only WFP policy.
pub fn install_wfp_loopback_policy(
    application: &Path,
    verifier_sid: &str,
    owner_sid: &str,
) -> Result<WindowsWfpLoopbackPolicyIdentity, WindowsHostError> {
    platform::install(application, verifier_sid, owner_sid)
}

/// Verifies every persistent WFP object and condition against the application.
pub fn verify_wfp_loopback_policy(
    application: &Path,
    verifier_sid: &str,
    owner_sid: &str,
) -> Result<WindowsWfpLoopbackPolicyIdentity, WindowsHostError> {
    platform::verify(application, verifier_sid, owner_sid)
}

/// Removes the D2I WFP policy. Missing objects are treated as already removed.
pub fn remove_wfp_loopback_policy(verifier_sid: &str) -> Result<(), WindowsHostError> {
    platform::remove(verifier_sid)
}

#[cfg(windows)]
mod platform {
    use super::{WindowsHostError, WindowsWfpLoopbackPolicyIdentity};
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null_mut, NonNull};
    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        LocalFree, ERROR_ACCESS_DENIED, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
        FWP_E_SUBLAYER_NOT_FOUND, HANDLE, HLOCAL,
    };
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineGetSecurityInfo0, FwpmEngineOpen0, FwpmEngineSetSecurityInfo0,
        FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmFilterGetByKey0,
        FwpmFilterGetSecurityInfoByKey0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
        FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmProviderGetByKey0,
        FwpmProviderGetSecurityInfoByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
        FwpmSubLayerGetByKey0, FwpmSubLayerGetSecurityInfoByKey0, FwpmTransactionAbort0,
        FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTRL_OPEN,
        FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0,
        FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_INDEXED,
        FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0, FWPM_PROVIDER_FLAG_PERSISTENT,
        FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
        FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
        FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT64, FWP_V4_ADDR_AND_MASK,
        FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
        GetExplicitEntriesFromAclW, SetEntriesInAclW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
        REVOKE_ACCESS, SDDL_REVISION_1, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SE_DACL_PROTECTED,
    };
    use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

    const PROVIDER_KEY: GUID = GUID::from_u128(0xeffa5c68_709d_4311_9a4c_1ff4f3c20bf0);
    const SUBLAYER_KEY: GUID = GUID::from_u128(0xf328c32f_dba5_4527_bcc0_c3763b734590);
    const V4_LOOPBACK_PERMIT_KEY: GUID = GUID::from_u128(0x769fcfb8_8dc3_4685_8e70_49deff9012d9);
    const V4_EGRESS_BLOCK_KEY: GUID = GUID::from_u128(0xfaab358b_8445_488e_8836_ce1173cd6000);
    const V6_LOOPBACK_PERMIT_KEY: GUID = GUID::from_u128(0x5433444c_fc9f_4845_9139_f83e316cbac2);
    const V6_EGRESS_BLOCK_KEY: GUID = GUID::from_u128(0x17ddc305_ac3a_4799_886e_0990bed1f105);
    const PROVIDER_NAME: &str = "D2I Browser Egress Provider v1";
    const PROVIDER_DESCRIPTION: &str =
        "D2I persistent WFP provider for a hash-pinned loopback-only browser";
    const SUBLAYER_NAME: &str = "D2I Browser Loopback-Only Sublayer v1";
    const SUBLAYER_DESCRIPTION: &str =
        "Permits browser loopback and blocks all other browser connect attempts";
    const SUBLAYER_WEIGHT: u16 = u16::MAX;
    const PERMIT_WEIGHT: u64 = u64::MAX;
    const BLOCK_WEIGHT: u64 = u64::MAX - 1;
    const ADMIN_OBJECT_ACCESS: u32 = 0x000f_07ff;
    const VERIFIER_OBJECT_ACCESS: u32 = 0x0002_0080;
    const VERIFIER_ENGINE_ACCESS: u32 = 0x0002_0000 | FWPM_ACTRL_OPEN;

    struct Engine(HANDLE);

    impl Drop for Engine {
        fn drop(&mut self) {
            // SAFETY: the handle is owned by this guard and closed once.
            unsafe {
                let _ = FwpmEngineClose0(self.0);
            }
        }
    }

    struct WfpMemory<T>(NonNull<T>);

    impl<T> WfpMemory<T> {
        fn new(pointer: *mut T, operation: &str) -> Result<Self, WindowsHostError> {
            NonNull::new(pointer)
                .map(Self)
                .ok_or_else(|| WindowsHostError::new(format!("{operation} returned a null object")))
        }

        fn as_ref(&self) -> &T {
            // SAFETY: WFP returned a non-null allocation valid until freed.
            unsafe { self.0.as_ref() }
        }
    }

    impl<T> Drop for WfpMemory<T> {
        fn drop(&mut self) {
            let mut pointer = self.0.as_ptr().cast::<c_void>();
            // SAFETY: this allocation came from a documented WFP API.
            unsafe {
                FwpmFreeMemory0(&mut pointer);
            }
        }
    }

    struct AppId(WfpMemory<FWP_BYTE_BLOB>);

    impl AppId {
        fn blob(&self) -> &FWP_BYTE_BLOB {
            self.0.as_ref()
        }

        fn bytes(&self) -> Result<&[u8], WindowsHostError> {
            blob_bytes(self.blob())
        }
    }

    struct SecurityDescriptor {
        value: PSECURITY_DESCRIPTOR,
        sddl: String,
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            if !self.value.0.is_null() {
                // SAFETY: SDDL conversion allocates this descriptor with LocalAlloc.
                let _ = unsafe { LocalFree(Some(HLOCAL(self.value.0))) };
            }
        }
    }

    struct WfpSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for WfpSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                let mut pointer = self.0 .0;
                // SAFETY: WFP allocated this security descriptor.
                unsafe {
                    FwpmFreeMemory0(&mut pointer);
                }
            }
        }
    }

    struct LocalSid(PSID);

    impl Drop for LocalSid {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: ConvertStringSidToSidW allocates this SID with LocalAlloc.
                let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
            }
        }
    }

    struct LocalAcl(*mut ACL);

    impl Drop for LocalAcl {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: SetEntriesInAclW allocates this ACL with LocalAlloc.
                let _ = unsafe { LocalFree(Some(HLOCAL(self.0.cast()))) };
            }
        }
    }

    struct LocalExplicitEntries(*mut EXPLICIT_ACCESS_W);

    impl Drop for LocalExplicitEntries {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: GetExplicitEntriesFromAclW allocates with LocalAlloc.
                let _ = unsafe { LocalFree(Some(HLOCAL(self.0.cast()))) };
            }
        }
    }

    struct DisplayStrings {
        name: Vec<u16>,
        description: Vec<u16>,
    }

    impl DisplayStrings {
        fn new(name: &str, description: &str) -> Self {
            Self {
                name: wide_text(name),
                description: wide_text(description),
            }
        }

        fn data(&mut self) -> FWPM_DISPLAY_DATA0 {
            FWPM_DISPLAY_DATA0 {
                name: PWSTR(self.name.as_mut_ptr()),
                description: PWSTR(self.description.as_mut_ptr()),
            }
        }
    }

    struct Transaction<'a> {
        engine: &'a Engine,
        active: bool,
    }

    impl<'a> Transaction<'a> {
        fn begin(engine: &'a Engine) -> Result<Self, WindowsHostError> {
            // SAFETY: the engine handle is live and owned by `engine`.
            let code = unsafe { FwpmTransactionBegin0(engine.0, 0) };
            check(code, "FwpmTransactionBegin0")?;
            Ok(Self {
                engine,
                active: true,
            })
        }

        fn commit(mut self) -> Result<(), WindowsHostError> {
            // SAFETY: this guard owns the active transaction.
            let code = unsafe { FwpmTransactionCommit0(self.engine.0) };
            check(code, "FwpmTransactionCommit0")?;
            self.active = false;
            Ok(())
        }
    }

    impl Drop for Transaction<'_> {
        fn drop(&mut self) {
            if self.active {
                // SAFETY: this guard owns the active transaction.
                unsafe {
                    let _ = FwpmTransactionAbort0(self.engine.0);
                }
            }
        }
    }

    pub(super) fn install(
        application: &Path,
        verifier_sid: &str,
        owner_sid: &str,
    ) -> Result<WindowsWfpLoopbackPolicyIdentity, WindowsHostError> {
        let descriptor = object_security_descriptor(verifier_sid, owner_sid)?;
        let engine = open_engine()?;
        set_engine_verifier_access(&engine, verifier_sid, true)?;
        if let Ok(engine_sddl) = verify_with_engine(&engine, application, verifier_sid, owner_sid) {
            return Ok(identity(verifier_sid, &engine_sddl, &descriptor.sddl));
        }
        let app_id = app_id(application)?;
        let install_result = (|| {
            let transaction = Transaction::begin(&engine)?;
            add_provider(&engine, descriptor.value)?;
            add_sublayer(&engine, descriptor.value)?;
            add_filters(&engine, &app_id, descriptor.value)?;
            transaction.commit()
        })();
        if let Err(error) = install_result {
            drop(engine);
            return match remove(verifier_sid) {
                Ok(()) => Err(WindowsHostError::new(format!(
                    "WFP installation failed and partial policy was recalled: {error}"
                ))),
                Err(cleanup) => Err(WindowsHostError::new(format!(
                    "WFP installation failed ({error}); recall also failed ({cleanup})"
                ))),
            };
        }
        let engine_sddl = match verify_with_engine(&engine, application, verifier_sid, owner_sid) {
            Ok(value) => value,
            Err(error) => {
                drop(engine);
                return match remove(verifier_sid) {
                    Ok(()) => Err(WindowsHostError::new(format!(
                        "post-install WFP verification failed and policy was recalled: {error}"
                    ))),
                    Err(cleanup) => Err(WindowsHostError::new(format!(
                        "post-install WFP verification failed ({error}); recall also failed ({cleanup})"
                    ))),
                };
            }
        };
        Ok(identity(verifier_sid, &engine_sddl, &descriptor.sddl))
    }

    pub(super) fn verify(
        application: &Path,
        verifier_sid: &str,
        owner_sid: &str,
    ) -> Result<WindowsWfpLoopbackPolicyIdentity, WindowsHostError> {
        let descriptor = object_security_descriptor(verifier_sid, owner_sid)?;
        let engine = open_engine()?;
        let engine_sddl = verify_with_engine(&engine, application, verifier_sid, owner_sid)?;
        Ok(identity(verifier_sid, &engine_sddl, &descriptor.sddl))
    }

    pub(super) fn remove(verifier_sid: &str) -> Result<(), WindowsHostError> {
        validate_verifier_sid(verifier_sid)?;
        let engine = open_engine()?;
        let transaction = Transaction::begin(&engine)?;
        for key in [
            V4_LOOPBACK_PERMIT_KEY,
            V4_EGRESS_BLOCK_KEY,
            V6_LOOPBACK_PERMIT_KEY,
            V6_EGRESS_BLOCK_KEY,
        ] {
            // SAFETY: the engine and key pointers are valid.
            let code = unsafe { FwpmFilterDeleteByKey0(engine.0, &key) };
            check_missing(
                code,
                FWP_E_FILTER_NOT_FOUND.0 as u32,
                "FwpmFilterDeleteByKey0",
            )?;
        }
        // SAFETY: the engine and key pointers are valid.
        let code = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &SUBLAYER_KEY) };
        check_missing(
            code,
            FWP_E_SUBLAYER_NOT_FOUND.0 as u32,
            "FwpmSubLayerDeleteByKey0",
        )?;
        // SAFETY: the engine and key pointers are valid.
        let code = unsafe { FwpmProviderDeleteByKey0(engine.0, &PROVIDER_KEY) };
        check_missing(
            code,
            FWP_E_PROVIDER_NOT_FOUND.0 as u32,
            "FwpmProviderDeleteByKey0",
        )?;
        transaction.commit()?;
        verify_removed_with_engine(&engine)?;
        set_engine_verifier_access(&engine, verifier_sid, false)
    }

    fn verify_removed_with_engine(engine: &Engine) -> Result<(), WindowsHostError> {
        for key in [
            V4_LOOPBACK_PERMIT_KEY,
            V4_EGRESS_BLOCK_KEY,
            V6_LOOPBACK_PERMIT_KEY,
            V6_EGRESS_BLOCK_KEY,
        ] {
            let mut pointer = null_mut();
            // SAFETY: the engine, key, and writable output pointer are valid.
            let code = unsafe { FwpmFilterGetByKey0(engine.0, &key, &raw mut pointer) };
            if !pointer.is_null() {
                drop(WfpMemory::new(
                    pointer,
                    "FwpmFilterGetByKey0 cleanup verification",
                )?);
            }
            if code != FWP_E_FILTER_NOT_FOUND.0 as u32 {
                return Err(WindowsHostError::new(format!(
                    "WFP filter or its object ACL remains after removal: 0x{code:08x}"
                )));
            }
        }
        let mut sublayer = null_mut();
        // SAFETY: the engine, key, and writable output pointer are valid.
        let code = unsafe { FwpmSubLayerGetByKey0(engine.0, &SUBLAYER_KEY, &raw mut sublayer) };
        if !sublayer.is_null() {
            drop(WfpMemory::new(
                sublayer,
                "FwpmSubLayerGetByKey0 cleanup verification",
            )?);
        }
        if code != FWP_E_SUBLAYER_NOT_FOUND.0 as u32 {
            return Err(WindowsHostError::new(format!(
                "WFP sublayer or its object ACL remains after removal: 0x{code:08x}"
            )));
        }
        let mut provider = null_mut();
        // SAFETY: the engine, key, and writable output pointer are valid.
        let code = unsafe { FwpmProviderGetByKey0(engine.0, &PROVIDER_KEY, &raw mut provider) };
        if !provider.is_null() {
            drop(WfpMemory::new(
                provider,
                "FwpmProviderGetByKey0 cleanup verification",
            )?);
        }
        if code != FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
            return Err(WindowsHostError::new(format!(
                "WFP provider or its object ACL remains after removal: 0x{code:08x}"
            )));
        }
        Ok(())
    }

    fn identity(
        verifier_sid: &str,
        engine_security_descriptor_sddl: &str,
        security_descriptor_sddl: &str,
    ) -> WindowsWfpLoopbackPolicyIdentity {
        WindowsWfpLoopbackPolicyIdentity {
            provider_key: "effa5c68-709d-4311-9a4c-1ff4f3c20bf0".to_owned(),
            sublayer_key: "f328c32f-dba5-4527-bcc0-c3763b734590".to_owned(),
            filter_keys: [
                "769fcfb8-8dc3-4685-8e70-49deff9012d9".to_owned(),
                "faab358b-8445-488e-8836-ce1173cd6000".to_owned(),
                "5433444c-fc9f-4845-9139-f83e316cbac2".to_owned(),
                "17ddc305-ac3a-4799-886e-0990bed1f105".to_owned(),
            ],
            verifier_sid: verifier_sid.to_owned(),
            engine_security_descriptor_sddl: engine_security_descriptor_sddl.to_owned(),
            security_descriptor_sddl: security_descriptor_sddl.to_owned(),
        }
    }

    fn open_engine() -> Result<Engine, WindowsHostError> {
        let mut handle = HANDLE::default();
        // SAFETY: all optional pointers are null and `handle` is writable.
        let code =
            unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut handle) };
        check(code, "FwpmEngineOpen0")?;
        if handle.is_invalid() {
            return Err(WindowsHostError::new(
                "FwpmEngineOpen0 returned an invalid handle",
            ));
        }
        Ok(Engine(handle))
    }

    fn app_id(application: &Path) -> Result<AppId, WindowsHostError> {
        let wide = wide_path(application);
        let mut pointer = null_mut();
        // SAFETY: `wide` is NUL-terminated and `pointer` is writable.
        let code = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut pointer) };
        check(code, "FwpmGetAppIdFromFileName0")?;
        let app_id = AppId(WfpMemory::new(pointer, "FwpmGetAppIdFromFileName0")?);
        let _ = app_id.bytes()?;
        Ok(app_id)
    }

    fn add_provider(
        engine: &Engine,
        descriptor: PSECURITY_DESCRIPTOR,
    ) -> Result<(), WindowsHostError> {
        let mut display = DisplayStrings::new(PROVIDER_NAME, PROVIDER_DESCRIPTION);
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: display.data(),
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            ..Default::default()
        };
        // SAFETY: all provider pointers remain live for the duration of the call.
        let code = unsafe { FwpmProviderAdd0(engine.0, &provider, Some(descriptor)) };
        check(code, "FwpmProviderAdd0")
    }

    fn add_sublayer(
        engine: &Engine,
        descriptor: PSECURITY_DESCRIPTOR,
    ) -> Result<(), WindowsHostError> {
        let mut display = DisplayStrings::new(SUBLAYER_NAME, SUBLAYER_DESCRIPTION);
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display.data(),
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            weight: SUBLAYER_WEIGHT,
            ..Default::default()
        };
        // SAFETY: all sublayer pointers remain live for the duration of the call.
        let code = unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, Some(descriptor)) };
        check(code, "FwpmSubLayerAdd0")
    }

    fn add_filters(
        engine: &Engine,
        app_id: &AppId,
        descriptor: PSECURITY_DESCRIPTOR,
    ) -> Result<(), WindowsHostError> {
        let mut v4_loopback = FWP_V4_ADDR_AND_MASK {
            addr: 0x7f00_0000,
            mask: 0xff00_0000,
        };
        let mut v6_loopback = FWP_V6_ADDR_AND_MASK {
            addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            prefixLength: 128,
        };
        add_filter(
            engine,
            app_id,
            V4_LOOPBACK_PERMIT_KEY,
            "D2I Browser IPv4 Loopback Permit v1",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_PERMIT,
            PERMIT_WEIGHT,
            Some(AddressCondition::V4(&mut v4_loopback)),
            descriptor,
        )?;
        add_filter(
            engine,
            app_id,
            V4_EGRESS_BLOCK_KEY,
            "D2I Browser IPv4 Egress Block v1",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_BLOCK,
            BLOCK_WEIGHT,
            None,
            descriptor,
        )?;
        add_filter(
            engine,
            app_id,
            V6_LOOPBACK_PERMIT_KEY,
            "D2I Browser IPv6 Loopback Permit v1",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_PERMIT,
            PERMIT_WEIGHT,
            Some(AddressCondition::V6(&mut v6_loopback)),
            descriptor,
        )?;
        add_filter(
            engine,
            app_id,
            V6_EGRESS_BLOCK_KEY,
            "D2I Browser IPv6 Egress Block v1",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_BLOCK,
            BLOCK_WEIGHT,
            None,
            descriptor,
        )
    }

    enum AddressCondition<'a> {
        V4(&'a mut FWP_V4_ADDR_AND_MASK),
        V6(&'a mut FWP_V6_ADDR_AND_MASK),
    }

    #[allow(clippy::too_many_arguments)]
    fn add_filter(
        engine: &Engine,
        app_id: &AppId,
        key: GUID,
        name: &str,
        layer: GUID,
        action: FWP_ACTION_TYPE,
        weight: u64,
        address: Option<AddressCondition<'_>>,
        descriptor: PSECURITY_DESCRIPTOR,
    ) -> Result<(), WindowsHostError> {
        let mut app_blob = *app_id.blob();
        let mut exact_weight = weight;
        let mut conditions = vec![FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: &mut app_blob,
                },
            },
        }];
        match address {
            Some(AddressCondition::V4(value)) => conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: value },
                },
            }),
            Some(AddressCondition::V6(value)) => conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: value },
                },
            }),
            None => {}
        }
        let mut display = DisplayStrings::new(name, SUBLAYER_DESCRIPTION);
        let filter = FWPM_FILTER0 {
            filterKey: key,
            displayData: display.data(),
            flags: FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_INDEXED,
            layerKey: layer,
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut exact_weight,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: action,
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: all filter and condition pointers remain live for the call.
        let code = unsafe { FwpmFilterAdd0(engine.0, &filter, Some(descriptor), None) };
        check(code, "FwpmFilterAdd0")
    }

    fn verify_with_engine(
        engine: &Engine,
        application: &Path,
        verifier_sid: &str,
        owner_sid: &str,
    ) -> Result<String, WindowsHostError> {
        let engine_sddl = verify_engine_security(engine, verifier_sid)?;
        let app_id = app_id(application)?;
        verify_provider(engine)?;
        verify_provider_security(engine, verifier_sid, owner_sid)?;
        verify_sublayer(engine)?;
        verify_sublayer_security(engine, verifier_sid, owner_sid)?;
        verify_filter(
            engine,
            &app_id,
            V4_LOOPBACK_PERMIT_KEY,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_PERMIT,
            PERMIT_WEIGHT,
            ExpectedAddress::V4,
        )?;
        verify_filter_security(engine, &V4_LOOPBACK_PERMIT_KEY, verifier_sid, owner_sid)?;
        verify_filter(
            engine,
            &app_id,
            V4_EGRESS_BLOCK_KEY,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWP_ACTION_BLOCK,
            BLOCK_WEIGHT,
            ExpectedAddress::None,
        )?;
        verify_filter_security(engine, &V4_EGRESS_BLOCK_KEY, verifier_sid, owner_sid)?;
        verify_filter(
            engine,
            &app_id,
            V6_LOOPBACK_PERMIT_KEY,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_PERMIT,
            PERMIT_WEIGHT,
            ExpectedAddress::V6,
        )?;
        verify_filter_security(engine, &V6_LOOPBACK_PERMIT_KEY, verifier_sid, owner_sid)?;
        verify_filter(
            engine,
            &app_id,
            V6_EGRESS_BLOCK_KEY,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_BLOCK,
            BLOCK_WEIGHT,
            ExpectedAddress::None,
        )?;
        verify_filter_security(engine, &V6_EGRESS_BLOCK_KEY, verifier_sid, owner_sid)?;
        Ok(engine_sddl)
    }

    fn verify_provider(engine: &Engine) -> Result<(), WindowsHostError> {
        let provider = get_provider(engine)?;
        let provider = provider.as_ref();
        if provider.providerKey != PROVIDER_KEY
            || provider.flags != FWPM_PROVIDER_FLAG_PERSISTENT
            || provider.providerData.size != 0
            || !provider.providerData.data.is_null()
            || !provider.serviceName.is_null()
            || wide_string(provider.displayData.name)? != PROVIDER_NAME
            || wide_string(provider.displayData.description)? != PROVIDER_DESCRIPTION
        {
            return Err(WindowsHostError::new(
                "installed WFP provider differs from the D2I loopback policy",
            ));
        }
        Ok(())
    }

    fn verify_sublayer(engine: &Engine) -> Result<(), WindowsHostError> {
        let sublayer = get_sublayer(engine)?;
        let sublayer = sublayer.as_ref();
        if sublayer.subLayerKey != SUBLAYER_KEY
            || sublayer.flags != FWPM_SUBLAYER_FLAG_PERSISTENT
            || sublayer.providerData.size != 0
            || !sublayer.providerData.data.is_null()
            || sublayer.weight != SUBLAYER_WEIGHT
            || !sublayer.providerKey.is_null()
            || wide_string(sublayer.displayData.name)? != SUBLAYER_NAME
            || wide_string(sublayer.displayData.description)? != SUBLAYER_DESCRIPTION
        {
            return Err(WindowsHostError::new(
                "installed WFP sublayer differs from the D2I loopback policy",
            ));
        }
        Ok(())
    }

    enum ExpectedAddress {
        None,
        V4,
        V6,
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_filter(
        engine: &Engine,
        app_id: &AppId,
        key: GUID,
        layer: GUID,
        action: FWP_ACTION_TYPE,
        weight: u64,
        address: ExpectedAddress,
    ) -> Result<(), WindowsHostError> {
        let filter = get_filter(engine, &key)?;
        let filter = filter.as_ref();
        let expected_count = if matches!(address, ExpectedAddress::None) {
            1
        } else {
            2
        };
        let actual_weight = exact_filter_weight(&filter.weight)?;
        let effective_weight = exact_filter_weight(&filter.effectiveWeight)?;
        if filter.filterKey != key
            || filter.flags != (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_INDEXED)
            || !filter.providerKey.is_null()
            || filter.providerData.size != 0
            || !filter.providerData.data.is_null()
            || filter.layerKey != layer
            || filter.subLayerKey != SUBLAYER_KEY
            || actual_weight != weight
            || effective_weight != weight
            || filter.numFilterConditions != expected_count
            || filter.filterCondition.is_null()
            || filter.action.r#type != action
            || !filter.reserved.is_null()
        {
            return Err(WindowsHostError::new(
                "installed WFP filter metadata differs from the D2I loopback policy",
            ));
        }
        // SAFETY: the WFP allocation owns `numFilterConditions` entries.
        let conditions = unsafe {
            std::slice::from_raw_parts(filter.filterCondition, filter.numFilterConditions as usize)
        };
        verify_app_condition(&conditions[0], app_id)?;
        match address {
            ExpectedAddress::None => {}
            ExpectedAddress::V4 => verify_v4_condition(&conditions[1])?,
            ExpectedAddress::V6 => verify_v6_condition(&conditions[1])?,
        }
        Ok(())
    }

    fn exact_filter_weight(value: &FWP_VALUE0) -> Result<u64, WindowsHostError> {
        if value.r#type != FWP_UINT64 {
            return Err(WindowsHostError::new(
                "installed WFP filter weight is not an exact UINT64",
            ));
        }
        // SAFETY: the tagged union contains a uint64 pointer after the type check.
        let pointer = unsafe { value.Anonymous.uint64 };
        let pointer = NonNull::new(pointer)
            .ok_or_else(|| WindowsHostError::new("installed WFP filter weight is null"))?;
        // SAFETY: the WFP allocation owns the pointed-to uint64 value.
        Ok(unsafe { *pointer.as_ptr() })
    }

    fn verify_app_condition(
        condition: &FWPM_FILTER_CONDITION0,
        app_id: &AppId,
    ) -> Result<(), WindowsHostError> {
        if condition.fieldKey != FWPM_CONDITION_ALE_APP_ID
            || condition.matchType != FWP_MATCH_EQUAL
            || condition.conditionValue.r#type != FWP_BYTE_BLOB_TYPE
        {
            return Err(WindowsHostError::new(
                "WFP application condition metadata differs",
            ));
        }
        // SAFETY: the tagged union is a byte blob pointer after the checks above.
        let blob = unsafe { condition.conditionValue.Anonymous.byteBlob };
        let blob = NonNull::new(blob)
            .ok_or_else(|| WindowsHostError::new("WFP application condition is null"))?;
        // SAFETY: the condition owns a valid blob for the lifetime of the filter.
        let actual = unsafe { blob_bytes(blob.as_ref())? };
        if actual != app_id.bytes()? {
            return Err(WindowsHostError::new(
                "WFP application condition targets a different executable",
            ));
        }
        Ok(())
    }

    fn verify_v4_condition(condition: &FWPM_FILTER_CONDITION0) -> Result<(), WindowsHostError> {
        if condition.fieldKey != FWPM_CONDITION_IP_REMOTE_ADDRESS
            || condition.matchType != FWP_MATCH_EQUAL
            || condition.conditionValue.r#type != FWP_V4_ADDR_MASK
        {
            return Err(WindowsHostError::new(
                "WFP IPv4 loopback condition metadata differs",
            ));
        }
        // SAFETY: the tagged union is a v4 address/mask pointer.
        let value = unsafe { condition.conditionValue.Anonymous.v4AddrMask };
        let value = NonNull::new(value)
            .ok_or_else(|| WindowsHostError::new("WFP IPv4 loopback condition is null"))?;
        // SAFETY: the condition owns the address value while the filter is live.
        let value = unsafe { value.as_ref() };
        if value.addr != 0x7f00_0000 || value.mask != 0xff00_0000 {
            return Err(WindowsHostError::new(
                "WFP IPv4 loopback condition has a different range",
            ));
        }
        Ok(())
    }

    fn verify_v6_condition(condition: &FWPM_FILTER_CONDITION0) -> Result<(), WindowsHostError> {
        if condition.fieldKey != FWPM_CONDITION_IP_REMOTE_ADDRESS
            || condition.matchType != FWP_MATCH_EQUAL
            || condition.conditionValue.r#type != FWP_V6_ADDR_MASK
        {
            return Err(WindowsHostError::new(
                "WFP IPv6 loopback condition metadata differs",
            ));
        }
        // SAFETY: the tagged union is a v6 address/mask pointer.
        let value = unsafe { condition.conditionValue.Anonymous.v6AddrMask };
        let value = NonNull::new(value)
            .ok_or_else(|| WindowsHostError::new("WFP IPv6 loopback condition is null"))?;
        // SAFETY: the condition owns the address value while the filter is live.
        let value = unsafe { value.as_ref() };
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        if value.addr != expected || value.prefixLength != 128 {
            return Err(WindowsHostError::new(
                "WFP IPv6 loopback condition has a different range",
            ));
        }
        Ok(())
    }

    fn set_engine_verifier_access(
        engine: &Engine,
        verifier_sid: &str,
        present: bool,
    ) -> Result<(), WindowsHostError> {
        validate_verifier_sid(verifier_sid)?;
        let current = engine_security(engine)?;
        let matching = engine_verifier_entries(current.dacl, verifier_sid)?;
        if present && matching.len() == 1 && matching[0] == VERIFIER_ENGINE_ACCESS {
            let _ = engine_security_sddl(current.descriptor.0)?;
            return Ok(());
        }
        if present && !matching.is_empty() {
            return Err(WindowsHostError::new(format!(
                "WFP engine verifier ACE differs before installation: {matching:?}"
            )));
        }
        let sid_text = wide_text(verifier_sid);
        let mut sid = PSID::default();
        // SAFETY: the SID text is NUL-terminated and the output pointer is writable.
        unsafe { ConvertStringSidToSidW(PCWSTR(sid_text.as_ptr()), &raw mut sid) }.map_err(
            |error| WindowsHostError::new(format!("WFP verifier SID conversion failed: {error}")),
        )?;
        let sid = LocalSid(sid);
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: if present { VERIFIER_ENGINE_ACCESS } else { 0 },
            grfAccessMode: if present { SET_ACCESS } else { REVOKE_ACCESS },
            grfInheritance: Default::default(),
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: Default::default(),
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: PWSTR(sid.0 .0.cast()),
            },
        };
        let mut updated = null_mut();
        // SAFETY: the current ACL and trustee SID remain live for this call.
        let code = unsafe {
            SetEntriesInAclW(
                Some(std::slice::from_ref(&entry)),
                Some(current.dacl),
                &mut updated,
            )
        };
        check(code.0, "SetEntriesInAclW(engine verifier)")?;
        let updated = LocalAcl(updated);
        // SAFETY: the engine is live and the updated ACL remains valid for the call.
        let code = unsafe {
            FwpmEngineSetSecurityInfo0(
                engine.0,
                DACL_SECURITY_INFORMATION.0,
                None,
                None,
                Some(updated.0.cast_const()),
                None,
            )
        };
        check(code, "FwpmEngineSetSecurityInfo0")?;
        let verified = engine_security(engine)?;
        let matching = engine_verifier_entries(verified.dacl, verifier_sid)?;
        let exact = matching.len() == 1 && matching[0] == VERIFIER_ENGINE_ACCESS;
        if exact != present || (!present && !matching.is_empty()) {
            return Err(WindowsHostError::new(format!(
                "WFP engine verifier ACE postcondition failed: {matching:?}"
            )));
        }
        let _ = engine_security_sddl(verified.descriptor.0)?;
        Ok(())
    }

    fn verify_engine_security(
        engine: &Engine,
        verifier_sid: &str,
    ) -> Result<String, WindowsHostError> {
        let security = engine_security(engine)?;
        let matching = engine_verifier_entries(security.dacl, verifier_sid)?;
        if matching.as_slice() != [VERIFIER_ENGINE_ACCESS] {
            return Err(WindowsHostError::new(format!(
                "WFP engine verifier ACE differs: observed={matching:?}, \
                 expected=[{VERIFIER_ENGINE_ACCESS}]"
            )));
        }
        engine_security_sddl(security.descriptor.0)
    }

    struct EngineSecurity {
        descriptor: WfpSecurityDescriptor,
        dacl: *mut ACL,
    }

    fn engine_security(engine: &Engine) -> Result<EngineSecurity, WindowsHostError> {
        let mut dacl = null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: output pointers are writable and the engine handle is live.
        let code = unsafe {
            FwpmEngineGetSecurityInfo0(
                engine.0,
                DACL_SECURITY_INFORMATION.0,
                null_mut(),
                null_mut(),
                &raw mut dacl,
                null_mut(),
                &raw mut descriptor,
            )
        };
        check(code, "FwpmEngineGetSecurityInfo0")?;
        if dacl.is_null() || descriptor.0.is_null() {
            return Err(WindowsHostError::new(
                "WFP engine security descriptor or DACL is null",
            ));
        }
        Ok(EngineSecurity {
            descriptor: WfpSecurityDescriptor(descriptor),
            dacl,
        })
    }

    fn engine_verifier_entries(
        dacl: *const ACL,
        verifier_sid: &str,
    ) -> Result<Vec<u32>, WindowsHostError> {
        let mut count = 0_u32;
        let mut entries = null_mut();
        // SAFETY: the DACL is live and output pointers are writable.
        let code = unsafe { GetExplicitEntriesFromAclW(dacl, &raw mut count, &raw mut entries) };
        check(code.0, "GetExplicitEntriesFromAclW(engine)")?;
        if count > 4_096 || (count > 0 && entries.is_null()) {
            return Err(WindowsHostError::new(
                "WFP engine ACL entry count or pointer is invalid",
            ));
        }
        let entries_guard = LocalExplicitEntries(entries);
        // SAFETY: the API returned `count` entries in the allocated array.
        let entries = unsafe { std::slice::from_raw_parts(entries_guard.0, count as usize) };
        let mut matching = Vec::new();
        for entry in entries {
            if entry.Trustee.TrusteeForm != TRUSTEE_IS_SID || entry.Trustee.ptstrName.is_null() {
                continue;
            }
            let sid = PSID(entry.Trustee.ptstrName.0.cast());
            if sid_string(sid)? == verifier_sid {
                if entry.grfAccessMode != GRANT_ACCESS || entry.grfInheritance.0 != 0 {
                    return Err(WindowsHostError::new(
                        "WFP engine verifier entry is not a non-inherited allow ACE",
                    ));
                }
                matching.push(entry.grfAccessPermissions);
            }
        }
        matching.sort_unstable();
        Ok(matching)
    }

    fn engine_security_sddl(descriptor: PSECURITY_DESCRIPTOR) -> Result<String, WindowsHostError> {
        let mut value = PWSTR::null();
        // SAFETY: the descriptor is live and the output pointer is writable.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &raw mut value,
                None,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!(
                "WFP engine security descriptor conversion failed: {error}"
            ))
        })?;
        let result = wide_string(value);
        if !value.is_null() {
            // SAFETY: the conversion API allocates the returned string with LocalAlloc.
            let _ = unsafe { LocalFree(Some(HLOCAL(value.0.cast()))) };
        }
        result
    }

    fn validate_verifier_sid(verifier_sid: &str) -> Result<(), WindowsHostError> {
        if verifier_sid.len() > 256
            || !verifier_sid.starts_with("S-1-15-2-")
            || verifier_sid
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && byte != b'-' && byte != b'S')
        {
            return Err(WindowsHostError::new(
                "WFP verifier SID must be an exact AppContainer profile SID",
            ));
        }
        Ok(())
    }

    fn object_security_descriptor(
        verifier_sid: &str,
        owner_sid: &str,
    ) -> Result<SecurityDescriptor, WindowsHostError> {
        validate_verifier_sid(verifier_sid)?;
        if owner_sid.len() > 256
            || !owner_sid.starts_with("S-1-")
            || owner_sid
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && byte != b'-' && byte != b'S')
        {
            return Err(WindowsHostError::new("WFP policy owner SID is invalid"));
        }
        let sddl = format!(
            "O:{owner_sid}G:{owner_sid}D:P(A;;0x{ADMIN_OBJECT_ACCESS:08x};;;SY)\
             (A;;0x{ADMIN_OBJECT_ACCESS:08x};;;BA)\
             (A;;0x{VERIFIER_OBJECT_ACCESS:08x};;;{verifier_sid})"
        );
        let wide = wide_text(&sddl);
        let mut value = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the SDDL is NUL-terminated and the output pointer is writable.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut value,
                None,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!(
                "WFP security descriptor conversion failed: {error}"
            ))
        })?;
        Ok(SecurityDescriptor { value, sddl })
    }

    fn verify_provider_security(
        engine: &Engine,
        verifier_sid: &str,
        owner_sid: &str,
    ) -> Result<(), WindowsHostError> {
        let mut owner = PSID::default();
        let mut group = PSID::default();
        let mut dacl = null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let information =
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        // SAFETY: all output pointers are writable and the fixed key is valid.
        let code = unsafe {
            FwpmProviderGetSecurityInfoByKey0(
                engine.0,
                Some(&PROVIDER_KEY),
                information.0,
                &raw mut owner,
                &raw mut group,
                &raw mut dacl,
                null_mut(),
                &raw mut descriptor,
            )
        };
        check(code, "FwpmProviderGetSecurityInfoByKey0")?;
        let descriptor = WfpSecurityDescriptor(descriptor);
        verify_object_security(owner, group, dacl, descriptor.0, verifier_sid, owner_sid)
    }

    fn verify_sublayer_security(
        engine: &Engine,
        verifier_sid: &str,
        owner_sid: &str,
    ) -> Result<(), WindowsHostError> {
        let mut owner = PSID::default();
        let mut group = PSID::default();
        let mut dacl = null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let information =
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        // SAFETY: all output pointers are writable and the fixed key is valid.
        let code = unsafe {
            FwpmSubLayerGetSecurityInfoByKey0(
                engine.0,
                Some(&SUBLAYER_KEY),
                information.0,
                &raw mut owner,
                &raw mut group,
                &raw mut dacl,
                null_mut(),
                &raw mut descriptor,
            )
        };
        check(code, "FwpmSubLayerGetSecurityInfoByKey0")?;
        let descriptor = WfpSecurityDescriptor(descriptor);
        verify_object_security(owner, group, dacl, descriptor.0, verifier_sid, owner_sid)
    }

    fn verify_filter_security(
        engine: &Engine,
        key: &GUID,
        verifier_sid: &str,
        owner_sid: &str,
    ) -> Result<(), WindowsHostError> {
        let mut owner = PSID::default();
        let mut group = PSID::default();
        let mut dacl = null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let information =
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        // SAFETY: all output pointers are writable and the key is valid.
        let code = unsafe {
            FwpmFilterGetSecurityInfoByKey0(
                engine.0,
                Some(key),
                information.0,
                &raw mut owner,
                &raw mut group,
                &raw mut dacl,
                null_mut(),
                &raw mut descriptor,
            )
        };
        check(code, "FwpmFilterGetSecurityInfoByKey0")?;
        let descriptor = WfpSecurityDescriptor(descriptor);
        verify_object_security(owner, group, dacl, descriptor.0, verifier_sid, owner_sid)
    }

    fn verify_object_security(
        owner: PSID,
        group: PSID,
        dacl: *mut ACL,
        descriptor: PSECURITY_DESCRIPTOR,
        verifier_sid: &str,
        owner_sid: &str,
    ) -> Result<(), WindowsHostError> {
        if owner.is_invalid()
            || group.is_invalid()
            || dacl.is_null()
            || descriptor.0.is_null()
            || sid_string(owner)? != owner_sid
            || sid_string(group)? != owner_sid
        {
            return Err(WindowsHostError::new(
                "WFP object owner, group, or DACL differs from the protected contract",
            ));
        }
        let mut control = Default::default();
        let mut revision = 0_u32;
        // SAFETY: descriptor is the live self-relative WFP security descriptor.
        unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) }
            .map_err(|error| {
                WindowsHostError::new(format!("GetSecurityDescriptorControl failed: {error}"))
            })?;
        if revision == 0 || control & SE_DACL_PROTECTED.0 == 0 {
            return Err(WindowsHostError::new(
                "WFP object DACL is not explicitly protected",
            ));
        }
        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: dacl is live and information has the documented size.
        unsafe {
            GetAclInformation(
                dacl,
                (&raw mut information).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .map_err(|error| WindowsHostError::new(format!("GetAclInformation failed: {error}")))?;
        if information.AceCount != 3 {
            return Err(WindowsHostError::new(
                "WFP object DACL must contain exactly three allow entries",
            ));
        }
        let mut entries = std::collections::BTreeMap::new();
        for index in 0..information.AceCount {
            let mut pointer = null_mut();
            // SAFETY: index is bounded by the queried ACE count.
            unsafe { GetAce(dacl, index, &raw mut pointer) }.map_err(|error| {
                WindowsHostError::new(format!("GetAce({index}) failed: {error}"))
            })?;
            if pointer.is_null() {
                return Err(WindowsHostError::new("WFP object DACL ACE is null"));
            }
            // SAFETY: the DACL owns a complete ACE at this pointer.
            let ace = unsafe { &*(pointer.cast::<ACCESS_ALLOWED_ACE>()) };
            if ace.Header.AceType != 0
                || ace.Header.AceFlags != 0
                || usize::from(ace.Header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(WindowsHostError::new(
                    "WFP object DACL contains a non-exact allow ACE",
                ));
            }
            let sid = PSID((&raw const ace.SidStart).cast_mut().cast());
            let sid = sid_string(sid)?;
            if entries.insert(sid, ace.Mask).is_some() {
                return Err(WindowsHostError::new(
                    "WFP object DACL contains a duplicate SID",
                ));
            }
        }
        let expected = std::collections::BTreeMap::from([
            ("S-1-5-18".to_owned(), ADMIN_OBJECT_ACCESS),
            ("S-1-5-32-544".to_owned(), ADMIN_OBJECT_ACCESS),
            (verifier_sid.to_owned(), VERIFIER_OBJECT_ACCESS),
        ]);
        if entries != expected {
            return Err(WindowsHostError::new(format!(
                "WFP object DACL grants a different SID or access mask: \
                     observed={entries:?}, expected={expected:?}"
            )));
        }
        Ok(())
    }

    fn sid_string(sid: PSID) -> Result<String, WindowsHostError> {
        let mut value = PWSTR::null();
        // SAFETY: sid is a live SID owned by the WFP security descriptor.
        unsafe { ConvertSidToStringSidW(sid, &raw mut value) }.map_err(|error| {
            WindowsHostError::new(format!("ConvertSidToStringSidW failed: {error}"))
        })?;
        let result = wide_string(value);
        if !value.is_null() {
            // SAFETY: ConvertSidToStringSidW allocates with LocalAlloc.
            let _ = unsafe { LocalFree(Some(HLOCAL(value.0.cast()))) };
        }
        result
    }

    fn get_provider(engine: &Engine) -> Result<WfpMemory<FWPM_PROVIDER0>, WindowsHostError> {
        let mut pointer = null_mut();
        // SAFETY: the engine, key, and writable output pointer are valid.
        let code = unsafe { FwpmProviderGetByKey0(engine.0, &PROVIDER_KEY, &mut pointer) };
        check(code, "FwpmProviderGetByKey0")?;
        WfpMemory::new(pointer, "FwpmProviderGetByKey0")
    }

    fn get_sublayer(engine: &Engine) -> Result<WfpMemory<FWPM_SUBLAYER0>, WindowsHostError> {
        let mut pointer = null_mut();
        // SAFETY: the engine, key, and writable output pointer are valid.
        let code = unsafe { FwpmSubLayerGetByKey0(engine.0, &SUBLAYER_KEY, &mut pointer) };
        check(code, "FwpmSubLayerGetByKey0")?;
        WfpMemory::new(pointer, "FwpmSubLayerGetByKey0")
    }

    fn get_filter(
        engine: &Engine,
        key: &GUID,
    ) -> Result<WfpMemory<FWPM_FILTER0>, WindowsHostError> {
        let mut pointer = null_mut();
        // SAFETY: the engine, key, and writable output pointer are valid.
        let code = unsafe { FwpmFilterGetByKey0(engine.0, key, &mut pointer) };
        check(code, "FwpmFilterGetByKey0")?;
        WfpMemory::new(pointer, "FwpmFilterGetByKey0")
    }

    fn blob_bytes(blob: &FWP_BYTE_BLOB) -> Result<&[u8], WindowsHostError> {
        if blob.size == 0 || blob.size as usize > 64 * 1024 || blob.data.is_null() {
            return Err(WindowsHostError::new(
                "WFP application ID blob is empty, null, or oversized",
            ));
        }
        // SAFETY: WFP reports a non-null buffer of exactly `size` bytes.
        Ok(unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) })
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn wide_text(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_string(value: PWSTR) -> Result<String, WindowsHostError> {
        if value.is_null() {
            return Err(WindowsHostError::new("WFP display string is null"));
        }
        let mut length = 0_usize;
        // SAFETY: WFP display strings are NUL-terminated. The explicit bound
        // prevents unbounded scans if an object is corrupt.
        unsafe {
            while length < 4096 && *value.0.add(length) != 0 {
                length += 1;
            }
            if length == 4096 {
                return Err(WindowsHostError::new(
                    "WFP display string exceeds 4096 UTF-16 units",
                ));
            }
            String::from_utf16(std::slice::from_raw_parts(value.0, length)).map_err(|error| {
                WindowsHostError::new(format!("invalid WFP display UTF-16: {error}"))
            })
        }
    }

    fn check(code: u32, operation: &str) -> Result<(), WindowsHostError> {
        if code == 0 {
            return Ok(());
        }
        let hint = if code == ERROR_ACCESS_DENIED.0 {
            "; run the WFP installation command from an elevated deployment session"
        } else {
            ""
        };
        Err(WindowsHostError::new(format!(
            "{operation} failed with Windows/WFP code 0x{code:08x}{hint}"
        )))
    }

    fn check_missing(code: u32, missing: u32, operation: &str) -> Result<(), WindowsHostError> {
        if code == missing {
            Ok(())
        } else {
            check(code, operation)
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{WindowsHostError, WindowsWfpLoopbackPolicyIdentity};
    use std::path::Path;

    pub(super) fn install(
        _application: &Path,
        _verifier_sid: &str,
        _owner_sid: &str,
    ) -> Result<WindowsWfpLoopbackPolicyIdentity, WindowsHostError> {
        unavailable()
    }

    pub(super) fn verify(
        _application: &Path,
        _verifier_sid: &str,
        _owner_sid: &str,
    ) -> Result<WindowsWfpLoopbackPolicyIdentity, WindowsHostError> {
        unavailable()
    }

    pub(super) fn remove(_verifier_sid: &str) -> Result<(), WindowsHostError> {
        unavailable()
    }

    fn unavailable<T>() -> Result<T, WindowsHostError> {
        Err(WindowsHostError::new(
            "Windows Filtering Platform is unavailable on this platform",
        ))
    }
}

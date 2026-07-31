use crate::adapter::{outcome, validate_operation_payload};
use crate::windows_observation::{
    ObservationAdapterResult, ObservationLimits, ReadOnlyObservationRequest,
    WindowsUiaObservationTarget, WindowsWebObservationTarget,
};
use crate::windows_worker::{verify_browser_egress_with_approved_relay, IsolatedWindowsWorker};
use crate::{
    ActivatedWindowsBinding, AdapterExecution, DesktopActionIntent, DesktopAdapter,
    DesktopAdapterDescriptor, DesktopError, ExecutionPermit, PreparedAction,
    SignedWindowsWfpFunctionalAttestationV2, WfpReceiptReplayLedger, WindowsAdapterConfiguration,
    WindowsAdapterKind,
};
use std::collections::BTreeMap;

struct WindowsWorkerAdapter {
    descriptor: DesktopAdapterDescriptor,
    configuration: WindowsAdapterConfiguration,
    integration_id: String,
    binding_id: String,
    activation_record_hash: String,
    observed_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    wfp_functional_attestation: Option<SignedWindowsWfpFunctionalAttestationV2>,
    receipt_replay: WfpReceiptReplayLedger,
    worker: IsolatedWindowsWorker,
}

impl WindowsWorkerAdapter {
    pub(crate) fn worker_process_id(&self) -> u32 {
        self.worker.process_id()
    }

    fn bind(
        activation: ActivatedWindowsBinding,
        configuration: WindowsAdapterConfiguration,
        expected_kind: WindowsAdapterKind,
        now_unix_seconds: u64,
    ) -> Result<Self, DesktopError> {
        configuration.validate()?;
        if !cfg!(windows) {
            return Err(DesktopError::AdapterUnavailable(
                "Windows adapters are unavailable on this platform".to_owned(),
            ));
        }
        if activation.adapter_kind != expected_kind || configuration.adapter_kind != expected_kind {
            return Err(DesktopError::Integrity(
                "Windows activation, configuration, and adapter kinds differ".to_owned(),
            ));
        }
        if now_unix_seconds < activation.observed_at_unix_seconds
            || now_unix_seconds >= activation.expires_at_unix_seconds
        {
            return Err(DesktopError::AdapterUnavailable(
                "Windows activation is outside its certified lifetime".to_owned(),
            ));
        }
        if configuration.configuration_hash()? != activation.configuration_hash {
            return Err(DesktopError::Integrity(
                "Windows adapter configuration differs from its certified hash".to_owned(),
            ));
        }
        let mut receipt_replay = WfpReceiptReplayLedger::default();
        let descriptor = configuration.descriptor()?;
        if descriptor != activation.adapter_descriptor {
            return Err(DesktopError::Integrity(
                "Windows adapter descriptor differs from its certified descriptor".to_owned(),
            ));
        }
        let worker = IsolatedWindowsWorker::start(configuration.clone())?;
        if expected_kind == WindowsAdapterKind::WebDriver {
            let _ = verify_browser_egress_with_approved_relay(
                &configuration,
                activation.wfp_functional_attestation.as_ref(),
                now_unix_seconds,
            )?;
        } else {
            let host = crate::current_windows_host_binding()?;
            let _ = crate::windows_egress::verify_configured_windows_browser_egress(
                &configuration,
                &host,
                activation.wfp_functional_attestation.as_ref(),
                &mut receipt_replay,
                now_unix_seconds,
            )?;
        }
        Ok(Self {
            descriptor,
            configuration,
            integration_id: activation.integration_id,
            binding_id: activation.binding_id,
            activation_record_hash: activation.activation_record_hash,
            observed_at_unix_seconds: activation.observed_at_unix_seconds,
            expires_at_unix_seconds: activation.expires_at_unix_seconds,
            wfp_functional_attestation: activation.wfp_functional_attestation,
            receipt_replay,
            worker,
        })
    }

    fn validate_lifetime(&self, now_unix_ms: u64) -> Result<(), DesktopError> {
        let now_unix_seconds = now_unix_ms / 1_000;
        if now_unix_seconds < self.observed_at_unix_seconds
            || now_unix_seconds >= self.expires_at_unix_seconds
        {
            return Err(DesktopError::AdapterUnavailable(
                "Windows adapter certification is outside its valid lifetime".to_owned(),
            ));
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        intent: &DesktopActionIntent,
        now_unix_ms: u64,
    ) -> Result<PreparedAction, DesktopError> {
        self.validate_lifetime(now_unix_ms)?;
        self.verify_live_egress(now_unix_ms / 1_000)?;
        intent.validate()?;
        if !self
            .descriptor
            .capabilities
            .contains(&intent.operation.capability())
        {
            return Err(DesktopError::AdapterUnavailable(
                "Windows adapter capability mismatch".to_owned(),
            ));
        }
        let precondition_hash = self.worker.snapshot(&intent.operation)?;
        PreparedAction::create(intent, &self.descriptor, precondition_hash, now_unix_ms)
    }

    fn trusted_resolution_snapshot(
        &mut self,
        operation: &crate::DesktopOperation,
        now_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        self.validate_lifetime(now_unix_ms)?;
        self.verify_live_egress(now_unix_ms / 1_000)?;
        if !self
            .descriptor
            .capabilities
            .contains(&operation.capability())
        {
            return Err(DesktopError::AdapterUnavailable(
                "Windows adapter capability mismatch during trusted resolution".to_owned(),
            ));
        }
        self.worker.snapshot(operation)
    }

    fn execute(
        &mut self,
        intent: &DesktopActionIntent,
        prepared: &PreparedAction,
        permit: &ExecutionPermit,
        payload: Option<&[u8]>,
        now_unix_ms: u64,
    ) -> Result<AdapterExecution, DesktopError> {
        self.validate_lifetime(now_unix_ms)?;
        self.verify_live_egress(now_unix_ms / 1_000)?;
        intent.validate()?;
        if !self
            .descriptor
            .capabilities
            .contains(&intent.operation.capability())
        {
            return Err(DesktopError::AdapterUnavailable(
                "Windows adapter capability mismatch".to_owned(),
            ));
        }
        validate_operation_payload(&intent.operation, payload)?;
        let action_hash = intent.action_hash()?;
        permit.validate_binding(&action_hash, prepared, now_unix_ms)?;
        let output = self
            .worker
            .commit(&intent.operation, &prepared.precondition_hash, payload)?;
        outcome(
            action_hash,
            &self.descriptor,
            output,
            now_unix_ms,
            "certified isolated Windows action completed",
        )
    }

    fn descriptor(&self) -> &DesktopAdapterDescriptor {
        &self.descriptor
    }

    fn verify_live_egress(&mut self, now_unix_seconds: u64) -> Result<(), DesktopError> {
        let host = crate::current_windows_host_binding()?;
        let _ = crate::windows_egress::verify_configured_windows_browser_egress(
            &self.configuration,
            &host,
            self.wfp_functional_attestation.as_ref(),
            &mut self.receipt_replay,
            now_unix_seconds,
        )?;
        Ok(())
    }

    fn observe_read_only(
        &mut self,
        request: &ReadOnlyObservationRequest,
        now_unix_seconds: u64,
    ) -> Result<ObservationAdapterResult, DesktopError> {
        self.validate_lifetime(now_unix_seconds.saturating_mul(1_000))?;
        request.validate()?;
        let configuration_hash = self.configuration.configuration_hash()?;
        if request.runtime_binding_digest() != configuration_hash {
            return Err(DesktopError::Integrity(
                "observation runtime binding digest differs from the activated configuration"
                    .to_owned(),
            ));
        }
        self.validate_observation_request(request)?;
        let before = verify_browser_egress_with_approved_relay(
            &self.configuration,
            self.wfp_functional_attestation.as_ref(),
            now_unix_seconds,
        )?;
        let payload = self.worker.observe(request)?;
        let after = verify_browser_egress_with_approved_relay(
            &self.configuration,
            self.wfp_functional_attestation.as_ref(),
            now_unix_seconds,
        )?;
        let stable_target_binding =
            self.stable_observation_binding(request, &configuration_hash)?;
        Ok(ObservationAdapterResult {
            payload,
            stable_target_binding,
            before_egress_receipt_hash: before
                .as_ref()
                .map(crate::SignedWfpVerificationReceipt::receipt_hash)
                .transpose()?,
            after_egress_receipt_hash: after
                .as_ref()
                .map(crate::SignedWfpVerificationReceipt::receipt_hash)
                .transpose()?,
        })
    }

    fn validate_observation_request(
        &self,
        request: &ReadOnlyObservationRequest,
    ) -> Result<(), DesktopError> {
        let host = crate::current_windows_host_binding()?;
        match request {
            ReadOnlyObservationRequest::Uia { target, limits } => {
                if self.configuration.adapter_kind != WindowsAdapterKind::UiAutomation
                    || target.session_id != host.session_id
                    || !self
                        .configuration
                        .ui_allowed_executable_hashes
                        .contains(&target.executable_hash)
                    || limits.max_observation_duration_ms > self.configuration.request_timeout_ms
                {
                    return Err(DesktopError::AccessDenied(
                        "UIA observation target is outside its activated binding".to_owned(),
                    ));
                }
            }
            ReadOnlyObservationRequest::WebDriver { target, limits } => {
                if self.configuration.adapter_kind != WindowsAdapterKind::WebDriver
                    || !self
                        .configuration
                        .browser_session_ids
                        .contains(&target.browser_session_id)
                    || !self
                        .configuration
                        .browser_allowed_origins
                        .contains(&target.expected_origin)
                    || limits.max_observation_duration_ms > self.configuration.request_timeout_ms
                {
                    return Err(DesktopError::AccessDenied(
                        "Web observation target is outside its activated binding".to_owned(),
                    ));
                }
                let policy = self
                    .configuration
                    .browser_egress_policy
                    .as_ref()
                    .ok_or_else(|| {
                        DesktopError::AccessDenied(
                            "Web observation requires concrete WFP policy binding".to_owned(),
                        )
                    })?;
                if policy.verifier_broker.is_none()
                    || policy.browser_executable != target.edge_driver_pin.browser_executable
                    || policy.browser_executable_hash
                        != target.edge_driver_pin.browser_executable_hash
                {
                    return Err(DesktopError::Integrity(
                        "Web observation Edge pin differs from WFP policy".to_owned(),
                    ));
                }
                let attestation = self.wfp_functional_attestation.as_ref().ok_or_else(|| {
                    DesktopError::AccessDenied(
                        "Web observation requires functional WFP attestation".to_owned(),
                    )
                })?;
                if attestation.runtime_binding_digest != target.runtime_binding_digest
                    || attestation.machine_binding != host
                    || attestation.browser_executable_hash
                        != target.edge_driver_pin.browser_executable_hash
                    || attestation.driver_executable_hash
                        != target.edge_driver_pin.driver_executable_hash
                    || attestation.edge_driver_pin_hash
                        != crate::hash_value(&target.edge_driver_pin)?
                    || !attestation
                        .browser_session_ids
                        .contains(&target.browser_session_id)
                    || !attestation
                        .allowed_origins
                        .contains(&target.expected_origin)
                    || !attestation.deny_by_default
                {
                    return Err(DesktopError::Integrity(
                        "Web observation target differs from functional WFP attestation".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn stable_observation_binding(
        &self,
        request: &ReadOnlyObservationRequest,
        configuration_hash: &str,
    ) -> Result<BTreeMap<String, String>, DesktopError> {
        let mut binding = BTreeMap::from([
            ("integration_id".to_owned(), self.integration_id.clone()),
            ("binding_id".to_owned(), self.binding_id.clone()),
            (
                "activation_record_hash".to_owned(),
                self.activation_record_hash.clone(),
            ),
            (
                "runtime_binding_digest".to_owned(),
                configuration_hash.to_owned(),
            ),
        ]);
        match request {
            ReadOnlyObservationRequest::Uia { target, .. } => {
                binding.extend([
                    ("source_kind".to_owned(), "uia".to_owned()),
                    ("process_id".to_owned(), target.process_id.to_string()),
                    ("executable_path".to_owned(), target.executable_path.clone()),
                    ("executable_hash".to_owned(), target.executable_hash.clone()),
                    (
                        "window_title_hash".to_owned(),
                        target.window_title_hash.clone(),
                    ),
                    ("session_id".to_owned(), target.session_id.to_string()),
                ]);
            }
            ReadOnlyObservationRequest::WebDriver { target, .. } => {
                let policy = self
                    .configuration
                    .browser_egress_policy
                    .as_ref()
                    .ok_or_else(|| {
                        DesktopError::Integrity("Web observation WFP policy is absent".to_owned())
                    })?;
                let attestation = self.wfp_functional_attestation.as_ref().ok_or_else(|| {
                    DesktopError::Integrity(
                        "Web observation functional attestation is absent".to_owned(),
                    )
                })?;
                binding.extend([
                    ("source_kind".to_owned(), "web_driver".to_owned()),
                    (
                        "browser_session_id".to_owned(),
                        target.browser_session_id.clone(),
                    ),
                    ("expected_origin".to_owned(), target.expected_origin.clone()),
                    (
                        "edge_version".to_owned(),
                        target.edge_driver_pin.browser_version.clone(),
                    ),
                    (
                        "edge_executable_hash".to_owned(),
                        target.edge_driver_pin.browser_executable_hash.clone(),
                    ),
                    (
                        "edge_driver_version".to_owned(),
                        target.edge_driver_pin.driver_version.clone(),
                    ),
                    (
                        "edge_driver_executable_hash".to_owned(),
                        target.edge_driver_pin.driver_executable_hash.clone(),
                    ),
                    ("wfp_policy_hash".to_owned(), policy.policy_hash()?),
                    (
                        "wfp_attestation_hash".to_owned(),
                        attestation.attestation_hash()?,
                    ),
                    (
                        "functional_report_hash".to_owned(),
                        attestation.self_test_report_hash.clone(),
                    ),
                ]);
            }
        }
        Ok(binding)
    }

    fn integration_id(&self) -> &str {
        &self.integration_id
    }

    fn binding_id(&self) -> &str {
        &self.binding_id
    }

    fn activation_record_hash(&self) -> &str {
        &self.activation_record_hash
    }

    fn configuration(&self) -> &WindowsAdapterConfiguration {
        &self.configuration
    }
}

macro_rules! windows_adapter {
    ($name:ident, $kind:expr) => {
        /// Certified, process-isolated Windows capability adapter.
        pub struct $name {
            inner: WindowsWorkerAdapter,
        }

        impl $name {
            /// Consumes one activated binding and starts its hash-pinned worker.
            pub fn bind(
                activation: ActivatedWindowsBinding,
                configuration: WindowsAdapterConfiguration,
                now_unix_seconds: u64,
            ) -> Result<Self, DesktopError> {
                Ok(Self {
                    inner: WindowsWorkerAdapter::bind(
                        activation,
                        configuration,
                        $kind,
                        now_unix_seconds,
                    )?,
                })
            }

            /// Returns the reviewed integration identity.
            pub fn integration_id(&self) -> &str {
                self.inner.integration_id()
            }

            /// Returns the certified runtime binding identity.
            pub fn binding_id(&self) -> &str {
                self.inner.binding_id()
            }

            /// Returns the durable replay-guard record hash.
            pub fn activation_record_hash(&self) -> &str {
                self.inner.activation_record_hash()
            }

            /// Returns the exact configuration used to launch the worker.
            pub fn configuration(&self) -> &WindowsAdapterConfiguration {
                self.inner.configuration()
            }
        }

        impl DesktopAdapter for $name {
            fn descriptor(&self) -> &DesktopAdapterDescriptor {
                self.inner.descriptor()
            }

            fn prepare(
                &mut self,
                intent: &DesktopActionIntent,
                now_unix_ms: u64,
            ) -> Result<PreparedAction, DesktopError> {
                self.inner.prepare(intent, now_unix_ms)
            }

            fn execute(
                &mut self,
                intent: &DesktopActionIntent,
                prepared: &PreparedAction,
                permit: &ExecutionPermit,
                payload: Option<&[u8]>,
                now_unix_ms: u64,
            ) -> Result<AdapterExecution, DesktopError> {
                self.inner
                    .execute(intent, prepared, permit, payload, now_unix_ms)
            }
        }
    };
}

windows_adapter!(WindowsUiAutomationAdapter, WindowsAdapterKind::UiAutomation);
windows_adapter!(WindowsWebDriverAdapter, WindowsAdapterKind::WebDriver);
windows_adapter!(WindowsFileWriteAdapter, WindowsAdapterKind::FileWrite);
windows_adapter!(WindowsProcessAdapter, WindowsAdapterKind::Process);

impl WindowsUiAutomationAdapter {
    pub(crate) fn worker_process_id(&self) -> u32 {
        self.inner.worker_process_id()
    }

    pub(crate) fn trusted_resolution_snapshot(
        &mut self,
        operation: &crate::DesktopOperation,
        now_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        self.inner
            .trusted_resolution_snapshot(operation, now_unix_ms)
    }

    pub(crate) fn validate_uia_observation_target(
        &self,
        target: &WindowsUiaObservationTarget,
        limits: &ObservationLimits,
    ) -> Result<(), DesktopError> {
        self.inner
            .validate_observation_request(&ReadOnlyObservationRequest::Uia {
                target: target.clone(),
                limits: limits.clone(),
            })
    }

    pub(crate) fn observe_read_only(
        &mut self,
        request: &ReadOnlyObservationRequest,
        now_unix_seconds: u64,
    ) -> Result<ObservationAdapterResult, DesktopError> {
        self.inner.observe_read_only(request, now_unix_seconds)
    }
}

impl WindowsWebDriverAdapter {
    pub(crate) fn worker_process_id(&self) -> u32 {
        self.inner.worker_process_id()
    }

    pub(crate) fn trusted_resolution_snapshot(
        &mut self,
        operation: &crate::DesktopOperation,
        now_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        self.inner
            .trusted_resolution_snapshot(operation, now_unix_ms)
    }

    pub(crate) fn validate_web_observation_target(
        &self,
        target: &WindowsWebObservationTarget,
        limits: &ObservationLimits,
    ) -> Result<(), DesktopError> {
        self.inner
            .validate_observation_request(&ReadOnlyObservationRequest::WebDriver {
                target: target.clone(),
                limits: limits.clone(),
            })
    }

    pub(crate) fn observe_read_only(
        &mut self,
        request: &ReadOnlyObservationRequest,
        now_unix_seconds: u64,
    ) -> Result<ObservationAdapterResult, DesktopError> {
        self.inner.observe_read_only(request, now_unix_seconds)
    }
}

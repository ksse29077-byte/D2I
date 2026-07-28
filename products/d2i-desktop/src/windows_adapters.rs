use crate::adapter::{outcome, validate_operation_payload};
use crate::windows_worker::IsolatedWindowsWorker;
use crate::{
    ActivatedWindowsBinding, AdapterExecution, DesktopActionIntent, DesktopAdapter,
    DesktopAdapterDescriptor, DesktopError, ExecutionPermit, PreparedAction,
    WindowsAdapterConfiguration, WindowsAdapterKind,
};

struct WindowsWorkerAdapter {
    descriptor: DesktopAdapterDescriptor,
    configuration: WindowsAdapterConfiguration,
    integration_id: String,
    binding_id: String,
    activation_record_hash: String,
    observed_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    worker: IsolatedWindowsWorker,
}

impl WindowsWorkerAdapter {
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
        crate::windows_egress::verify_configured_windows_browser_egress(&configuration)?;
        let descriptor = configuration.descriptor()?;
        if descriptor != activation.adapter_descriptor {
            return Err(DesktopError::Integrity(
                "Windows adapter descriptor differs from its certified descriptor".to_owned(),
            ));
        }
        let worker = IsolatedWindowsWorker::start(configuration.clone())?;
        Ok(Self {
            descriptor,
            configuration,
            integration_id: activation.integration_id,
            binding_id: activation.binding_id,
            activation_record_hash: activation.activation_record_hash,
            observed_at_unix_seconds: activation.observed_at_unix_seconds,
            expires_at_unix_seconds: activation.expires_at_unix_seconds,
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
        crate::windows_egress::verify_configured_windows_browser_egress(&self.configuration)?;
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

    fn execute(
        &mut self,
        intent: &DesktopActionIntent,
        prepared: &PreparedAction,
        permit: &ExecutionPermit,
        payload: Option<&[u8]>,
        now_unix_ms: u64,
    ) -> Result<AdapterExecution, DesktopError> {
        self.validate_lifetime(now_unix_ms)?;
        crate::windows_egress::verify_configured_windows_browser_egress(&self.configuration)?;
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

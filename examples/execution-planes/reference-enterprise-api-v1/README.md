# Reference Enterprise API Connector

This fixture represents a generic internal work-order API. ERP, MES, and CMMS
labels appear only as cross-domain examples; Core interprets none of them.

The Completion runner creates a new signed Connector Pack, approval, exact
ephemeral loopback endpoint binding, network policy, and opaque credential
reference for every run. The runtime-generated synthetic secret is passed only
through inherited process handles to the reference server and connector worker
and is never written here.

Cross-domain deterministic compatibility fixtures use opaque metadata:

| Fixture | System family | Resource class | Operation |
| --- | --- | --- | --- |
| General office | reference-enterprise | work_order | update-work-order-status |
| Finance | finance-reference | ledger_record | update-approved-record |
| IT service | it-service-reference | service_ticket | update-ticket-status |
| Safety | safety-reference | safety_record | update-record-status |
| ERP metadata | erp-reference | opaque_resource | update-approved-state |
| MES metadata | mes-reference | opaque_resource | update-approved-state |
| CMMS metadata | cmms-reference | opaque_resource | update-approved-state |

# General Office Enterprise API Role Fixture

Role Contract version 1.5.0 authorizes only the opaque
`reference-enterprise-api` integration, `enterprise_api.read`,
`enterprise_api.write`, and the `work_order.status` semantic target. It does
not contain an origin, port, HTTP method, request body, or credential.

The separately signed Connector Pack and endpoint binding supply transport
details. Every mutation still requires current Role and Case evidence, Policy
Admission, a one-shot Enterprise activation, KRN dispatch, and a fresh API
observation. Authentication failure, untrusted operation instructions, and
malformed responses terminate in Human-by-Exception without another action.

# D2I Embodied Intelligence RFC

## Status

Phase 9 establishes a separate Rust product under `products/d2i-embodied`.
It does not add robot control to the compiler or reference runtime.

## Responsibility Boundary

```text
ROS 2 sensor bytes
  -> typed SensorEvent
  -> D2I cognition / planning / memory
  -> high-level ActionIntent
  -> external SafetyController assessment
  -> permit-bound HardwarePort dispatch
  -> external motor / actuator controller
```

D2I may produce an intent. It cannot issue raw motor commands, implement an
emergency loop, or bypass safety assessment. `safety_loop` deadlines are valid
for sensor classification but rejected for D2I action planning.

## Contracts

### Sensor Event

`schemas/embodied/sensor-event.schema.json` defines a bounded event with robot,
sequence, timestamp, frame, sensor kind, deadline class, quality, labels, and a
SHA-256-bound payload. Unknown fields are rejected.

### Action Intent

`schemas/embodied/action-intent.schema.json` defines a package-bound,
evidence-bound high-level intention with an expiration, deadline class, action
kind, parameters, and explicit hard or advisory safety constraints. It is not a
hardware command.

Deadline classes are:

| Class | Maximum intent lifetime | D2I planning |
| --- | ---: | --- |
| `safety_loop` | 20 ms | prohibited |
| `control` | 100 ms | allowed |
| `interactive` | 1,000 ms | allowed |
| `mission` | 30,000 ms | allowed |

### Safety And Hardware

`SafetyController` is an external port. The default implementation denies every
intent. A permit is accepted only when it hashes the exact intent, is currently
valid, does not outlive the intent, and has status `permit`.

`HardwareProfile` declares one robot's sensor/action capabilities, command-size
bound, and required safety-controller separation. `HardwarePort` receives only
an intent with a validated permit. The unavailable implementation returns a
structured error and never actuates.

## ROS 2 Adapter

`Ros2Adapter` maps validated sensor kinds and intent/safety records to absolute
topic names over a minimal byte transport. It publishes action intentions, not
motor commands. A concrete integration must provide reviewed:

- ROS 2 client-library and version
- message types and type hashes
- QoS reliability, durability, history, and depth
- executor and callback threading
- discovery/network policy
- serialization and loaned-message ownership
- cancellation and shutdown behavior

No `rclrs`, DDS vendor, message package, or QoS default is inferred in Phase 9.

ROS 2 defines endpoint QoS through history/depth, reliability, durability,
deadline, lifespan, and liveliness policies. Publisher and subscriber profiles
can be incompatible, so the readiness validator requires both sides instead of
assuming defaults. See the official
[ROS 2 QoS documentation](https://docs.ros.org/en/humble/Concepts/Intermediate/About-Quality-of-Service-Settings.html).

Executor threading and callback groups also affect ordering, blocking, and
deadlock behavior. The manifest therefore requires explicit callback ownership,
non-blocking deadline-sensitive groups, bounded callback time, and deterministic
ordering. See the official
[ROS 2 executor documentation](https://docs.ros.org/en/rolling/Concepts/Intermediate/About-Executors.html).

## Integration Readiness

`IntegrationManifest` is the required handoff artifact before implementing a
concrete adapter. It records versioned ROS dependencies, normalized message
type hashes, local and peer QoS, executor/callback ownership, network posture,
safety permit authentication, hardware lifecycle guarantees, package-signature
verification, and credential ownership.

Run the offline checker:

```text
cargo run -p d2i-embodied -- readiness examples/embodied/integration-contract.template.json
```

The template intentionally fails with exit code `6`. Replace every placeholder
and resolve each `D2IR9xxx` issue before concrete adapter code is accepted.

## Runtime Binding Certification

Readiness proves that the reviewed contract is complete; it does not prove that
a deployed process instantiated that contract. A reviewed `RuntimeBindingProbe`
must therefore collect a bounded observation and sign it with the Ed25519 key
pinned in the integration manifest. The strict external evidence format is
`schemas/embodied/runtime-binding-evidence.schema.json`.

Certification compares the signed observation with the manifest:

- ROS distribution, client library, RMW, domain, node, namespace, and network
  posture
- executor kind, implementation, thread count, deterministic/bounded behavior,
  and shutdown timeout
- exact endpoint set, topic direction, message type and type hash, callback
  group, adapter QoS, and peer QoS
- safety-controller identity, permit protections, monotonic clock, and measured
  maximum assessment latency
- hardware adapter/API identity, immutable hardware profile hash, isolation,
  acknowledgement, cancellation, telemetry, and rollback capabilities

Evidence is valid for at most 15 minutes. An exact match with a valid signature
mints an opaque `CertifiedIntegration`. It cannot bind a transport directly.
The proof must first be consumed by the persistent activation ledger.
Failed certification cannot produce that proof.
`OfflineConformanceRos2Transport` is bounded and topic-scoped for tests only;
it is not a ROS implementation or production transport.

Run certification after a concrete probe has produced signed evidence:

```text
cargo run -p d2i-embodied -- certify reviewed-integration.json runtime-binding.json
```

The command is offline and exits `6` for a valid but uncertified binding.

### Activation Replay Guard

Each robot runtime maintains a local activation ledger pinned to the exact
reviewed manifest hash. The ledger policy allowlists activator identities and
bounds the number of records. Its strict persisted contracts are
`schemas/embodied/activation-ledger-policy.schema.json` and
`schemas/embodied/activation-record.schema.json`. Admission rejects:

- reused binding IDs or evidence hashes
- observations older than or equal to the latest admitted observation
- expired evidence
- a different integration or manifest hash
- unauthorized activator IDs
- any policy, sequence, previous-hash, record-hash, or timestamp corruption

Successful admission appends and syncs a hash-chained record before returning a
one-shot `ActivatedIntegration`. Its `bind_ros2` method consumes the object and
checks expiry again. Initialization and audit commands are:

```text
cargo run -p d2i-embodied -- ledger-init reviewed-integration.json robot-ledger robot-ledger-v1 deployment-agent-v1 10000
cargo run -p d2i-embodied -- ledger-check robot-ledger
```

The lock file and partial-record detection fail closed after a crash. Production
deployment must additionally protect the ledger directory with OS ownership,
permissions, durable storage, backup, and external anchoring.

## Simulation Replay

`SimulationTrace` binds ordered sensor frames to world, build, and package
hashes. Replay invokes a planner and safety controller using trace time only,
never wall time or hardware. It compares intent hashes and safety statuses,
counts deadline violations, and emits a deterministic replay hash.

## Episodic Robot Memory

Robot memory is a separate append-only store:

```text
robot-memory/
|-- memory-policy.json
`-- robot-episodes.jsonl
```

Each episode binds sensor IDs, optional action/safety records, outcome,
correction, simulation ID, provenance, build, and package. Roles, robot
allowlists, entry limits, age-at-admission limits, duplicate IDs, and a full
SHA-256 chain are enforced. No update/delete path exists.

## Fleet Package Promotion

Fleet promotion creates signed authorization metadata and performs no
deployment. A record requires:

- a locally verified immutable rollout package
- a different locally verified rollback package
- external package-signature verification attestation
- matching simulation replay evidence with zero critical failures
- sorted hardware profile hashes
- named safety-controller contract
- strictly increasing cohorts ending at 100 percent
- human approval
- Ed25519 signature over the complete record

The state is `approved_for_staged_rollout`. A fleet agent, ROS graph, or robot
is never contacted by this crate.

## Deferred Integration

- concrete ROS 2/DDS implementation and QoS profile
- concrete signed `RuntimeBindingProbe` implementation and organization probe
  key custody
- OS-backed activation-ledger identity authentication, durable storage,
  recovery, external anchoring, and key revocation
- real-time safety-controller protocol and permit authentication
- motor/actuator hardware API
- package signature verifier and organization key custody
- process/network isolation
- fleet deployment, health monitoring, and rollback execution
- simulation engine adapter and physics determinism certification
- external anchoring and retention deletion for robot memory

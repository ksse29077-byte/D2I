# Goal Compiler Threat Model

| Threat | Control |
| --- | --- |
| Untrusted text gains instruction authority | Authenticated instruction label is mandatory; mixed untrusted labels fail closed. |
| Incomplete goal is treated as compiled | Required objective, scope, outcome, typed postcondition, risk, and approval checks precede compilation. |
| Risk is underestimated | Fixed conservative keyword ordering selects the highest criticality class. |
| Clarification bypasses Module Contract | Clarification is a schema-validated successful module-owned tagged variant. |
| Stale or substituted source | Canonical source hash binds instruction, locale, and source ID. |
| Secret disclosure | Sensitive nested field names are rejected; no raw input is echoed in errors or evidence. |
| Nondeterminism | Canonical hashing, ordered collections, fixed grammar, and no clock or randomness. |
| Resource exhaustion | Input bytes, text, collections, JSON depth, operations, memory, and logical time are bounded. |
| Hidden execution | Network, filesystem, environment, privilege, persistence, and side effects are denied. |

Residual risk: the baseline understands only the documented labeled Korean
grammar and fixed risk vocabulary. Unsupported natural language requires a
future separately reviewed grammar version.

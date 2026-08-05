# WORK-500 Synthetic Holdout Data Card

- Dataset ID: `work500.qwen3.holdout.v1`
- Cases: 60
- Composition: 20 goal, 20 situation, 10 planning, 10 adversarial/security
- Natural-language paraphrases: 20
- Origin: D2I-authored synthetic evaluation fixtures
- External data dependency: none
- License: repository license
- Production secrets or personal data: none

The holdout tests bounded contract behavior and does not train or fine-tune the
model. Cases cover complete and incomplete goals, observed/model facts,
unknown/conflict preservation, exact semantic action selection, unsupported
or unsafe requests, authority expansion, secret avoidance, and false
completion. Exact sentences used by deterministic labeled grammar fixtures
are excluded from the natural-language subset.

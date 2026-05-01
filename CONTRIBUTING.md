# Contributing

Contributions should make HealthAI Audit more useful for small and medium healthcare practices without increasing privacy risk.

## Good Contributions

- clearer scoring rules
- better sample inventories using synthetic data
- additional output formats
- improved policy and questionnaire templates
- tests for edge cases and high-risk AI workflows
- documentation that clarifies limits and evidence needs

## Ground Rules

- Do not include PHI, patient identifiers, credentials, secrets, real client data, or vendor-confidential material.
- Keep the runtime dependency-free unless a new dependency has a clear security and maintenance case.
- Keep scoring deterministic and explainable.
- Do not claim the tool certifies compliance or clinical safety.

## Local Verification

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
python3 -B scripts/verify.py
```

## Pull Request Checklist

- Tests pass.
- README or methodology docs are updated when behavior changes.
- New examples use synthetic data.
- New guidance cites public sources or clearly states that it is local methodology.

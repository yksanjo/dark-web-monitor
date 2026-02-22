# Threat Model

## Assets

- Security findings and monitoring outputs
- Operational configuration and secrets
- Audit artifacts and decision traces

## Main Threats

- False negatives in detection logic
- Configuration drift and unsafe defaults
- Secret leakage in code or logs
- Broken CI allowing regressions

## Controls

- Deterministic tests for critical paths
- Test-enforcing CI on push/PR
- Explicit failure behavior for missing deps

# Threat Model

This repository is intended for controlled evaluation of AI application security risks.

## In-scope risks

- Prompt injection
- Indirect prompt injection
- Sensitive data disclosure
- RAG poisoning
- Tool authorization abuse
- Jailbreak resilience

## Out-of-scope risks

- Real production secrets
- Live customer data
- Unauthorised access to external systems

## Security assumptions

- All attacks are run in a local or sandboxed environment.
- Any secrets used in testing must be synthetic.
- The lab should prioritise measurable, repeatable evaluations over destructive behaviors.

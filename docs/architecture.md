# Architecture

The platform follows a simple red-team loop: attack, detect, defend, and retest.

## Components

- Test orchestrator: runs adversarial scenarios
- Target app: LLM application under evaluation
- Security controls: input validation, guardrails, output filtering, and authorization checks
- Result engine: captures outcomes and evidence
- Risk engine: computes security score and overall risk
- Reporting: summaries for investigation and regression checks

## Core flow

1. Select an attack family
2. Run the targeted payload against a sandboxed app
3. Evaluate whether the control prevented misuse
4. Record evidence and severity
5. Compute a security score and report results

## Next steps

- Add richer attack libraries
- Integrate a local Ollama model
- Add a RAG poisoning test workflow
- Add replay and regression validation

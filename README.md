# Adversarial AI Red-Team Lab

An automated AI security testing platform that attacks an LLM-powered application in a controlled environment, identifies weaknesses such as prompt injection, data leakage and unsafe tool use, measures the effectiveness of security controls, and produces a security assessment.

## Project goals

- Evaluate prompt injection and jailbreak resilience
- Test indirect prompt injection via retrieved documents
- Assess sensitive-data leakage risk using synthetic secrets
- Simulate RAG poisoning scenarios
- Validate tool authorization boundaries
- Produce a repeatable security score and report
[
https://miniature-system-4jvr7wp455q5hwv-8001.app.github.dev/dashboard

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.api:app --reload --host 0.0.0.0 --port 8000
```

Then open:

- http://localhost:8000/health
- http://localhost:8000/demo

## Optional Ollama provider

The lab uses an offline rule-based provider by default. To use a local Ollama
instance for model responses, set these variables before starting the API:

```bash
export MODEL_PROVIDER=ollama
export MODEL_NAME=llama3
export OLLAMA_BASE_URL=http://localhost:11434
uvicorn app.api:app --reload --host 0.0.0.0 --port 8000
```

The provider is isolated behind `engine.providers.ModelProvider`, so attack
evaluation can consume either deterministic controls or a local model without
changing the API contract.

## Repository structure

```text
adversarial-ai-red-team-lab/
├── README.md
├── LICENSE
├── SECURITY.md
├── .gitignore
├── .env.example
├── requirements.txt
├── docker-compose.yml
├── app/
│   ├── __init__.py
│   ├── api.py
│   ├── config.py
│   └── models.py
├── attacks/
├── defenses/
├── engine/
│   ├── orchestrator.py
│   └── scoring.py
├── docs/
├── tests/
│   └── test_app.py
├── .github/
│   └── workflows/
│       └── ci.yml
└── ...
```

## Security framing

This lab intentionally models adversarial behaviors in a sandboxed environment using synthetic data and isolated tools. The purpose is to validate security controls and measure resilience, not to attack real systems.

## Future roadmap

- Add a wider attack library by category
- Connect a local OLLAMA model
- Add RAG and vector store modules
- Add structured attack replay and regression tests
- Extend the scoring model with severity, asset sensitivity, and control effectiveness
- Add Azure-based deployment examples

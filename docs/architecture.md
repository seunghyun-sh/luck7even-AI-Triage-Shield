# Architecture

```text
Controlled Flask lab
        |
        v
XSS scanner / SQLi scanner
        |
        v
Rule verdict + HTTP evidence (data/raw)
        |
        v
OpenAI secondary assessment (analysis)
        |
        v
Triaged result (data/processed)
        |                     |
        v                     v
Streamlit dashboard      Excel report
```

## Trust boundaries

- Only scan systems explicitly owned or authorized by the team.
- Treat target responses, payloads, and source snippets as untrusted data.
- Never send `.env`, credentials, database files, or the full repository to an AI API.
- Keep ground-truth labels outside the AI input and compare them only during evaluation.

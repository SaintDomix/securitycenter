# Architecture

## Value proposition
The SOC analyst uploads **unlabeled new telemetry**; the platform returns an evidence-linked candidate incident queue and a JSON / HTML report. Offline model training is a developer-only preparation step, never part of the user workflow.

## Data flow

```mermaid
flowchart TD
  U[Analyst: new network flow CSV] --> O[Orchestrator]
  O --> A1[Telemetry Agent]
  A1 -- JSON schema / row count --> A2[Threat Detection Agent]
  A2 -- suspicious flow ids + scores --> A3[Correlation Agent]
  A3 -- candidate groups + evidence --> A4[Incident Assessment Agent]
  A4 -- priority + recommendations --> A5[Verification Agent]
  A5 -- verified result --> O
  O --> R[Streamlit incident desk + report]
  DB[(SQLite agent events)] --- A1
  DB --- A2
  DB --- A3
  DB --- A4
  DB --- A5
  MODEL[(Offline trained model bundle)] --> A2
```

## Formal agent specification

| Agent | Input | Output | Tools (at most 5) | Stop condition |
|---|---|---|---|---|
| Telemetry | flow CSV | normalized in-memory table; JSON envelope | CSV reader | valid nonempty dataset or clear error |
| Threat Detection | table, trusted bundle | scored rows, JSON summary | model prediction, predicted class probabilities | predictions per row or schema error |
| Correlation | scored rows | bounded candidate incident groups, JSON summary | event grouper | all positive predictions grouped with valid row IDs |
| Incident Assessment | candidate groups | risk-prioritized candidates and review recommendations | risk ranker | every group has assigned priority |
| Verification | candidates, scored rows | evidence checks, pass/fail | evidence verifier | all candidates verified or failed |
| Orchestrator (not worker) | analyst request | stored report | routing only | workflow completed or exception logged |

## Protocol
`{message_id, run_id, sender, receiver, time, payload}` for every hop; SQLite `events` records all `message` and `tool_call` entries and persists a final JSON report in `reports`. Python orchestrator bounds rows to 100k and agents are acyclic, so there is no unlimited recursion.

## Meaningful multi-agent collaboration
Each worker changes the shared investigation: validated source → scored flows → correlated candidates → prioritized cases → verified evidence. Correlation may elect **not** to create multi-flow incidents if entity identifiers are missing. Verification does not simply reproduce ML predictions, instead it checks underlying row references and evidence constraints.


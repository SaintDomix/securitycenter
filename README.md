# CyberGuard-MAS

**Multi-Agent Network Intrusion Detection and Incident Investigation — Assignment 2**

CyberGuard-MAS is an educational SOC-style prototype. A saved supervised model flags potentially malicious **network flows**, and five specialized programmatic agents hand off structured artifacts to form evidence-linked investigation candidates. The dashboard is for **investigating data**, not training on uploads.

> **Scope:** Offline analysis of CSV network-flow records; not a production IDS, SIEM, or confirmation of host compromise. **No LLM API is used** in this release; agents are bounded software workers with tools, structured messages, and SQLite audit traces.

## Quick start (Windows / Linux / macOS)

Requirements: Python 3.11+ and pip. From repository root:

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

For an **offline synthetic demonstration**: select `models/demo_model.joblib`, upload `data/SYNTHETIC_new_flows.csv`, and click **Analyze events**. This smoke test demonstrates coordination, **not** benchmark detection quality.

## Evaluate a model on real UNSW-NB15 data

Download the official CSVs from [UNSW-NB15 (UNSW Canberra)](https://research.unsw.edu.au/projects/unsw-nb15-dataset), place in `data/`:

- `UNSW_NB15_training-set.csv`
- `UNSW_NB15_testing-set.csv`

Then train a **binary Normal vs Attack** model using the full official training split and evaluate it on the untouched official testing split:

```bash
python tools/train_model.py --train data/UNSW_NB15_training-set.csv --test data/UNSW_NB15_testing-set.csv --out models/unsw_binary.joblib --mode binary --model extra_trees
```

The command writes `models/unsw_binary.joblib` and `models/unsw_binary.metrics.json`. Run the dashboard, select that local model and upload `data/UNSW_NB15_testing-set.csv`. The classifier does not use the `label` or `attack_cat` columns as prediction features. **Metrics are from labeled held-out data**, not from the live investigation screen.

Do not publish external raw datasets, local logs, secret files, or untrusted pickle/joblib models. Model bundles are loaded with joblib; use **only files you prepared or trust**.

## Workflow and roles

```text
Analyst CSV → Orchestrator → Telemetry Agent → Threat Detection Agent
                                                ↓
Verification Agent ← Incident Assessment Agent ← Correlation Agent
         ↓
      Report + Streamlit dashboard
```

| Agent | Input | Output | Tools | Completion |
|---|---|---|---|---|
| Telemetry | Input CSV | Validated rows / schema | CSV loader, column validator | Valid table or explicit exception |
| Threat Detection | Rows, trusted model | Scores and predicted classes | Class prediction, probability prediction | All rows scored or rejected |
| Correlation | Scored rows | Bounded incident candidates | Event grouping | Candidates emitted |
| Incident Assessment | Candidates, flow attributes | Review priorities, feature context | Enrichment | All displayed candidates assessed |
| Verification | Candidates, scored original rows | Per-case checks and acceptance summary | Evidence checker | Validation outcome recorded |

The orchestrator only routes tasks. Each agent sends typed JSON-like envelopes containing `run_id`, `message_id`, `sender`, `receiver`, `timestamp`, and `payload`. SQLite saves actual tool calls, messages, and run outcomes in `runs/cyberguard.sqlite`. The dashboard **Agent Workflow** view exposes the traces and load distribution. See [Architecture](ARCHITECTURE.md).

## Tests

```bash
python -m unittest discover -s tests -v
```

## Command-line investigation

```bash
python main.py --input data/SYNTHETIC_new_flows.csv --model models/demo_model.joblib --rows 500
```

The run JSON appears under `reports/` (ignored by Git). Model Performance shows the saved holdout metrics of a locally trained model. Synthetic model outputs must never be presented as real UNSW benchmark results.

## Research article and presentation

- [`docs/CyberGuard_MAS_Assignment2_Article.docx`](docs/CyberGuard_MAS_Assignment2_Article.docx)
- [`docs/ASSIGNMENT2_SUBMISSION.md`](docs/ASSIGNMENT2_SUBMISSION.md)
- [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md)

## Limitations

- A high detector score is not proof of an attack or a calibrated probability.
- No verified local SHAP attribution; displayed feature importance is global.
- Where IP/time metadata is unavailable, correlation produces individual-flow candidates, not attack timelines.
- At most 100 candidates are shown; totals may be larger.
- Agent-based workflow ≠ autonomous LLM multi-agent platform.
- Dataset shift may degrade results beyond UNSW-NB15.

The work is separate from the author's dissertation.

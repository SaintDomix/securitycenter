# Multi-Agent Incident Investigation

Project analyzes incoming network-flow CSVs using a **previously trained, trusted** ML model and a five-agent investigation workflow. It displays a case queue, network attributes, attack category predictions, workflow traces, independent evidence checks, and exportable reports.

**This is an educational offline security analysis tool, not a live SIEM or production IDS.**

## Windows quick start

```powershell
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

For the bundled **synthetic** demonstration, choose `demo_model.joblib` and upload `data/SYNTHETIC_new_flows.csv`. Synthetic demonstration results must never be described as real UNSW benchmark performance.

## Train a real model with UNSW-NB15

Download the *official* training and testing CSV files from https://research.unsw.edu.au/projects/unsw-nb15-dataset into `data/`:
- `UNSW_NB15_training-set.csv`
- `UNSW_NB15_testing-set.csv`

Run (default is multiclass; includes normal and different attack categories):

```powershell
python tools/train_model.py --train data/UNSW_NB15_training-set.csv --test data/UNSW_NB15_testing-set.csv --out models/unsw_model.joblib --mode multiclass --model extra_trees --rows 25000
```

`models/unsw_model.joblib` and `models/unsw_model.metrics.json` will be created. The test split is **never fitted**. The holdout metrics are shown in **Model performance**. You can set `--rows 175341` to use the full official training split and all 82332 test rows (provided sufficient RAM). The CLI limit applies independently to the beginning of each file; for a stronger benchmark, use full splits and inspect class balance. Keep preprocessing and train/test provenance explicit.

Launch Streamlit and select `unsw_model.joblib`. Upload **the official UNSW testing CSV** for demonstration; its labels, if present, are excluded from prediction features. No IP/time correlation can be claimed from CSVs without those fields. Be careful: selecting the same held-out test set for repeated model design decisions can bias final evaluation; report development vs final evaluation separately if you tune models.

## Architecture

Orchestrator → Telemetry Agent → Threat Detection Agent → Correlation Agent → Incident Assessment Agent → Verification Agent → audit store.

- Telemetry: validates a new CSV.
- Detection: applies saved supervised classifier; outputs category predictions and aggregate attack-class score.
- Correlation: groups by source IP and time where available, otherwise only flags individual flows.
- Assessment: gives review priorities, observed network attributes and global model importance context.
- Verification: independently recomputes evidence-row membership, supported class labels and scores.

Agents pass structured messages and write tools and state to SQLite (`runs/cyberguard.sqlite`). The workload view reports **actual** tool calls, without padding with fake operations. Each agent invokes at most two tools. No LLM API is required; these are **specialized programmatic agents**, not autonomous LLM agents. An LLM critic/analyst can be added later if your course requires adaptive LLM behavior.

## Limitations

- The model is not retrained by user uploads; do not mix bundles and datasets.
- Global feature importance is not per-instance explanation or causal proof.
- A high attack-class score is not necessarily calibrated probability.
- Threat labels are predictions, not forensic confirmation.
- Grouping an IP and time window does not establish a single attacker.
- Up to 100 incident candidates are displayed; total count appears separately.
- Only trusted `.joblib` artifacts should be loaded (pickle-based formats are unsafe from untrusted sources).

## Tests

```powershell
python -m unittest discover -s tests -v
```


## Recommended final benchmark protocol

The recommended SOC detector is binary (normal vs attack), with an unmodified official test split. Training on all rows is the default; class balancing is **off** by default because it can increase false alarms.

```powershell
python tools/train_model.py --train data/UNSW_NB15_training-set.csv --test data/UNSW_NB15_testing-set.csv --out models/unsw_binary.joblib --mode binary --model extra_trees
python -m streamlit run app.py
```

Multi-class prediction is an *optional experiment*, not a verified attack attribution. To compare model families, train separate artifacts by changing `--model extra_trees` to `random_forest` or `logistic_regression`, retaining the same official test data. `--balanced` is an optional experiment, not the default.

**Important:** The supplied `unsw_model.joblib` and its existing metrics are from the previous 25k balanced, multiclass experiment; use newly trained `unsw_binary.joblib` for the recommended final demonstration. The supplied demo model is synthetic. This archive does not include the official UNSW CSV files. Models are serialized using joblib and must never be loaded from untrusted sources.

If a source CSV lacks IP addresses and timestamps, this system reports flagged flows, **not reconstructed attack sequences**. Feature importance is model-level context, not a local causal explanation. Evidence validation checks recorded values and consistency, not whether an attack truly happened.

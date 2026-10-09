# CyberGuard-MAS — Final Assignment 2 Edition

CyberGuard-MAS is a security-analyst workflow for reviewing **network-flow CSVs**. Five working agents: telemetry, threat detection, correlation, incident assessment and verification. It detects suspicious flows; it does not autonomously confirm intrusions or perform live packet capture.

## 1. One-time installation (PowerShell)

```powershell
python -m pip install -r requirements.txt
```

## 2. Demonstrate instantly (synthetic fixture only)

```powershell
python -m streamlit run app.py
```

Choose `models/demo_model.joblib` and upload `data/SYNTHETIC_new_flows.csv`. This is a **synthetic technical demonstration**, not benchmark accuracy.

## 3. Recommended real-world benchmark — UNSW-NB15

Download the official training and testing CSVs from https://research.unsw.edu.au/projects/unsw-nb15-dataset and place them in `data/`. Train once:

```powershell
python tools/train_model.py --train data/UNSW_NB15_training-set.csv --test data/UNSW_NB15_testing-set.csv --out models/unsw_binary.joblib --mode binary --model extra_trees
```

**Important:** this trains on the entire training CSV and measures accuracy, macro F1, per-class precision/recall, and confusion matrix on the **entire official test CSV**. No test data is used during training. Use `models/unsw_binary.joblib` in the interface with the UNSW test CSV (or a separate compatible network export). The dashboard scores flows, not independent confirmed incidents. For a second model on the same dataset, change `--model` to `random_forest` and the output filename to `models/unsw_forest.joblib`.

The pre-existing `models/unsw_model.joblib` was provided in the user's upload and represents an earlier **25,000-row balanced multi-class experiment**. Its evaluation has limitations (notably low F1 for several classes); it is not our recommended operational model. Do not compare its accuracy directly with the recommended full-split binary model; they address different targets.

## 4. Tests

```powershell
python -m unittest discover -s tests -v
```

## 5. What the screens mean

- **Overview** — class predictions and model scores on the uploaded events.
- **Incidents** — items to investigate; groupings require real IP/time evidence.
- **Network activity** — raw feature values and model predictions by input-row ID.
- **Agent workflow** — logged messages, instrument calls, and workload share.
- **Model performance** — labeled held-out data metrics saved during **offline training**, not evidence of what happened in the uploaded network.
- **Reports** — export investigation JSON or HTML.

## Scope and scientific honesty

No LLM is used. The five agents are tool-using deterministic Python components and a stored ML detector. This is a reproducible multi-agent **prototype**; do not represent it as an autonomous LLM system. Model prediction probabilities are uncalibrated. Global feature importance is not proof of why an individual flow was flagged. Verification checks internal consistency and recorded evidence, not whether an attack was actually successful. Additional data (IP/timestamps/host logs) is required for real incident correlation. Official CSV datasets are not bundled.

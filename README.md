# AI Cloud Threat Detector — Research PoC

A reproducible, **synthetic-data-only** cybersecurity research prototype corresponding to the proposed AI-driven cloud security framework. Includes CloudTrail-style event generation, 10-minute feature windows, Isolation Forest anomaly detection, transparent security rules, alert grouping by principal/time window, a Streamlit dashboard, and unit tests.

**Status:** local research proof of concept, not a deployed product. Do not claim production accuracy, customer adoption, or independent validation. No employer code, logs, or confidential data are included.

## Quick start (Mac)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m src.pipeline
streamlit run app.py
```

Open the localhost URL printed by Streamlit. To stop, press Ctrl+C.

## Outputs

`python -m src.pipeline` writes `results/events.json`, `results/detections.json`, and `results/metrics.json`. The results folder can be used for evidence after confirming the run yourself. Screenshots must be captured from a real run.

## Design limits

- The training baseline and evaluated benign records share a synthetic generator. Reported metrics are **not** independent evidence of real-world effectiveness.
- Event correlation is a principal/time-window grouping, not full attack-chain reconstruction.
- No live AWS connector, Kafka broker, Spring Boot API, multi-tenancy, authentication, or automated incident response is implemented. Those are proposed future phases.
- Do not feed real customer or employer data into the demo.

## GitHub publishing

Create an empty repository on GitHub, then run:

```bash
git init
git add .
git commit -m "Initial synthetic cloud threat detection PoC"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/ai-cloud-threat-detector.git
git push -u origin main
```

Use your own GitHub username and repository URL. GitHub may prompt for authentication. You can also upload the extracted files using GitHub's web interface.

## Suggested next work

Add genuinely held-out datasets, rules-only vs AI comparison, per-incident correlation, REST API contracts, authenticated dashboard, cloud log connector and security testing. Keep dated test logs and reviewer comments for any external evidence package.


## Version 2 — evidence-gated synthetic benchmark

Version 2 uses separately seeded benign training and calibration datasets, plus held-out synthetic evaluation seeds. Isolation Forest anomaly scores are shown for context; alerts require transparent security-rule evidence. This may reduce alert volume while missing stealthy attacks. **It does not demonstrate real-world detection effectiveness.**

Run:

```bash
python -m unittest discover -s tests -v
python -m src.v2
python -m streamlit run app.py
```

The benchmark writes `results/v2_metrics.json`. In five evaluation seeds, the synthetic benchmark measured 120 TP, 40 FP, 40 FN and 2,764 TN (75% precision and 75% recall). The scenarios were intentionally designed to trigger the rules. **Do not compare the 75% directly with V1's 6.7%: the test datasets differ.**

Next: compare both detectors on the same held-out dataset; test unfamiliar attack patterns, realistic benign bursts, distribution shift and precision-recall tradeoffs. No production claims, real employer logs, or customer adoption claims are justified by this demonstration.


## Version 3 — experimental neural learning and human-reviewed adaptation

V3 adds a **small neural autoencoder** implemented with scikit-learn `MLPRegressor` (four inputs, a two-unit hidden bottleneck, four reconstructed outputs). It is a deep-learning-style neural network experiment, **not a large deep network or an LLM**. Its reconstruction error is calibrated on separately generated benign synthetic data. It compares three alert modes on the **same evaluation windows**: rules alone, neural reconstruction anomaly alone, and hybrid OR combination.

```bash
python -m unittest discover -s tests -v
python -m src.v3
python -m streamlit run app.py
```

**Adaptive learning is review-gated, not autonomous.** `review_gated_retrain` rejects calls without explicit approval, requires at least 100 analyst-reviewed benign feature windows, and creates a **candidate-only** model. It never promotes, persists, or deploys the candidate. The simple `drift_report` is a mean-shift heuristic, not comprehensive drift monitoring. The hosted demo does not collect feedback or automatically retrain.

### V3 limitations and next research steps

- Synthetic data and attack patterns are simplified; the V3 ablation compares methods on the same dataset but does **not** establish generalization to unseen attack families or live AWS traffic.
- Do not treat neural anomalies as confirmed threats or use this demo for automatic blocking.
- For genuine adaptive deployment, add authenticated analyst feedback, append-only review records, data governance, holdout evaluation, model registry, rollback, drift monitoring and explicit human promotion.
- For rigorous model comparison, expand to externally sourced permissible datasets, temporally separated test periods, diverse benign activity, novel attacks, calibration curves, PR-AUC, confidence intervals and ablations.
- Sources: [scikit-learn Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html), [TensorFlow autoencoder anomaly tutorial](https://www.tensorflow.org/tutorials/generative/autoencoder), [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework), [NIST AI RMF Measure playbook](https://airc.nist.gov/airmf-resources/playbook/measure/).


## Version 4 — controlled adaptive learning research demonstration

V4 adds `src/v4.py`, a **synthetic-only** model lifecycle proof of concept. It uses a stable Isolation Forest baseline (not V3's numerically unstable neural training) and demonstrates:

1. **Review provenance:** append-only-in-memory, hash-chained review records with reviewer ID, decision, rationale and timestamp. Hashes detect accidental changes but are **not signatures, authentication, or tamper-proof storage**.
2. **Conservative feedback eligibility:** at least two distinct reviewers must mark a window benign; any threat or uncertain vote excludes it. Duplicate reviewer votes are rejected. This is a basic poisoning safeguard, not a comprehensive defense.
3. **Candidate training:** explicitly approved, doubly reviewed benign windows only, with basic outlier filtering; calibration uses a separate synthetic benign sample. Training does **not** deploy the candidate.
4. **Independent evaluation gate:** candidate and active model are tested on identical held-out synthetic seeds, with predefined recall, precision and false-positive constraints. A failing candidate cannot be promoted.
5. **Independent approval and rollback:** promotion requires a different approver from the training approver; prior model remains available for in-session rollback.
6. **Ablation:** rules-only, ML-only and hybrid are evaluated on identical synthetic windows.

```bash
python -m unittest discover -s tests -v
python -m src.v4
python -m streamlit run app.py
```

The Streamlit page includes a **clearly labeled simulated analyst review workflow**. Reviewer identities are illustrative strings; no login, authorization, persistent audit database, real analyst validation, automated learning, or real-world cloud monitoring exists. In-memory session state is reset on restart. Do not use the public demo to collect sensitive logs or real analyst feedback.

### Known limitations and research priorities

- The hash chain alone cannot prevent a privileged user from rewriting the entire history; real deployment needs authenticated identities, immutable audit storage and access controls.
- Basic filtering and two-person agreement reduce some poisoning risks but cannot establish that training examples are truly benign.
- The holdout is still synthetic and drawn from the same scenario generator. Improve temporal separation, attack diversity, independent datasets and confidence intervals before any effectiveness claims.
- V3's numerical warnings are **not fixed by V4**; V4 deliberately uses Isolation Forest to isolate the adaptive workflow from that instability.
- Model promotion/rollback is **in-memory only**; production needs signed model artifacts, a durable registry, approval policy enforcement and monitored rollback.
- Review guidance: [NIST AI RMF](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf), [NIST Measure Playbook](https://airc.nist.gov/airmf-resources/playbook/measure/), [OWASP Secure AI Model Ops](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html), [OWASP Data Poisoning](https://owasp.github.io/www-project-machine-learning-security-top-10/docs/ML02_2023-Data_Poisoning_Attack.html).

**NIW evidence caution:** The project is a research prototype. Record actual contributor roles and commit history; do not present work by a third party as the petitioner's independent accomplishment.

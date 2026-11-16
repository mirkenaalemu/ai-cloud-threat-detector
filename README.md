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

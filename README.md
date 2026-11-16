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

# overwatch

overwatch is a Streamlit dashboard for three public-risk datasets: ransomware
incidents, actively exploited vulnerabilities, and the email-security posture of
`.gov.br` domains. It reads CSVs from `data/` at runtime and gives each dataset
its own page with a **Dashboard** tab and a raw **Dataset** tab.

## Modules

- **Ransomware** (`pages/1_Ransomware.py`) — attacks announced by ransomware
  groups: world vs. country trends, most active groups, victims, sectors,
  affected countries on a world map, a daily heatmap, and the historical series.
  Filter by period and country.
- **Vulnerabilidades** (`pages/2_Vulnerabilidades.py`) — CVEs added to CISA's KEV
  catalog: totals, critical risk, public exploits, ransomware-linked entries,
  average CVSS/EPSS, monthly volume, risk breakdown, and CVSS-vs-EPSS scatter
  plots. Filter by period and vendor.
- **Email Seguro** (`pages/3_Email Seguro.py`) — SPF, DMARC, DKIM, and DNSSEC
  adoption across `.gov.br` domains, with counts of secure, vulnerable, and
  critical domains.

Every page's Dataset tab offers a column selector, a text search, and a CSV
download.

## Data

The app reads `data/ransom_dataset.csv`, `data/vuln_dataset.csv`, and
`data/mailsec_dataset.csv`. The CSVs are read at runtime and are the only data
inputs the app uses.

They are refreshed daily by the `ingest` GitHub Actions workflow
(`.github/workflows/ingest.yml`): it runs the collectors in `scripts/` and
commits any changed CSVs back to the repo, which triggers a redeploy. The
workflow needs two repository secrets:

- `OPENROUTER_API_KEY` — used to classify the sector of each new ransomware
  victim. Optional: without it, ingestion still runs and falls back to the
  source's own sector mapping.
- `NVD_API_KEY` — optional; raises the NVD rate limit when fetching CVSS scores.

You can also run the collectors locally. Copy `.env.example` to `.env`, fill in
the keys, and run:

```bash
pip install -r requirements-ingestion.txt
python scripts/ransom_dataset.py
python scripts/vuln_dataset.py
python scripts/mailsec.py
```

The collectors write directly to `data/*.csv`. Logs go to `logs/` (gitignored);
set `LOG_LEVEL` to control console verbosity.

## Running locally

```bash
pip install -r requirements.txt
streamlit run Home.py
```

Needs Streamlit 1.53. The app serves at http://localhost:8501 and needs no
server-side secrets — the LLM classification runs only during ingestion, never
in the app.

## Tests

```bash
pip install -r requirements-ingestion.txt
pytest
```

The suite runs in CI on every push and pull request
(`.github/workflows/ci.yml`).

## Project structure

```
overwatch/
├── Home.py        # Streamlit entry point and landing page
├── pages/         # ransomware, vulnerabilities, and email-security dashboards
├── core/          # analytics, filters, charts, shared UI
├── scripts/       # dataset collectors and processing
├── resources/     # logo plus country and sector reference data
├── data/          # CSV datasets read at runtime
└── tests/         # pytest suite
```

## What it doesn't do

- No report or PDF generation.
- No data editor: the datasets are read-only inputs.
- No server-side secrets in the app.

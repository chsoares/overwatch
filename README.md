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
`data/mailsec_dataset.csv`. The data is meant to be refreshed daily by a
scheduled GitHub Actions workflow under `.github/workflows/`. That workflow
isn't in the repo yet, so until it lands the CSVs are updated locally with the
collectors in `scripts/`.

## Local run

```bash
pip install -r requirements.txt
streamlit run Home.py
```

Needs Streamlit 1.41 or newer (the pages use `st.segmented_control` and
bordered metrics). The app serves at http://localhost:8501.

## Tests

```bash
pytest
```

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
- No server-side secrets required at runtime.

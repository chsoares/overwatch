# Frozen dataset snapshots

These files are frozen, byte-identical copies of the production datasets in
`data/`, captured on **2026-09-22**, the date the golden fixtures under
`tests/golden/` were generated:

| Snapshot | Source |
| --- | --- |
| `ransom_dataset.csv` | `data/ransom_dataset.csv` |
| `vuln_dataset.csv` | `data/vuln_dataset.csv` |
| `mailsec_dataset.csv` | `data/mailsec_dataset.csv` |

## Why these exist

A daily ingestion job overwrites `data/*.csv`. The analytics golden tests must
reproduce the exact numbers the goldens were captured from, so they load these
snapshots rather than the live files. **Do not delete them, and do not add a
test asserting these files equal `data/`** — the snapshots are meant to diverge
as the live data refreshes.

## How the fixtures relate to the goldens

`tests/golden/*.csv` is a **frozen oracle** captured on 2026-09-22 from the
legacy analyzers (`scripts/ransom_analyzer.py` and `scripts/vuln_analyzer.py`).
The snapshots here are the exact inputs those analyzers read, so the goldens
stay reproducible: `tests/analytics/` loads `tests/fixtures/` through
`_datasets.py` instead of the live `data/`.

The fixtures and the goldens are a **matched pair**. Editing an input without
recapturing the goldens silently invalidates the oracle, and vice versa.

## Regeneration is not currently possible

The legacy analyzers referenced above have been deleted from the repository
(`refactor: remove legacy analyzers`). The goldens therefore cannot be
regenerated without first restoring that tooling. Until then, treat both
`tests/fixtures/` and `tests/golden/` as read-only: do not edit them casually.

Restoring the ability to recapture means, at minimum:

1. Restoring the legacy analyzer tooling that produced `tests/golden/*.csv`.
2. Refreshing `data/` from the ingestion job.
3. Re-running those analyzers to regenerate the goldens.
4. Copying the refreshed inputs byte-for-byte into this directory:

   ```sh
   cp data/ransom_dataset.csv data/vuln_dataset.csv data/mailsec_dataset.csv tests/fixtures/
   ```

5. Updating the capture date above and committing the snapshots together with
   the regenerated goldens.

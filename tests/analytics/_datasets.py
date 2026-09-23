"""Paths to the frozen dataset snapshots used by the analytics tests.

The files under ``tests/fixtures/`` are byte-for-byte copies of ``data/*.csv``
captured when the golden fixtures were generated. Tests load these instead of
the live ``data/`` files so a daily refresh of the production dataset cannot
invalidate the goldens. See ``tests/fixtures/README.md`` for provenance and
recapture steps.
"""

from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

RANSOM_CSV = FIXTURES_DIR / "ransom_dataset.csv"
VULN_CSV = FIXTURES_DIR / "vuln_dataset.csv"
MAILSEC_CSV = FIXTURES_DIR / "mailsec_dataset.csv"

"""Pure dataset helpers shared by the content pages (no Streamlit calls)."""

import pandas as pd

ALL_COLUMNS = "Todas as colunas"


def filter_dataset(data, column, query):
    """Case-insensitive literal text filter over one column or all of them."""
    if not query:
        return data
    if column == ALL_COLUMNS:
        mask = pd.Series(False, index=data.index)
        for name in data.columns:
            mask |= data[name].astype(str).str.contains(
                query, case=False, na=False, regex=False
            )
        return data[mask]
    return data[
        data[column].astype(str).str.contains(query, case=False, na=False, regex=False)
    ]

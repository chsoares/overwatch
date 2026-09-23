"""Minimal shared styling for the Streamlit app."""

import streamlit as st

_CSS = """
.block-container { max-width: 1200px; padding-top: 3rem; }
"""


def apply_app_styles():
    st.markdown(f"<style>{_CSS}</style>", unsafe_allow_html=True)

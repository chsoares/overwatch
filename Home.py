#!/usr/bin/env python3
"""Landing page for the overwatch application."""

import streamlit as st

from core.paths import PAGES_DIR, RESOURCES_DIR
from core.styles import apply_app_styles

st.set_page_config(
    page_title="overwatch",
    layout="centered",
)
st.logo(str(RESOURCES_DIR / "logo_text.png"), icon_image=str(RESOURCES_DIR / "logo_icon.png"))
apply_app_styles()

st.image(str(RESOURCES_DIR / "logo_text.png"), width=420)

home_path = PAGES_DIR / "home.md"
if not home_path.exists():
    st.error("Página não encontrada.")
    st.stop()
st.markdown(home_path.read_text(encoding="utf-8"), unsafe_allow_html=True)

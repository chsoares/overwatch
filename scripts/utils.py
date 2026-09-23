#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path


def find_project_root():
    """
    Encontra o diretório raiz do projeto procurando pelo arquivo Home.py
    """
    current_dir = Path.cwd()

    # Procurar Home.py subindo os diretórios
    while current_dir != current_dir.parent:
        if (current_dir / "Home.py").exists():
            return current_dir
        current_dir = current_dir.parent

    raise FileNotFoundError("Arquivo Home.py não encontrado na estrutura de diretórios")

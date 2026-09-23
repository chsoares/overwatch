#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para análise de segurança DNSSEC em domínios .gov.br.
Verifica configurações de DNSKEY e RRSIG para domínios com MX.
"""

# Bibliotecas padrão
import logging
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

# Adicionar diretório raiz ao PYTHONPATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Bibliotecas de DNS
import dns.exception
import dns.resolver
import pandas as pd

# Configurar logging
from core.settings import DATA_DIR
from scripts.logger_config import setup_logger

# Configuração do nível de log
LOG_LEVEL = "DEBUG"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Configuração do Logging
logger, console_handler = setup_logger("mailsec_dnssec", log_to_file=True)
console_handler.setLevel(getattr(logging, LOG_LEVEL))

# Suprimir warnings
warnings.filterwarnings("ignore")

# Caminho do CSV de entrada/saída
CSV_FILE_PATH = DATA_DIR / "mailsec_dataset.csv"

def check_dnssec(domain):
    """
    Verifica configuração DNSSEC do domínio.
    Faz uma query DNSKEY com want_dnssec=True para verificar se o domínio
    está realmente assinado com DNSSEC.
    
    Args:
        domain (str): Domínio a ser verificado
        
    Returns:
        bool: True se o domínio está assinado DNSSEC (tem tanto DNSKEY quanto RRSIG)
    """
    try:
        # Converter domínio para objeto dns.name
        name = dns.name.from_text(domain)
        
        # Criar query DNSKEY com want_dnssec=True
        request = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True)
        
        # Fazer a query usando Google DNS (8.8.8.8)
        try:
            response = dns.query.udp(request, '8.8.8.8', timeout=2)
        except Exception as e:
            # Tentar TCP como fallback
            try:
                response = dns.query.tcp(request, '8.8.8.8', timeout=2)
            except Exception:
                return False

        has_dnskey = False
        has_rrsig = False
        
        # Verificar se há DNSKEY e RRSIG na resposta
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                has_dnskey = True
            elif rrset.rdtype == dns.rdatatype.RRSIG:
                has_rrsig = True
        
        # Um domínio está assinado DNSSEC se tiver tanto DNSKEY quanto RRSIG
        DNSSEC_signed = has_dnskey and has_rrsig
        
        if DNSSEC_signed:
            logger.debug(f"DNSSEC: True")
        
        return DNSSEC_signed

    except Exception as e:
        logger.error(f"Erro ao verificar DNSSEC para {domain}: {e}")
        return False

def process_domains():
    """
    Processa a lista de domínios do CSV existente.
    Verifica DNSSEC apenas para domínios com MX=True.
    
    Returns:
        pandas.DataFrame: DataFrame atualizado com os resultados DNSSEC
    """
    try:
        # Carregar dataset existente
        logger.info(f"Carregando dataset de {CSV_FILE_PATH}")
        df = pd.read_csv(CSV_FILE_PATH)
        
        # Verificar se já existe a coluna DNSSEC
        if "DNSSEC_signed" in df.columns:
            logger.warning("Coluna DNSSEC_signed já existe no dataset. Será sobrescrita.")
        
        # Adicionar/atualizar coluna DNSSEC
        df["DNSSEC_signed"] = False
        
        # Filtrar domínios com MX
        mx_domains = df[df["MX_found"] == True]
        total_domains = len(mx_domains)
        logger.info(f"Verificando DNSSEC para {total_domains:,} domínios com MX...")
        
        # Processar cada domínio com MX
        for idx, row in mx_domains.iterrows():
            try:
                domain = row["domain"]
                logger.info(f"Processando domínio: {domain} [{idx:,}/{total_domains:,}]")
                
                # Verificar DNSSEC
                DNSSEC_signed = check_dnssec(domain)
                df.at[idx, "DNSSEC_signed"] = DNSSEC_signed
                
                # time.sleep(1)  # Delay para evitar sobrecarga
                
            except Exception as e:
                logger.error(f"Erro ao processar {domain}: {e}")
                continue
        
        # Gerar overview
        generate_overview(df)
        
        # Salvar dataset atualizado
        df.to_csv(CSV_FILE_PATH, index=False)
        logger.success(f"Dataset atualizado salvo em: {CSV_FILE_PATH}")
        
        return df
        
    except Exception as e:
        logger.error(f"Erro ao processar dataset: {e}")
        raise

def generate_overview(df):
    """
    Gera um overview dos resultados do processamento.
    
    Args:
        df (pandas.DataFrame): DataFrame com os resultados
    """
    total = len(df)
    if total == 0:
        logger.warning("Nenhum domínio processado")
        return
        
    # Calcular estatísticas
    mx_count = df["MX_found"].sum()
    dnssec_signed_count = df["DNSSEC_signed"].sum()
    
    # Gerar overview
    logger.analysis("=== Overview dos Resultados DNSSEC ===")
    logger.analysis(f"Total de domínios no dataset: {total}")
    logger.analysis(f"Com MX: {mx_count} ({mx_count/total*100:.1f}%)")
    logger.analysis(f"Assinados DNSSEC: {dnssec_signed_count} ({dnssec_signed_count/total*100:.1f}%)")
    logger.analysis("=====================================\n")

def main():
    """Função principal do script."""
    try:
        logger.success(f"Iniciando execução em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Processar domínios do dataset existente
        process_domains()
        
        logger.success(f"Execução finalizada em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except Exception as e:
        logger.error(f"Erro na execução: {e}")
        raise

if __name__ == "__main__":
    main() 
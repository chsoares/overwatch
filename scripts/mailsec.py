#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para análise de segurança de e-mail em domínios .gov.br.
Verifica configurações de SPF, DMARC e DKIM.
"""

# Bibliotecas padrão
import logging
import os
import shutil
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

# Adicionar diretório raiz ao PYTHONPATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Bibliotecas de dados
import dns.exception

# Bibliotecas de DNS
import dns.resolver
import numpy as np
import pandas as pd

# Configurar logging
from core.settings import DATA_DIR
from scripts.logger_config import setup_logger

# Configuração do nível de log
LOG_LEVEL = "DEBUG"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Configuração do Logging
logger, console_handler = setup_logger("mailsec", log_to_file=True)
console_handler.setLevel(getattr(logging, LOG_LEVEL))

# Suprimir warnings
warnings.filterwarnings("ignore")

# Caminho do CSV de saída
CSV_FILE_PATH = DATA_DIR / "mailsec_dataset.csv"

# URL do CSV oficial de domínios
DOMAINS_URL = "https://dominiosgovbr.sisp.gov.br/dados/dominios_gov_br.csv"

# Seletores DKIM comuns
DKIM_SELECTORS = [
    "selector1", "selector2", "default", "google", "mail",
    "dkim", "s1", "s2", "k1", "k2", "2023", "2024"
]

def load_domains():
    """
    Carrega a lista de domínios do CSV oficial.
    
    Returns:
        pandas.DataFrame: DataFrame com os domínios
    """
    try:
        logger.info("Carregando lista de domínios...")
        df = pd.read_csv(DOMAINS_URL, sep=";", encoding="utf-8")
        
        # Manter apenas a primeira coluna (domínios)
        df = df.iloc[:, 0].to_frame()
        df.columns = ["domain"]
        
        # Remover possíveis espaços
        df["domain"] = df["domain"].str.strip()
        
        return df
        
    except Exception as e:
        logger.error(f"Erro ao carregar domínios: {e}")
        raise

def check_mx(domain):
    """
    Verifica se o domínio possui registro MX.
    
    Args:
        domain (str): Domínio a ser verificado
        
    Returns:
        bool: True se encontrou MX, False caso contrário
    """
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return False

def check_spf(domain):
    """
    Verifica configuração SPF do domínio.
    
    Args:
        domain (str): Domínio a ser verificado
        
    Returns:
        tuple: (SPF, SPF_valid, SPF_secure)
            - SPF: conteúdo bruto do registro
            - SPF_valid: True se registro é válido
            - SPF_secure: True se termina com -all ou ~all
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_records = [str(r) for r in answers if str(r).startswith('"v=spf1')]
        
        if not spf_records:
            return "", False, False
            
        spf = spf_records[0].strip('"')
        spf_valid = spf.startswith("v=spf1")
        spf_secure = spf.endswith("-all") or spf.endswith("~all")
        
        return spf, spf_valid, spf_secure
        
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return "", False, False

def check_dmarc(domain):
    """
    Verifica configuração DMARC do domínio.
    
    Args:
        domain (str): Domínio a ser verificado
        
    Returns:
        tuple: (DMARC, DMARC_valid, dmarc_secure)
            - DMARC: conteúdo bruto do registro
            - dmarc_valid: True se contém v=DMARC1 e a tag p está presente
            - dmarc_secure: True se p (ou sp, se presente) não for none
    """
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        dmarc_records = [str(r) for r in answers if "v=DMARC1" in str(r)]
        
        if not dmarc_records:
            return "", False, False
            
        dmarc = dmarc_records[0].strip('"')
        dmarc_valid = "v=DMARC1" in dmarc and "p=" in dmarc
        
        # Verificar se p (ou sp, se presente) não é none
        dmarc_secure = False
        if dmarc_valid:
            # Extrair partes do DMARC de forma robusta
            parts = {}
            for part in [p.strip() for p in dmarc.split(";")]:
                if "=" in part:
                    key, value = part.split("=", 1)
                    parts[key.strip()] = value.strip()
            
            p_value = parts.get("p", "").strip()
            sp_value = parts.get("sp", p_value).strip()  # Se sp não existir, usa p
            dmarc_secure = p_value not in ["none", ""] or sp_value not in ["none", ""]
        
        return dmarc, dmarc_valid, dmarc_secure
        
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return "", False, False

def check_dkim(domain):
    """
    Verifica se o domínio possui configuração DKIM.
    Tenta diferentes seletores comuns e o nome do domínio.
    
    Args:
        domain (str): Domínio a ser verificado
        
    Returns:
        tuple: (DKIM, DKIM_valid, DKIM_selector)
            - DKIM: conteúdo bruto do registro DKIM encontrado (ou string vazia se não encontrado)
            - DKIM_valid: True se encontrou algum registro DKIM válido
            - DKIM_selector: seletor usado para encontrar o DKIM (ou string vazia se não encontrado)
    """
    # Adicionar o nome do domínio como seletor (sem .gov.br)
    domain_selector = domain.split('.')[0]
    selectors = [domain_selector] + DKIM_SELECTORS  # Testa primeiro o nome do domínio
    
    for selector in selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            # Retorna o primeiro registro DKIM encontrado
            dkim_record = str(answers[0]).strip('"')
            logger.debug(f"DKIM encontrado com seletor '{selector}'")
            return dkim_record, True, selector
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            continue
    return "", False, ""

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

def process_domain(domain):
    """
    Processa um domínio individual, realizando todas as verificações.
    
    Args:
        domain (str): Domínio a ser verificado
        
    Returns:
        dict: Resultados das verificações
    """
    # Verificar MX primeiro
    mx_found = check_mx(domain)
    
    # Se não tem MX, não precisa verificar os outros
    if not mx_found:
        return {
            "domain": domain,
            "MX_found": False,
            "SPF": "",
            "SPF_valid": False,
            "SPF_secure": False,
            "DMARC": "",
            "DMARC_valid": False,
            "DMARC_secure": False,
            "DKIM": "",
            "DKIM_selector": "",
            "DKIM_valid": False,
            "DNSSEC_signed": False
        }
    
    # Verificar SPF
    spf, spf_valid, spf_secure = check_spf(domain)
    if spf:
        logger.debug(f"SPF: {spf}")
    
    # Verificar DMARC
    dmarc, dmarc_valid, dmarc_secure = check_dmarc(domain)
    if dmarc:
        logger.debug(f"DMARC: {dmarc}")
    
    # Verificar DKIM
    dkim, dkim_valid, dkim_selector = check_dkim(domain)
    if dkim:
        logger.debug(f"DKIM: {dkim}")
    
    # Verificar DNSSEC
    DNSSEC_signed = check_dnssec(domain)
    
    return {
        "domain": domain,
        "MX_found": True,
        "SPF": spf,
        "SPF_valid": spf_valid,
        "SPF_secure": spf_secure,
        "DMARC": dmarc,
        "DMARC_valid": dmarc_valid,
        "DMARC_secure": dmarc_secure,
        "DKIM": dkim,
        "DKIM_selector": dkim_selector,
        "DKIM_valid": dkim_valid,
        "DNSSEC_signed": DNSSEC_signed
    }

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
    spf_valid = df["SPF_valid"].sum()
    spf_secure = df["SPF_secure"].sum()
    dmarc_valid = df["DMARC_valid"].sum()
    dmarc_secure = df["DMARC_secure"].sum()
    dkim_valid = df["DKIM_valid"].sum()
    dnssec_signed_count = df["DNSSEC_signed"].sum()
    
    # Gerar overview
    logger.analysis("=== Overview dos Resultados ===")
    logger.analysis(f"Total de domínios avaliados: {total}")
    logger.analysis(f"Com MX: {mx_count} ({mx_count/total*100:.1f}%)")
    logger.analysis(f"SPF válido: {spf_valid} ({spf_valid/total*100:.1f}%)")
    logger.analysis(f"SPF seguro: {spf_secure} ({spf_secure/total*100:.1f}%)")
    logger.analysis(f"DMARC válido: {dmarc_valid} ({dmarc_valid/total*100:.1f}%)")
    logger.analysis(f"DMARC seguro: {dmarc_secure} ({dmarc_secure/total*100:.1f}%)")
    logger.analysis(f"DKIM válido: {dkim_valid} ({dkim_valid/total*100:.1f}%)")
    logger.analysis(f"Assinados DNSSEC: {dnssec_signed_count} ({dnssec_signed_count/total*100:.1f}%)")
    logger.analysis("=============================\n")

def process_domains():
    """
    Processa a lista completa de domínios do CSV oficial.
    
    Returns:
        pandas.DataFrame: Resultados do processamento
    """
    # Carregar lista completa
    df_domains = load_domains()
    total_domains = len(df_domains)
    logger.info(f"Processando {total_domains:,} domínios...")
    
    results = []
    for idx, domain in enumerate(df_domains["domain"], 1):
        try:
            logger.info(f"Processando domínio: {domain} [{idx:,}/{total_domains:,}]")
            result = process_domain(domain)
            results.append(result)
            time.sleep(1)  # Delay para evitar sobrecarga
        except Exception as e:
            logger.error(f"Erro ao processar {domain}: {e}")
            continue
    
    df = pd.DataFrame(results)
    generate_overview(df)
    return df

def backup_existing_dataset():
    """
    Faz backup do dataset existente se ele existir.
    O backup é salvo em data/backups/mailsec_dataset_{timestamp}.csv
    """
    if CSV_FILE_PATH.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = DATA_DIR / "backups"
        backup_dir.mkdir(exist_ok=True)
        backup_path = backup_dir / f"mailsec_dataset_{timestamp}.csv"
        
        # Copiar arquivo usando operações básicas
        with open(CSV_FILE_PATH, 'r', encoding='utf-8') as src:
            with open(backup_path, 'w', encoding='utf-8') as dst:
                dst.write(src.read())
        
        logger.info(f"Backup do dataset existente criado em: {backup_path}")

def main():
    """Função principal do script."""
    try:
        logger.success(f"Iniciando execução em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Fazer backup do dataset existente se houver
        backup_existing_dataset()
        
        # Processar lista completa
        results = process_domains()
        
        # Salvar resultados
        os.makedirs(DATA_DIR, exist_ok=True)
        results.to_csv(CSV_FILE_PATH, index=False)
        logger.success(f"Resultados salvos em: {CSV_FILE_PATH}")
        
        logger.success(f"Execução finalizada em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except Exception as e:
        logger.error(f"Erro na execução: {e}")
        raise

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para análise de segurança de e-mail em domínios.
Verifica configurações de SPF, DMARC e DKIM.
Aceita domínio individual via -d ou lista de domínios via -f.
"""

# Bibliotecas padrão
import argparse
import logging
import re
import subprocess
import sys
import time
import warnings
from datetime import datetime
from functools import wraps
from pathlib import Path

# Adicionar diretório raiz ao PYTHONPATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Bibliotecas de DNS
import dns.exception
import dns.message
import dns.query
import dns.resolver

# Configurar logging
from scripts.logger_config import setup_logger
from scripts.utils import find_project_root

# Configuração do nível de log
LOG_LEVEL = "DEBUG"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Configuração do Logging
logger, console_handler = setup_logger("mailsec_tester", log_to_file=False)
console_handler.setLevel(getattr(logging, LOG_LEVEL))

# Suprimir warnings
warnings.filterwarnings("ignore")

# Configuração dos servidores DNS
DNS_SERVERS = [
    "8.8.8.8",    # Google DNS
    "8.8.4.4",    # Google DNS (backup)
    "1.1.1.1",    # Cloudflare
    "1.0.0.1",    # Cloudflare (backup)
    "9.9.9.9",    # Quad9
]

# Configurar o resolver do dnspython
resolver = dns.resolver.Resolver()
resolver.nameservers = DNS_SERVERS
resolver.timeout = 5.0  # timeout de 5 segundos
resolver.lifetime = 10.0  # tempo total máximo de 10 segundos

# Log dos servidores DNS configurados
logger.info(f"Servidores DNS configurados: {', '.join(DNS_SERVERS)}")

# Seletores DKIM comuns
DKIM_SELECTORS = [
    "selector1", "selector2", "default", "google", "mail",
    "dkim", "s1", "s2", "k1", "k2", "2023", "2024"
]

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Analisa configurações de segurança de e-mail em domínios.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Domínio individual para análise (ex: domain.gov.br)')
    group.add_argument('-f', '--file', help='Arquivo com lista de domínios (um por linha)')
    return parser.parse_args()

def load_domains(args):
    """
    Carrega a lista de domínios do argumento ou arquivo.
    
    Args:
        args: Argumentos da linha de comando
        
    Returns:
        list: Lista de domínios
    """
    domains = []
    
    if args.domain:
        domains.append(args.domain.strip())
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Erro ao ler arquivo de domínios: {e}")
            sys.exit(1)
    
    return domains

def with_retry_and_dig_fallback(func):
    """
    Decorator que adiciona retry e fallback com dig para funções de check DNS.
    Tenta a função original 3 vezes apenas em caso de timeout ou exceções inesperadas.
    Erros DNS esperados (NXDOMAIN, NoAnswer) não geram retry nem fallback.
    """
    @wraps(func)
    def wrapper(domain, *args, **kwargs):
        # Número de tentativas
        max_retries = 3
        retry_delay = 1  # segundos entre tentativas
        
        # Primeira tentativa
        try:
            return func(domain, *args, **kwargs)
        except dns.exception.Timeout as e:
            # Timeout na primeira tentativa, vamos tentar mais vezes
            logger.debug(f"Timeout ao consultar {domain}, tentando novamente...")
            for attempt in range(1, max_retries):
                time.sleep(retry_delay)
                try:
                    return func(domain, *args, **kwargs)
                except dns.exception.Timeout:
                    if attempt < max_retries - 1:
                        logger.debug(f"Timeout novamente, tentativa {attempt + 1}/{max_retries}...")
                    continue
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
                    # Erro DNS esperado, retorna sem mais tentativas
                    return get_empty_result(func.__name__)
                except Exception as e:
                    logger.debug(f"Erro inesperado: {str(e)}")
                    if attempt < max_retries - 1:
                        continue
            # Se chegou aqui, todas as tentativas falharam com timeout
            logger.debug(f"Todas as tentativas falharam com timeout para {domain}, tentando com dig...")
            return check_with_dig(domain, func.__name__, *args, **kwargs)
            
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
            # Erro DNS esperado, retorna sem retry
            return get_empty_result(func.__name__)
            
        except Exception as e:
            # Erro inesperado na primeira tentativa, vamos tentar mais vezes
            logger.debug(f"Erro inesperado ao consultar {domain}: {str(e)}, tentando novamente...")
            for attempt in range(1, max_retries):
                time.sleep(retry_delay)
                try:
                    return func(domain, *args, **kwargs)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    return get_empty_result(func.__name__)
                except Exception as e:
                    if attempt < max_retries - 1:
                        logger.debug(f"Erro persiste, tentativa {attempt + 1}/{max_retries}...")
                    continue
            # Se chegou aqui, todas as tentativas falharam com erro inesperado
            logger.debug(f"Todas as tentativas falharam para {domain}, tentando com dig...")
            return check_with_dig(domain, func.__name__, *args, **kwargs)
    
    return wrapper

def check_with_dig(domain, check_type, selector=None):
    """
    Função genérica para verificar registros DNS usando dig.
    
    Args:
        domain (str): Domínio a ser verificado
        check_type (str): Tipo de verificação ('mx', 'spf', 'dmarc', 'dkim')
        selector (str, optional): Seletor para DKIM
        
    Returns:
        tuple: Resultado apropriado para o tipo de check
    """
    try:
        if check_type == 'dkim' and selector:
            dkim_domain = f"{selector}._domainkey.{domain}"
            cmd = ["dig", "+short", "TXT", dkim_domain]
        elif check_type == 'dmarc':
            dmarc_domain = f"_dmarc.{domain}"
            cmd = ["dig", "+short", "TXT", dmarc_domain]
        else:
            cmd = ["dig", "+short", "TXT" if check_type in ['spf', 'dkim'] else "MX", domain]
        
        logger.debug(f"Tentando consulta com dig: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            logger.debug(f"Falha ao executar dig: {result.stderr}")
            return get_empty_result(check_type)
        
        output = result.stdout.strip()
        if not output:
            return get_empty_result(check_type)
        
        # Processar saída baseado no tipo de check
        if check_type == 'mx':
            return bool(output), None, None
        elif check_type == 'spf':
            spf_records = [r for r in output.split('\n') if r.startswith('"v=spf1')]
            if not spf_records:
                return "", False, False
            spf = spf_records[0].strip('"')
            return spf, spf.startswith("v=spf1"), spf.endswith("-all") or spf.endswith("~all")
        elif check_type == 'dmarc':
            dmarc_records = [r for r in output.split('\n') if "v=DMARC1" in r]
            if not dmarc_records:
                return "", False, False
            dmarc = dmarc_records[0].strip('"')
            dmarc_valid = "v=DMARC1" in dmarc and "p=" in dmarc
            parts = {}
            for part in [p.strip() for p in dmarc.split(";")]:
                if "=" in part:
                    key, value = part.split("=", 1)
                    parts[key.strip()] = value.strip()
            p_value = parts.get("p", "").strip()
            sp_value = parts.get("sp", p_value).strip()
            dmarc_secure = p_value not in ["none", ""] or sp_value not in ["none", ""]
            return dmarc, dmarc_valid, dmarc_secure
        elif check_type == 'dkim':
            dkim_record = "".join(re.findall(r'"([^"]*)"', output))
            if dkim_record and "v=DKIM1" in dkim_record:
                logger.debug(f"DKIM encontrado com dig usando seletor '{selector}'")
                return dkim_record, True, selector
            return "", False, ""
            
    except subprocess.TimeoutExpired:
        logger.debug(f"Timeout ao executar dig para {domain}")
    except Exception as e:
        logger.debug(f"Erro ao executar dig: {str(e)}")
    
    return get_empty_result(check_type)

def get_empty_result(check_type):
    """Retorna o resultado vazio apropriado para cada tipo de check."""
    if check_type == 'mx':
        return False, None, None
    elif check_type == 'spf':
        return "", False, False
    elif check_type == 'dmarc':
        return "", False, False
    elif check_type == 'dkim':
        return "", False, ""

@with_retry_and_dig_fallback
def check_mx(domain):
    """
    Verifica se o domínio possui registro MX.
    
    Args:
        domain (str): Domínio a ser verificado
        
    Returns:
        tuple: (mx_found, None, None)
            - mx_found: True se encontrou MX, False caso contrário
    """
    logger.debug(f"Verificando MX para {domain}")
    answers = resolver.resolve(domain, "MX")
    mx_records = [str(r.exchange) for r in answers]
    logger.debug(f"Registros MX encontrados: {', '.join(mx_records)}")
    return True, None, None

@with_retry_and_dig_fallback
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
    logger.debug(f"Verificando SPF para {domain}")
    answers = resolver.resolve(domain, "TXT")
    spf_records = [str(r) for r in answers if str(r).startswith('"v=spf1')]
    
    if not spf_records:
        logger.debug(f"Nenhum registro SPF encontrado para {domain}")
        return "", False, False
        
    spf = spf_records[0].strip('"')
    spf_valid = spf.startswith("v=spf1")
    spf_secure = spf.endswith("-all") or spf.endswith("~all")
    
    logger.debug(f"SPF encontrado: {spf} (válido: {spf_valid}, seguro: {spf_secure})")
    return spf, spf_valid, spf_secure

@with_retry_and_dig_fallback
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
    dmarc_domain = f"_dmarc.{domain}"
    logger.debug(f"Verificando DMARC para {dmarc_domain}")
    
    answers = resolver.resolve(dmarc_domain, "TXT")
    dmarc_records = [str(r) for r in answers if "v=DMARC1" in str(r)]
    
    if not dmarc_records:
        logger.debug(f"Nenhum registro DMARC encontrado para {domain}")
        return "", False, False
        
    dmarc = dmarc_records[0].strip('"')
    dmarc_valid = "v=DMARC1" in dmarc and "p=" in dmarc
    
    # Verificar se p (ou sp, se presente) não é none
    dmarc_secure = False
    if dmarc_valid:
        parts = {}
        for part in [p.strip() for p in dmarc.split(";")]:
            if "=" in part:
                key, value = part.split("=", 1)
                parts[key.strip()] = value.strip()
        
        p_value = parts.get("p", "").strip()
        sp_value = parts.get("sp", p_value).strip()
        dmarc_secure = p_value not in ["none", ""] or sp_value not in ["none", ""]
    
    logger.debug(f"DMARC encontrado: {dmarc} (válido: {dmarc_valid}, seguro: {dmarc_secure})")
    return dmarc, dmarc_valid, dmarc_secure

def check_dkim(domain):
    """
    Verifica se o domínio possui configuração DKIM.
    Tenta diferentes seletores comuns e o nome do domínio.
    
    Args:
        domain (str): Domínio a ser verificado
        
    Returns:
        tuple: (DKIM, DKIM_valid, selector)
            - DKIM: conteúdo bruto do registro DKIM encontrado (ou string vazia se não encontrado)
            - DKIM_valid: True se encontrou algum registro DKIM válido
            - selector: seletor utilizado (ou string vazia se não encontrado)
    """
    # Adicionar o nome do domínio como seletor (sem .gov.br)
    domain_selector = domain.split('.')[0]
    selectors = [domain_selector] + DKIM_SELECTORS  # Testa primeiro o nome do domínio
    
    for selector in selectors:
        try:
            # Usar o decorator para este seletor específico
            @with_retry_and_dig_fallback
            def check_single_dkim(domain, selector):
                answers = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                dkim_record = str(answers[0]).strip('"')
                if dkim_record and "v=DKIM1" in dkim_record:
                    logger.debug(f"DKIM encontrado com seletor '{selector}'")
                return dkim_record, True, selector
            
            result = check_single_dkim(domain, selector)
            if result[1]:  # Se DKIM válido
                return result
                
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Erro DNS esperado, continua para o próximo seletor
            continue
        except Exception as e:
            # Erro inesperado, continua
            continue
            
    logger.debug(f"Nenhum registro DKIM encontrado para {domain}")
    return "", False, ""

def process_domain(domain):
    """
    Processa um domínio individual e imprime os resultados.
    
    Args:
        domain (str): Domínio a ser verificado
    """
    print(f"\n=== Análise de {domain} ===")
    
    # Verificar MX primeiro
    mx_found, _, _ = check_mx(domain)
    print(f"MX: {'✓' if mx_found else '✗'}")
    
    if not mx_found:
        print("Domínio não possui registro MX. Pulando outras verificações.")
        return
    
    # Verificar SPF
    spf, spf_valid, spf_secure = check_spf(domain)
    print("\nSPF:")
    print(f"Registro: {spf if spf else 'Não encontrado'}")
    print(f"Válido: {'✓' if spf_valid else '✗'}")
    print(f"Seguro: {'✓' if spf_secure else '✗'}")
    
    # Verificar DMARC
    dmarc, dmarc_valid, dmarc_secure = check_dmarc(domain)
    print("\nDMARC:")
    print(f"Registro: {dmarc if dmarc else 'Não encontrado'}")
    print(f"Válido: {'✓' if dmarc_valid else '✗'}")
    print(f"Seguro: {'✓' if dmarc_secure else '✗'}")
    
    # Verificar DKIM
    dkim, dkim_valid, selector = check_dkim(domain)
    print("\nDKIM:")
    print(f"Registro: {dkim if dkim else 'Não encontrado'}")
    print(f"Seletor: {selector if selector else 'Não encontrado'}")
    print(f"Válido: {'✓' if dkim_valid else '✗'}")
    
    print("\n" + "=" * (len(domain) + 12))

def main():
    """Função principal do script."""
    try:
        args = parse_args()
        domains = load_domains(args)
        
        print(f"Iniciando análise em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total de domínios a processar: {len(domains)}")
        
        for domain in domains:
            try:
                process_domain(domain)
                time.sleep(1)  # Delay para evitar sobrecarga
            except Exception as e:
                logger.error(f"Erro ao processar {domain}: {e}")
                continue
        
        print(f"\nAnálise finalizada em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except Exception as e:
        logger.error(f"Erro na execução: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para coleta e análise de vulnerabilidades do KEV (Known Exploited Vulnerabilities).
Integra dados de múltiplas fontes: CISA KEV, NVD (CVSS), First (EPSS), GitHub e ExploitDB.
Suporta processamento em lotes para grandes volumes de dados.
"""

import argparse
import io
import logging
import math
import os
import sys
import time
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from time import sleep
from typing import List, Optional, Tuple

import cve_searchsploit as ss
import nvdlib
import pandas as pd
import requests
from dotenv import load_dotenv

# Configurar imports baseado em como o script é executado
if __name__ == "__main__":
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    from scripts.logger_config import setup_logger
else:
    from .logger_config import setup_logger

from core.settings import DATA_DIR

# Configuração do nível de log
LOG_LEVEL = "DEBUG"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Janela padrão (em meses) do modo --recent. Antes era configurável via
# config.yaml (check_recent_months), que foi removido; mantemos o default.
CHECK_RECENT_MONTHS = 6

# Configuração do Logging
logger, console_handler = setup_logger("vuln_ingestor", log_to_file=True)
console_handler.setLevel(getattr(logging, LOG_LEVEL))  # Aplica o nível configurado

# Carregar variáveis de ambiente
load_dotenv(override=True)

class VulnIngestor:
    """
    Gerencia a coleta e processamento de dados de vulnerabilidades.
    Integra dados do KEV com informações adicionais de CVSS, EPSS e exploits.
    """

    def __init__(self):
        """Inicializa o ingestor de vulnerabilidades."""
        self.logger = logger

        # Configurar caminhos
        self.data_path = DATA_DIR
        self.csv_path = self.data_path / "vuln_dataset.csv"
        
        # Configurar APIs
        self.nvd_key = os.getenv("NVD_API_KEY")
        self.github_token = os.getenv("GITHUB_TOKEN")
        
        # Atualizar base de exploits
        self._update_exploitdb()

    def _update_exploitdb(self):
        """Atualiza a base de dados do ExploitDB."""
        try:
            with redirect_stdout(io.StringIO()):
                self.logger.info("Atualizando base de exploits...")
                ss.update_db()
            self.logger.success("Base de exploits atualizada com sucesso!")
        except Exception as e:
            self.logger.warning(f"ExploitDB não disponível ({str(e)})")
            self.logger.warning("Continuando sem verificação do ExploitDB...")
            
            # Sobrescrever função check_exploitdb para sempre retornar 'No' durante os testes
            def check_exploitdb(cve_id):
                self.logger.debug(f"{cve_id}: Não (ExploitDB indisponível no Windows)")
                return 'No'
            
            self.check_exploitdb = check_exploitdb

    def process_kev_data(self) -> pd.DataFrame:
        """
        Processa os dados do KEV (Known Exploited Vulnerabilities).
        
        Returns:
            pandas.DataFrame: DataFrame processado com os dados do KEV
        """
        self.logger.analysis("Iniciando coleta de dados do KEV")
        
        url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        response = requests.get(url)
        data = response.json()
        
        # Criar DataFrame inicial
        kev_df = pd.DataFrame(data['vulnerabilities'])
        
        # Processar datas
        kev_df['dateAdded'] = pd.to_datetime(kev_df['dateAdded'], format='%Y-%m-%d')
        kev_df['dueDate'] = pd.to_datetime(kev_df['dueDate'], format='%Y-%m-%d')
        
        # Selecionar e renomear colunas
        kev_df = kev_df[['cveID', 'dateAdded', 'vendorProject', 'product', 'knownRansomwareCampaignUse']]
        kev_df.rename(columns={'knownRansomwareCampaignUse': 'ransomCampaign'}, inplace=True)
        
        self.logger.success(f"Dados do KEV processados: {len(kev_df)} vulnerabilidades")
        return kev_df.sort_values(by='dateAdded')

    def check_cvss(self, cve_id: str) -> Optional[float]:
        """
        Verifica o CVSS Score de uma vulnerabilidade.
        
        Args:
            cve_id: ID da vulnerabilidade
            
        Returns:
            float: CVSS score ou None em caso de erro
        """
        MAX_RETRIES = 5
        fail_count = 0
        
        while fail_count < MAX_RETRIES:
            try:
                cvss = nvdlib.searchCVE(cveId=cve_id, key=self.nvd_key, delay=1)[0].score
                score = cvss[1]
                severity = cvss[2]
                self.logger.debug(f"{cve_id}: {severity} ({score})")
                return score
            except Exception:
                self.logger.warning(f"{cve_id} falhou. Tentando novamente... ({fail_count + 1}/{MAX_RETRIES})")
                fail_count += 1
                sleep(3 ** fail_count)  # Delay exponencial
        
        self.logger.error(f"{cve_id} falhou {MAX_RETRIES} vezes. Pulando...")
        return None

    def check_epss(self, cve_id: str) -> Optional[float]:
        """
        Verifica o EPSS Score de uma vulnerabilidade.
        
        Args:
            cve_id: ID da vulnerabilidade
            
        Returns:
            float: EPSS score ou None em caso de erro
        """
        try:
            url = f'https://api.first.org/data/v1/epss?cve={cve_id}'
            response = requests.get(url)
            data = response.json()['data'][0]['epss']
            score = float(data)
            self.logger.debug(f"{cve_id}: {score*100:.1f}%")
            return score
        except Exception as e:
            self.logger.error(f"Erro ao verificar EPSS para {cve_id}: {str(e)}")
            return None

    def check_exploitdb(self, cve_id: str) -> str:
        """
        Verifica a existência de exploits no ExploitDB.
        
        Args:
            cve_id: ID da vulnerabilidade
            
        Returns:
            str: 'Yes' se encontrado, 'No' caso contrário
        """
        data = ss.edbid_from_cve(cve_id)
        if bool(data):
            self.logger.debug(f"{cve_id}: Sim (ExploitDB - IDs: {', '.join(map(str, data))})")
            return 'Yes'
        self.logger.debug(f"{cve_id}: Não (ExploitDB)")
        return 'No'

    def check_github(self, cve_id: str) -> Optional[str]:
        """
        Verifica a existência de exploits no GitHub.
        
        Args:
            cve_id: ID da vulnerabilidade
            
        Returns:
            str: 'Yes' se encontrado, 'No' caso contrário, None em caso de erro
        """
        github_search = f"https://api.github.com/search/repositories?q={cve_id}"
        headers = {"Authorization": f"token {self.github_token}"}
        
        while True:
            try:
                response = requests.get(github_search, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    if data['total_count'] > 0:
                        self.logger.debug(f"{cve_id}: Sim (Github - Total: {data['total_count']})")
                        return 'Yes'
                    self.logger.debug(f"{cve_id}: Não (GitHub)")
                    return 'No'
                    
                if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
                    remaining = int(response.headers['X-RateLimit-Remaining'])
                    reset_time = int(response.headers['X-RateLimit-Reset'])
                    current_time = time.time()
                    
                    if remaining == 0:
                        delay = max(1, reset_time - current_time + 1)
                        self.logger.warning(f"Limite de requisições atingido em {cve_id}. Aguardando {delay:.0f} segundos.")
                        sleep(delay)
                        continue
                
                if response.status_code in [500, 502, 503, 504]:
                    self.logger.warning(f"Erro do servidor GitHub ({response.status_code}). Aguardando 30 segundos...")
                    sleep(30)
                    continue
                    
                self.logger.warning(f"{cve_id}: Status: {response.status_code} (GitHub)")
                return None
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Erro na requisição para {cve_id}: {str(e)}")
                return None

    def calculate_risk(self, cvss: Optional[float], epss: Optional[float]) -> Optional[str]:
        """
        Calcula o nível de risco baseado nos scores CVSS e EPSS.
        
        Args:
            cvss: CVSS Score
            epss: EPSS Score
        
        Returns:
            str: Nível de risco (Critical, High, Medium, Low) ou None se algum score for None
        """
        if cvss is None or epss is None:
            self.logger.debug(f"Risco não calculado: CVSS={cvss}, EPSS={epss} (valores incompletos)")
            return None
            
        if cvss >= 9 and epss >= 0.9:
            risk = "Critical"
        elif cvss >= 5 and epss >= 0.5:
            risk = "High"
        elif cvss >= 5 or epss >= 0.5:
            risk = "Medium"
        else:
            risk = "Low"
        
        self.logger.debug(f"Risco calculado: CVSS={cvss}, EPSS={epss:.1%} -> {risk}")
        return risk

    def update_vulnerability_data(self, check_mode: str, batch_size: int = 0) -> pd.DataFrame:
        """
        Atualiza os dados de vulnerabilidades com informações adicionais.
        
        Args:
            check_mode: Modo de verificação ("all", "recent", "new")
            batch_size: Tamanho do lote para processamento (0 = processar tudo de uma vez)
            
        Returns:
            pd.DataFrame: Dataset atualizado
        """
        # 1. Processar dados do KEV
        kev_df = self.process_kev_data()
        
        # 2. Carregar ou criar dataset
        self.logger.analysis("Filtrando registros...")

        if self.csv_path.exists():
            vuln_df = pd.read_csv(self.csv_path)
            # Converter a coluna dateAdded para datetime
            vuln_df['dateAdded'] = pd.to_datetime(vuln_df['dateAdded'])
            
            # Determinar quais registros processar baseado no modo
            if check_mode == "all":
                # Processa todos os registros existentes + novos
                new_records = kev_df[~kev_df['cveID'].isin(vuln_df['cveID'])]
                records_to_process = vuln_df.copy()  # Processa todo o dataset existente
            elif check_mode == "recent":
                # Processa registros recentes (últimos X meses)
                months = CHECK_RECENT_MONTHS
                recent_date = datetime.now() - pd.Timedelta(days=months * 30)  # Aproximação de 30 dias por mês
                recent_date = pd.Timestamp(recent_date)
                new_records = kev_df[~kev_df['cveID'].isin(vuln_df['cveID'])]
                records_to_process = vuln_df[vuln_df['dateAdded'] >= recent_date]
            else:  # "new"
                # Processa apenas registros novos
                new_records = kev_df[~kev_df['cveID'].isin(vuln_df['cveID'])]
                records_to_process = pd.DataFrame()  # Não processa registros existentes
            
            if not new_records.empty:
                # Garantir que todas as colunas necessárias existam nos novos registros
                for col in ['cvss', 'epss', 'exploit', 'risk']:
                    if col not in new_records.columns:
                        new_records[col] = None
                
                self.logger.info(f"Adicionados {len(new_records)} novos registros.")
                # Debug dos novos registros
                for _, row in new_records.iterrows():
                    self.logger.debug(f"Novo registro: {row['cveID']} - {row['vendorProject']} {row['product']}")
                
                # Adicionar novos registros à lista de processamento
                if records_to_process.empty:
                    records_to_process = new_records
                else:
                    records_to_process = pd.concat([records_to_process, new_records])
            else:
                self.logger.info("Nenhum novo registro encontrado.")
                
            # Adicionar registros com valores None à lista de processamento
            failed_records = vuln_df[
                (vuln_df['cvss'].isna() | 
                vuln_df['epss'].isna() | 
                vuln_df['exploit'].isna() | 
                vuln_df['risk'].isna())
            ]
            
            if not failed_records.empty:
                self.logger.info(f"Encontrados {len(failed_records)} registros com dados incompletos.")
                for _, row in failed_records.iterrows():
                    missing = []
                    if pd.isna(row['cvss']): missing.append('CVSS')
                    if pd.isna(row['epss']): missing.append('EPSS')
                    if pd.isna(row['exploit']): missing.append('Exploit')
                    if pd.isna(row['risk']): missing.append('Risk')
                    self.logger.debug(f"Registro incompleto: {row['cveID']} - Faltando: {', '.join(missing)}")
                
                # Adicionar registros incompletos à lista de processamento
                if records_to_process.empty:
                    records_to_process = failed_records
                else:
                    # Garantir que não haja duplicatas
                    records_to_process = pd.concat([records_to_process, failed_records]).drop_duplicates(subset=['cveID'])
        else:
            # Se não existe dataset, cria novo com os dados do KEV
            # Garantir que todas as colunas necessárias existam
            vuln_df = kev_df.copy()
            for col in ['cvss', 'epss', 'exploit', 'risk']:
                if col not in vuln_df.columns:
                    vuln_df[col] = None
            
            records_to_process = vuln_df.copy()
            self.logger.info(f"Novo dataset criado com {len(vuln_df)} registros.")
        
        # Verificar se há registros para processar
        if records_to_process.empty:
            self.logger.info("Nenhum registro para processar.")
            return vuln_df
        
        # Ordenar registros por data (do mais antigo para o mais recente)
        records_to_process = records_to_process.sort_values(by='dateAdded', ascending=True)
        self.logger.info(f"Registros ordenados por data (do mais antigo para o mais recente)")
        
        # Processar registros em lotes ou todos de uma vez
        if batch_size > 0:
            self.logger.analysis(f"Iniciando processamento em lotes de {batch_size} registros...")
            
            # Separar novos registros do dataset principal para processamento em lotes
            existing_records = vuln_df.copy()
            new_records_to_add = pd.DataFrame()
            
            # Identificar registros que não estão no dataset principal
            new_records_mask = ~records_to_process['cveID'].isin(existing_records['cveID'])
            if new_records_mask.any():
                new_records_to_add = records_to_process[new_records_mask].copy()
                # Remover novos registros da lista de processamento (serão adicionados por lote)
                records_to_process = records_to_process[~new_records_mask].copy()
                
                # Garantir que novos registros estejam ordenados por data
                new_records_to_add = new_records_to_add.sort_values(by='dateAdded', ascending=True)
            
            # Dividir em lotes
            total_records = len(records_to_process) + len(new_records_to_add)
            num_batches = math.ceil(total_records / batch_size)
            
            self.logger.info(f"Total de {total_records} registros a processar em {num_batches} lotes")
            
            # Processar cada lote de registros existentes
            if not records_to_process.empty:
                self.logger.info(f"Processando {len(records_to_process)} registros existentes")
                
                # Garantir que registros existentes estejam ordenados por data
                records_to_process = records_to_process.sort_values(by='dateAdded', ascending=True)
                
                # Dividir registros existentes em lotes
                existing_batches = math.ceil(len(records_to_process) / batch_size)
                for batch_num in range(existing_batches):
                    start_idx = batch_num * batch_size
                    end_idx = min((batch_num + 1) * batch_size, len(records_to_process))
                    
                    batch_df = records_to_process.iloc[start_idx:end_idx].copy()
                    
                    self.logger.info(f"Processando lote {batch_num + 1}/{num_batches} ({len(batch_df)} registros existentes)")
                    start_time = datetime.now()
                    
                    try:
                        # 1. Atualizar CVSS
                        self.logger.info("Verificando CVSS...")
                        for idx, row in batch_df.iterrows():
                            cve_id = row['cveID']
                            if pd.isna(row['cvss']):
                                cvss_score = self.check_cvss(cve_id)
                                # Atualizar no DataFrame principal
                                existing_records.loc[existing_records['cveID'] == cve_id, 'cvss'] = cvss_score
                        
                        # 2. Atualizar EPSS
                        self.logger.info("Verificando EPSS...")
                        for idx, row in batch_df.iterrows():
                            cve_id = row['cveID']
                            # No modo all ou recent, sempre atualiza o EPSS
                            if check_mode in ["all", "recent"] or pd.isna(row['epss']):
                                epss_score = self.check_epss(cve_id)
                                # Atualizar no DataFrame principal
                                existing_records.loc[existing_records['cveID'] == cve_id, 'epss'] = epss_score
                        
                        # 3. Verificar exploits
                        self.logger.info("Verificando exploits...")
                        for idx, row in batch_df.iterrows():
                            cve_id = row['cveID']
                            # No modo all ou recent, verificar todos os registros com exploit = 'No' ou None
                            if check_mode in ["all", "recent"] and row['exploit'] == 'Yes':
                                continue  # Pula se já tem exploit = 'Yes' e não estamos no modo all/recent
                            
                            if pd.isna(row['exploit']) or row['exploit'] == 'No':
                                # Checa ExploitDB primeiro
                                result_exploitdb = self.check_exploitdb(cve_id)
                                if result_exploitdb == 'Yes':
                                    existing_records.loc[existing_records['cveID'] == cve_id, 'exploit'] = 'Yes'
                                    continue  # Pula GitHub se ExploitDB já retornou 'Yes'

                                # Caso contrário, checa GitHub
                                result_github = self.check_github(cve_id)
                                existing_records.loc[existing_records['cveID'] == cve_id, 'exploit'] = 'Yes' if result_github == 'Yes' else 'No'
                        
                        # 4. Calcular Risco
                        self.logger.info("Calculando níveis de risco...")
                        for idx, row in batch_df.iterrows():
                            cve_id = row['cveID']
                            # No modo all ou recent, sempre recalcula o risco
                            if check_mode in ["all", "recent"] or pd.isna(row['risk']):
                                # Obter valores atualizados de CVSS e EPSS
                                updated_row = existing_records[existing_records['cveID'] == cve_id].iloc[0]
                                risk = self.calculate_risk(updated_row['cvss'], updated_row['epss'])
                                existing_records.loc[existing_records['cveID'] == cve_id, 'risk'] = risk
                        
                        # Reordenar por dateAdded
                        existing_records['dateAdded'] = pd.to_datetime(existing_records['dateAdded'])
                        existing_records = existing_records.sort_values(by='dateAdded', ascending=True)
                        
                        # Reordenar colunas
                        columns_order = ['cveID', 'dateAdded', 'vendorProject', 'product', 
                                        'cvss', 'epss', 'risk', 'exploit', 'ransomCampaign']
                        existing_records = existing_records[columns_order]
                        
                        # Salvar após cada lote
                        existing_records.to_csv(self.csv_path, index=False)
                        
                        end_time = datetime.now()
                        duration = (end_time - start_time).total_seconds()
                        self.logger.success(f"Lote {batch_num + 1} concluído em {duration:.1f} segundos")
                        
                        # Estimar tempo restante
                        if batch_num < num_batches - 1:
                            remaining_batches = num_batches - (batch_num + 1)
                            est_remaining_time = remaining_batches * duration
                            self.logger.info(f"Tempo estimado restante: {est_remaining_time/60:.1f} minutos")
                        
                    except Exception as e:
                        self.logger.error(f"Erro ao processar lote {batch_num + 1}: {str(e)}")
                        # Continuar com o próximo lote mesmo em caso de erro
            
            # Processar cada lote de novos registros
            if not new_records_to_add.empty:
                self.logger.info(f"Processando {len(new_records_to_add)} novos registros")
                
                # Dividir novos registros em lotes
                new_batches = math.ceil(len(new_records_to_add) / batch_size)
                for batch_num in range(new_batches):
                    start_idx = batch_num * batch_size
                    end_idx = min((batch_num + 1) * batch_size, len(new_records_to_add))
                    
                    batch_df = new_records_to_add.iloc[start_idx:end_idx].copy()
                    
                    batch_num_overall = batch_num + (0 if records_to_process.empty else existing_batches)
                    self.logger.info(f"Processando lote {batch_num_overall + 1}/{num_batches} ({len(batch_df)} novos registros)")
                    start_time = datetime.now()
                    
                    try:
                        # 1. Atualizar CVSS
                        self.logger.info("Verificando CVSS...")
                        for idx, row in batch_df.iterrows():
                            cve_id = row['cveID']
                            if pd.isna(row['cvss']):
                                cvss_score = self.check_cvss(cve_id)
                                # Atualizar no lote
                                batch_df.loc[batch_df['cveID'] == cve_id, 'cvss'] = cvss_score
                        
                        # 2. Atualizar EPSS
                        self.logger.info("Verificando EPSS...")
                        for idx, row in batch_df.iterrows():
                            cve_id = row['cveID']
                            # No modo all ou recent, sempre atualiza o EPSS
                            if check_mode in ["all", "recent"] or pd.isna(row['epss']):
                                epss_score = self.check_epss(cve_id)
                                # Atualizar no lote
                                batch_df.loc[batch_df['cveID'] == cve_id, 'epss'] = epss_score
                        
                        # 3. Verificar exploits
                        self.logger.info("Verificando exploits...")
                        for idx, row in batch_df.iterrows():
                            cve_id = row['cveID']
                            # No modo all ou recent, verificar todos os registros com exploit = 'No' ou None
                            if check_mode in ["all", "recent"] and row['exploit'] == 'Yes':
                                continue  # Pula se já tem exploit = 'Yes' e não estamos no modo all/recent
                            
                            if pd.isna(row['exploit']) or row['exploit'] == 'No':
                                # Checa ExploitDB primeiro
                                result_exploitdb = self.check_exploitdb(cve_id)
                                if result_exploitdb == 'Yes':
                                    batch_df.loc[batch_df['cveID'] == cve_id, 'exploit'] = 'Yes'
                                    continue  # Pula GitHub se ExploitDB já retornou 'Yes'

                                # Caso contrário, checa GitHub
                                result_github = self.check_github(cve_id)
                                batch_df.loc[batch_df['cveID'] == cve_id, 'exploit'] = 'Yes' if result_github == 'Yes' else 'No'
                        
                        # 4. Calcular Risco
                        self.logger.info("Calculando níveis de risco...")
                        for idx, row in batch_df.iterrows():
                            cve_id = row['cveID']
                            # No modo all ou recent, sempre recalcula o risco
                            if check_mode in ["all", "recent"] or pd.isna(row['risk']):
                                # Obter valores atualizados de CVSS e EPSS do lote
                                updated_row = batch_df[batch_df['cveID'] == cve_id].iloc[0]
                                risk = self.calculate_risk(updated_row['cvss'], updated_row['epss'])
                                batch_df.loc[batch_df['cveID'] == cve_id, 'risk'] = risk
                        
                        # Adicionar o lote processado ao dataset principal
                        existing_records = pd.concat([existing_records, batch_df]).reset_index(drop=True)
                        
                        # Reordenar por dateAdded
                        existing_records['dateAdded'] = pd.to_datetime(existing_records['dateAdded'])
                        existing_records = existing_records.sort_values(by='dateAdded', ascending=True)
                        
                        # Reordenar colunas
                        columns_order = ['cveID', 'dateAdded', 'vendorProject', 'product', 
                                        'cvss', 'epss', 'risk', 'exploit', 'ransomCampaign']
                        existing_records = existing_records[columns_order]
                        
                        # Salvar após cada lote
                        existing_records.to_csv(self.csv_path, index=False)
                        
                        end_time = datetime.now()
                        duration = (end_time - start_time).total_seconds()
                        self.logger.success(f"Lote {batch_num_overall + 1} concluído em {duration:.1f} segundos")
                        
                        # Estimar tempo restante
                        if batch_num_overall < num_batches - 1:
                            remaining_batches = num_batches - (batch_num_overall + 1)
                            est_remaining_time = remaining_batches * duration
                            self.logger.info(f"Tempo estimado restante: {est_remaining_time/60:.1f} minutos")
                        
                    except Exception as e:
                        self.logger.error(f"Erro ao processar lote {batch_num_overall + 1}: {str(e)}")
                        # Continuar com o próximo lote mesmo em caso de erro
            
            # Atualizar o DataFrame principal com todos os registros processados
            vuln_df = existing_records.copy()
            
            self.logger.success(f"Processamento em lotes concluído. Total de {num_batches} lotes processados.")
            
        else:
            # Processamento tradicional (todos de uma vez)
            self.logger.analysis("Iniciando enriquecimento de dados...")
            
            # Adicionar novos registros ao dataset principal
            new_records_mask = ~records_to_process['cveID'].isin(vuln_df['cveID'])
            if new_records_mask.any():
                new_records_to_add = records_to_process[new_records_mask].copy()
                vuln_df = pd.concat([vuln_df, new_records_to_add]).reset_index(drop=True)
            
            # Garantir que os registros a processar estejam ordenados por data
            records_to_process = records_to_process.sort_values(by='dateAdded', ascending=True)
            self.logger.info(f"Registros ordenados por data (do mais antigo para o mais recente)")
            
            # Atualizar CVSS
            self.logger.info("Verificando CVSS...")
            empty_cvss = vuln_df['cvss'].isna()
            if empty_cvss.any():
                # Processar registros com CVSS vazio em ordem cronológica
                cvss_records = vuln_df[empty_cvss].sort_values(by='dateAdded', ascending=True)
                for idx, row in cvss_records.iterrows():
                    cve_id = row['cveID']
                    cvss_score = self.check_cvss(cve_id)
                    vuln_df.loc[vuln_df['cveID'] == cve_id, 'cvss'] = cvss_score
            
            # Atualizar EPSS
            self.logger.info("Verificando EPSS...")
            if not records_to_process.empty:
                # Para --all e --recent, devemos verificar todos os registros em records_to_process
                # independentemente se já têm valores
                records_to_update = records_to_process.sort_values(by='dateAdded', ascending=True)
                for _, row in records_to_update.iterrows():
                    cve_id = row['cveID']
                    # No modo all ou recent, sempre atualiza o EPSS
                    if check_mode in ["all", "recent"] or pd.isna(vuln_df.loc[vuln_df['cveID'] == cve_id, 'epss'].values[0]):
                        epss_score = self.check_epss(cve_id)
                        vuln_df.loc[vuln_df['cveID'] == cve_id, 'epss'] = epss_score
            
            # Verificar exploits
            self.logger.info("Verificando exploits...")
            if not records_to_process.empty:
                # Para --all e --recent, verificar todos os registros com exploit = 'No' ou None
                # Para --new, verificar apenas novos registros
                if check_mode in ["all", "recent"]:
                    exploit_records = records_to_process[
                        (records_to_process['exploit'].isna()) | 
                        (records_to_process['exploit'] == 'No')
                    ]
                else:
                    exploit_records = records_to_process[
                        (records_to_process['cveID'].isin(vuln_df[
                            (vuln_df['exploit'].isna()) | 
                            (vuln_df['exploit'] == 'No')
                        ]['cveID'])) |
                        (~records_to_process['cveID'].isin(vuln_df['cveID']))  # Inclui novos registros
                    ]
                
                # Processar em ordem cronológica
                exploit_records = exploit_records.sort_values(by='dateAdded', ascending=True)
                for _, row in exploit_records.iterrows():
                    cve_id = row['cveID']
                    idx = vuln_df[vuln_df['cveID'] == cve_id].index[0]
                    
                    # Checa ExploitDB primeiro
                    result_exploitdb = self.check_exploitdb(cve_id)
                    if result_exploitdb == 'Yes':
                        vuln_df.at[idx, 'exploit'] = 'Yes'
                        continue  # Pula GitHub se ExploitDB já retornou 'Yes'

                    # Caso contrário, checa GitHub
                    result_github = self.check_github(cve_id)
                    vuln_df.at[idx, 'exploit'] = 'Yes' if result_github == 'Yes' else 'No'
            
            # Calcular Risco
            self.logger.analysis("Calculando níveis de risco...")
            if not records_to_process.empty:
                # Para --all e --recent, recalcular o risco para todos os registros em records_to_process
                # Para --new, calcular apenas para registros novos ou com valores ausentes
                if check_mode in ["all", "recent"]:
                    risk_records = vuln_df[vuln_df['cveID'].isin(records_to_process['cveID'])].sort_values(by='dateAdded', ascending=True)
                else:
                    risk_records = vuln_df[
                        (vuln_df['cveID'].isin(records_to_process['cveID'])) & 
                        (vuln_df['risk'].isna())
                    ].sort_values(by='dateAdded', ascending=True)
                
                for idx, row in risk_records.iterrows():
                    risk = self.calculate_risk(row['cvss'], row['epss'])
                    vuln_df.loc[idx, 'risk'] = risk
            
            # Reordenar por dateAdded
            vuln_df['dateAdded'] = pd.to_datetime(vuln_df['dateAdded']).dt.date
            vuln_df = vuln_df.sort_values(by='dateAdded', ascending=True)
            
            # Reordenar colunas
            columns_order = ['cveID', 'dateAdded', 'vendorProject', 'product', 
                            'cvss', 'epss', 'risk', 'exploit', 'ransomCampaign']
            vuln_df = vuln_df[columns_order]
            
            # Salvar dataset
            vuln_df.to_csv(self.csv_path, index=False)
            self.logger.success("Atualização de dados concluída!")
        
        return vuln_df

if __name__ == "__main__":
    # Configurar argumentos
    parser = argparse.ArgumentParser(description="Atualiza dataset de vulnerabilidades do KEV")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--all",
        action="store_true",
        help="Verifica todas as entradas novamente"
    )
    group.add_argument(
        "--recent",
        action="store_true",
        help="Verifica apenas entradas dos últimos X meses"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=0,
        help="Processa os dados em lotes do tamanho especificado (0 = processar tudo de uma vez)"
    )
    args = parser.parse_args()
    
    logger.success(f"Iniciando execução em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        ingestor = VulnIngestor()
        
        # Determinar modo de verificação
        if args.all:
            check_mode = "all"
        elif args.recent:
            check_mode = "recent"
        else:
            check_mode = "new"
            
        logger.info(f"Modo de verificação: --{check_mode}")
        
        # Verificar se o processamento em lotes está ativado
        if args.batch_size > 0:
            logger.info(f"Processamento em lotes ativado: {args.batch_size} registros por lote")
        
        ingestor.update_vulnerability_data(check_mode=check_mode, batch_size=args.batch_size)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro na conexão com API: {str(e)}")
    except pd.errors.EmptyDataError:
        logger.error("Erro: Dataset vazio ou corrompido")
    except Exception as e:
        logger.error(f"Erro inesperado: {str(e)}")
    
    logger.info(f"Execução finalizada em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    sys.exit(0) 
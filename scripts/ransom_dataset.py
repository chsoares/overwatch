#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para coleta e análise de dados sobre ataques ransomware.
Integra dados da API ransomware.live com análises adicionais.
"""

import json
import logging
import os
import sys
import warnings
from datetime import datetime
from pathlib import Path
from time import sleep

import pandas as pd
import requests

# Configurar imports baseado em como o script é executado
if __name__ == "__main__":
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    from scripts.logger_config import log_exception, setup_logger
    from scripts.sector_classifier import SectorClassifier, SystemicClassifierError
    from scripts.web_extractor import WebContentExtractor
else:
    from .logger_config import log_exception, setup_logger
    from .sector_classifier import SectorClassifier, SystemicClassifierError
    from .web_extractor import WebContentExtractor

from core.settings import DATA_DIR, RESOURCES_DIR, classifier_enabled

warnings.filterwarnings("ignore")

# Configuração do nível de log
LOG_LEVEL = "DEBUG"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Configuração do Logging
logger, console_handler = setup_logger("ransom_ingestor", log_to_file=True)
console_handler.setLevel(getattr(logging, LOG_LEVEL))  # Aplica o nível configurado


class RansomIngestor:
    """
    Classe principal para ingestão de dados de ransomware.
    Gerencia a coleta, processamento e persistência dos dados.
    """

    def __init__(self):
        """Inicializa o ingestor com configurações do projeto."""

        logger.success(
            f"Execução inicializada em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        try:
            # Métricas de classificação
            self.classification_start_time = None
            self.classification_total_time = 0.0
            self.classification_total_cost = 0.0

            # Configurar caminhos
            data_dir = DATA_DIR
            resources_dir = RESOURCES_DIR

            # Paths específicos
            self.csv_path = data_dir / "ransom_dataset.csv"
            self.sectors_file = resources_dir / "sectors.json"
            self.mapping_file = resources_dir / "sectors_mapping.json"
            self.iso_file = resources_dir / "iso.json"

            # Carregar mapeamento de setores
            with open(self.mapping_file, "r", encoding="utf-8") as f:
                self.sectors_mapping = json.load(f)

            # Carregar códigos ISO válidos
            with open(self.iso_file, "r", encoding="utf-8") as f:
                iso_data = json.load(f)
                self.valid_iso2_codes = {
                    country["ISO2"].strip() for country in iso_data
                }
                logger.debug(
                    f"Carregados {len(self.valid_iso2_codes)} códigos ISO2 válidos"
                )

            # Configurar API
            self.api_base_url = "https://api.ransomware.live/v2/victims"
            self.max_retries = 3
            self.retry_delay = 2

            # Mapeamento de colunas API v2 para formato antigo
            self.api_v2_column_mapping = {
                "victim": "post_title",
                "country": "country",
                "domain": "website",
                "group": "group_name",
                "activity": "activity",
                "attackdate": "published",
                "discovered": "discovered",
                "screenshot": "screenshot",
                "claim_url": "post_url",
            }

            # Colunas do dataset
            self.base_columns = [
                "post_title",
                "country",
                "website",
                "group_name",
                "activity",
                "published",
                "discovered",
                "screenshot",
                "post_url",
            ]
            self.columns = self.base_columns[:]  # Copia a lista
            # Inserir activity_classified e used_fallback após activity
            activity_index = self.columns.index("activity")
            self.columns.insert(activity_index + 1, "activity_classified")
            self.columns.insert(activity_index + 2, "used_fallback")

            # Inicializar classificador e extrator (classificador é opcional)
            self.classifier = None
            if classifier_enabled():
                try:
                    self.classifier = SectorClassifier(self.sectors_file)
                    logger.debug("Classificador de setores inicializado com sucesso")
                except SystemicClassifierError as e:
                    logger.warning(
                        f"Classificador de setores indisponível ({str(e)}). "
                        "Usando fallback baseado na coluna activity."
                    )
                    self.classifier = None
            else:
                logger.info(
                    "Classificador de setores desabilitado (sem chave OpenRouter). "
                    "Usando fallback baseado na coluna activity."
                )

            self.extractor = WebContentExtractor()
            logger.debug("Ingestor inicializado com sucesso")
            logger.debug(
                f"Mapeamento de setores carregado: {len(self.sectors_mapping)} setores"
            )

        except Exception as e:
            logger.error(f"Erro ao inicializar ingestor: {str(e)}")
            raise

    def _map_sector(self, original_sector: str) -> str:
        """
        Mapeia o setor original para nosso padrão de classificação.

        Args:
            original_sector: Setor original da fonte

        Returns:
            Setor mapeado ou setor original se não houver mapeamento
        """
        try:
            # Tratar caso especial de Not Found
            if not original_sector or original_sector == "Not Found":
                return "Not Found"

            # Tentar encontrar mapeamento direto
            if original_sector in self.sectors_mapping:
                mapped = self.sectors_mapping[original_sector]
                return mapped

            # Se não encontrar, tentar normalizar e procurar novamente
            normalized = original_sector.strip().lower()
            for source, target in self.sectors_mapping.items():
                if source.lower() == normalized:
                    return target

            # Se não encontrar mapeamento, retornar original
            logger.warning(f"Setor sem mapeamento: {original_sector}")
            return original_sector

        except Exception as e:
            logger.error(f"Erro ao mapear setor {original_sector}: {str(e)}")
            return original_sector

    def _classify_sector(self, row: pd.Series) -> tuple[str, bool]:
        """
        Classifica o setor de uma empresa com fallback para valor mapeado.
        Tenta extrair conteúdo do website antes de classificar.
        Se a extração falhar, usa o valor mapeado da coluna activity.

        Args:
            row: Linha do DataFrame com dados da empresa

        Returns:
            Tupla com (classificação do setor, flag indicando se usou fallback)
        """
        try:
            # Sem classificador não há por que buscar conteúdo na web
            if self.classifier is None:
                mapped_sector = self._map_sector(row["activity"])
                logger.debug(
                    f"Classificador desabilitado; usando fallback para "
                    f"{row['website']}: {row['activity']} -> {mapped_sector}"
                )
                return mapped_sector, True  # Usou fallback

            # Tentar extrair conteúdo do website
            website_content = None
            if row["website"]:
                try:
                    website_content = self.extractor.extract_content(row["website"])
                except Exception as e:
                    logger.debug(f"Falha na extração para {row['website']}: {str(e)}")

            # Se conseguiu extrair conteúdo, tentar classificar
            if website_content:
                try:
                    result = self.classifier.classify_content(
                        content=website_content, company_name=row["post_title"]
                    )
                    if result:
                        return result, False  # Não usou fallback
                except SystemicClassifierError:
                    raise  # Re-lança erros sistêmicos
                except Exception as e:
                    logger.error(f"Erro na classificação de {row['website']}: {str(e)}")

            # Se não conseguiu extrair conteúdo ou classificar, usar fallback
            mapped_sector = self._map_sector(row["activity"])
            logger.debug(
                f"Usando fallback para {row['website']}: {row['activity']} -> {mapped_sector}"
            )
            return mapped_sector, True  # Usou fallback

        except SystemicClassifierError:
            raise  # Re-lança erros sistêmicos
        except Exception as e:
            logger.error(f"Erro ao processar {row['website']}: {str(e)}")
            mapped_sector = self._map_sector(row["activity"])
            return mapped_sector, True  # Usou fallback

    def _log_classification_metrics(self, df: pd.DataFrame):
        """
        Loga métricas sobre a classificação e mapeamento.

        Métricas principais:
        - Classificados com sucesso: registros onde a extração web e classificação funcionou
        - Fallbacks: registros onde precisamos usar o valor da coluna activity
        - Diferentes da fonte: registros onde nossa classificação difere da original
        - Setores não mapeados: valores originais que não têm mapeamento no nosso padrão
        - Tempo e custo: métricas de performance e custo do processo
        """
        total = len(df)

        try:
            # Garantir que a coluna used_fallback existe e é booleana
            if "used_fallback" not in df.columns:
                logger.warning("Coluna used_fallback não encontrada no DataFrame")
                return

            df["used_fallback"] = df["used_fallback"].fillna(True).astype(bool)

            # Identificar registros que foram classificados com sucesso vs fallbacks
            fallbacks = df[df["used_fallback"]]["website"].tolist()
            classified_success = df[~df["used_fallback"]]["website"].tolist()

            # Identificar classificações diferentes da fonte
            different_from_source = []
            unmapped_sectors = set()

            for _, row in df.iterrows():
                # Ignorar casos onde o original é Not Found
                if row["activity"] == "Not Found":
                    continue

                # Mapear o setor original para comparação
                original_mapped = self._map_sector(row["activity"])

                # Verificar se a classificação é diferente da fonte (considerando o mapeamento)
                if row["activity_classified"] != original_mapped:
                    different_from_source.append(
                        {
                            "website": row["website"],
                            "nossa_classificacao": row["activity_classified"],
                            "classificacao_fonte": row["activity"],
                        }
                    )

                # Verificar se o valor original está no nosso mapeamento
                if row["activity"] not in self.sectors_mapping:
                    unmapped_sectors.add(row["activity"])

            # Calcular métricas
            total_classified = len(classified_success)
            total_fallbacks = len(fallbacks)
            total_different = len(different_from_source)

            # Log das métricas principais
            logger.success("Classificação concluída!")
            logger.analysis("Resumo da classificação:")
            logger.info(f"- Total de registros: {total}")
            logger.info(
                f"- Classificados com sucesso: {total_classified} ({(total_classified/total)*100:.1f}%)"
            )
            logger.info(
                f"- Usando fallback: {total_fallbacks} ({(total_fallbacks/total)*100:.1f}%)"
            )
            logger.info(
                f"- Diferentes da fonte: {total_different} ({(total_different/total)*100:.1f}%)"
            )

            # Log de métricas de performance e custo
            if self.classification_total_time > 0:
                logger.analysis("Métricas de performance:")
                logger.info(f"- Tempo total: {self.classification_total_time:.2f}s")
                logger.info(
                    f"- Tempo médio: {(self.classification_total_time/total):.2f}s por registro"
                )
                logger.info(f"- Custo total: ${self.classification_total_cost:.4f}")
                logger.info(
                    f"- Custo médio: ${(self.classification_total_cost/total):.4f} por registro"
                )

            # Log detalhado de setores não mapeados
            if unmapped_sectors:
                logger.analysis(
                    f"Encontrados {len(unmapped_sectors)} setores sem mapeamento:"
                )
                for sector in sorted(unmapped_sectors):
                    logger.warning(f"- {sector}")

            # Log detalhado de classificações diferentes
            if different_from_source:
                logger.analysis(
                    f"Detalhes das {len(different_from_source)} classificações diferentes:"
                )
                for diff in different_from_source:
                    logger.info(
                        f"- {diff['website']}: {diff['classificacao_fonte']} -> {diff['nossa_classificacao']}"
                    )

        except Exception as e:
            logger.error(f"Erro ao calcular métricas de classificação: {str(e)}")
            # Não propagar o erro para permitir que o processo continue

    @staticmethod
    def _to_naive_utc(series: pd.Series) -> pd.Series:
        """
        Normaliza timestamps para datetime64[ns] naive em UTC.

        A API v2 retorna datas ISO-8601 com offset UTC (ex.:
        "2026-02-28T21:02:36.060651+00:00"), o que produz dtype tz-aware
        e quebra comparações com Timestamps naive. Valores naive são
        interpretados como UTC, preservando o wall-clock existente.
        """
        return pd.to_datetime(series, errors="coerce", utc=True).dt.tz_localize(None)

    def _transform_api_v2_response(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transforma a resposta da API v2 para o formato esperado pelo código.

        Args:
            df: DataFrame com dados brutos da API v2

        Returns:
            DataFrame com colunas renomeadas para o formato antigo
        """
        if df.empty:
            return df

        try:
            # Renomear colunas de acordo com o mapeamento
            df_renamed = df.rename(columns=self.api_v2_column_mapping)

            # Garantir que todas as colunas base existem
            for col in self.base_columns:
                if col not in df_renamed.columns:
                    df_renamed[col] = ""

            # Selecionar apenas as colunas base na ordem correta
            df_renamed = df_renamed[self.base_columns]

            logger.debug(f"Dados da API v2 transformados: {len(df_renamed)} registros")
            return df_renamed

        except Exception as e:
            logger.error(f"Erro ao transformar dados da API v2: {str(e)}")
            raise

    def process_victims_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aplica tratamentos padronizados aos dados de vítimas.

        Args:
            df: DataFrame com dados brutos da API

        Returns:
            DataFrame processado e limpo
        """
        if df.empty:
            logger.warning("DataFrame vazio recebido para processamento")
            return df

        logger.debug("Iniciando tratamento dos dados")

        try:
            # Verificar colunas necessárias (apenas colunas base)
            missing_cols = [col for col in self.base_columns if col not in df.columns]
            if missing_cols:
                logger.warning(f"Colunas ausentes nos dados: {missing_cols}")
                for col in missing_cols:
                    df[col] = ""

            # Substituir NaN por string vazia
            df = df.replace({pd.NA: "", pd.NaT: "", None: ""})

            # Tratar valores vazios na coluna activity
            df["activity"] = df["activity"].replace({"": "Not Found"})

            # Normalizar código do país (UK -> GB)
            df["country"] = df["country"].replace({"UK": "GB"})

            # Validar e limpar códigos de país inválidos
            df["country"] = df["country"].apply(
                lambda x: x if x in self.valid_iso2_codes else ""
            )

            # Normalizar nome Lockbit (lockbit* -> lockbit)
            df["group_name"] = df["group_name"].str.replace(r"^lockbit\d*$", "lockbit", regex=True)

            # Normalizar websites
            # 1. Copiar post_title para website se vazio
            mask_website_vazio = ~df["website"].notna() | (df["website"] == "")
            df.loc[mask_website_vazio, "website"] = df.loc[mask_website_vazio, "post_title"]
            
            # 2. Aplicar normalizações
            df["website"] = (df["website"]
                           .str.lower()
                           .str.replace("www.", "")
                           .str.replace("https://", "")
                           .str.replace("http://", "")
                           .str.rstrip("/"))

            # Remover espaços extras
            for col in ["post_title", "website", "group_name"]:
                df[col] = df[col].str.strip()

            # Normalizar datas (sempre naive em UTC)
            for col in ["published", "discovered"]:
                df[col] = self._to_naive_utc(df[col])

            # Remover registros com datas inválidas
            valid_dates_mask = df["discovered"].notna() & df["published"].notna()
            invalid_dates = sum(~valid_dates_mask)
            if invalid_dates > 0:
                logger.warning(
                    f"Removidos {invalid_dates} registros com datas inválidas"
                )

            df = df[valid_dates_mask]

            # Remover registros anteriores a 2023
            data_limite = pd.to_datetime("2023-01-01")
            registros_antigos = df[df["published"] < data_limite]
            if not registros_antigos.empty:
                logger.warning(
                    f"Removidos {len(registros_antigos)} registros anteriores a 2023"
                )
            df = df[df["published"] >= data_limite]

            return df

        except Exception as e:
            logger.error(f"Erro no processamento dos dados: {str(e)}")
            raise

    def classify_sectors(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Classifica os setores para registros que ainda não foram classificados.

        Args:
            df: DataFrame com registros a serem classificados

        Returns:
            DataFrame com setores classificados

        Raises:
            SystemicClassifierError: Se houver um erro sistêmico no classificador
        """
        try:
            # Garantir que as colunas necessárias existem
            if "activity_classified" not in df.columns:
                df["activity_classified"] = ""
            if "used_fallback" not in df.columns:
                df["used_fallback"] = False

            # Identificar registros não classificados
            unclassified = df["activity_classified"].isna() | (
                df["activity_classified"] == ""
            )
            records_to_classify = df[unclassified]

            if not records_to_classify.empty:
                logger.analysis("Iniciando classificação de setor")
                logger.info(
                    f"Total de registros para classificar: {len(records_to_classify)}"
                )

                # Iniciar contagem de tempo e custo
                self.classification_start_time = datetime.now()
                initial_cost = (
                    self.classifier.api_client.total_cost if self.classifier else 0.0
                )

                # Classificar apenas registros necessários
                total_records = len(records_to_classify)
                for idx, (index, row) in enumerate(records_to_classify.iterrows(), 1):
                    try:
                        logger.analysis(
                            f"Processando: {row['post_title']} [{idx}/{total_records}]"
                        )
                        classification, used_fallback = self._classify_sector(row)

                        # Atualizar valores usando o índice original do DataFrame
                        df.loc[index, "activity_classified"] = classification
                        df.loc[index, "used_fallback"] = used_fallback

                        if used_fallback:
                            logger.warning(
                                f"{row['post_title']} classificado usando fallback: {classification}"
                            )
                        else:
                            logger.success(
                                f"{row['post_title']} classificado com sucesso: {classification}"
                            )
                    except SystemicClassifierError:
                        raise  # Re-lança erros sistêmicos para interromper todo o processo
                    except Exception as e:
                        logger.error(
                            f"Erro ao classificar {row['post_title']}: {str(e)}"
                        )
                        # Para erros não-sistêmicos, continua com próximo registro

                # Calcular tempo e custo total
                self.classification_total_time = (
                    datetime.now() - self.classification_start_time
                ).total_seconds()
                self.classification_total_cost = (
                    self.classifier.api_client.total_cost - initial_cost
                    if self.classifier
                    else 0.0
                )

                # Log das métricas de classificação
                self._log_classification_metrics(df)

            return df

        except SystemicClassifierError:
            raise  # Re-lança erros sistêmicos para interromper todo o processo
        except Exception as e:
            logger.error(f"Erro na classificação em lote: {str(e)}")
            return df  # Retorna DataFrame mesmo com erro não-sistêmico

    def get_monthly_data(self, year: int, month: int) -> pd.DataFrame:
        """
        Obtém dados de um mês específico da API ransomware.live.

        Args:
            year: Ano dos dados
            month: Mês dos dados

        Returns:
            DataFrame com os dados do mês processados
        """
        logger.analysis(f"Coletando dados de {month:02d}/{year}")

        url = f"{self.api_base_url}/{year}/{month}"

        for attempt in range(self.max_retries):
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    month_data = pd.read_json(response.text)
                    logger.debug(f"Dados coletados: {len(month_data)} registros")

                    # Transformar dados da API v2 para formato antigo
                    month_data = self._transform_api_v2_response(month_data)

                    # Aplicar tratamentos
                    month_data = self.process_victims_data(month_data)
                    logger.info(f"Após tratamento: {len(month_data)} registros válidos")

                    return month_data
                else:
                    logger.error(f"Erro {response.status_code} ao acessar a API")
                    if attempt < self.max_retries - 1:
                        sleep_time = self.retry_delay * (
                            2**attempt
                        )  # Exponential backoff
                        logger.debug(f"Tentando novamente em {sleep_time} segundos...")
                        sleep(sleep_time)
                    continue

            except Exception as e:
                logger.error(f"Erro ao coletar dados: {str(e)}")
                if attempt < self.max_retries - 1:
                    sleep_time = self.retry_delay * (2**attempt)
                    logger.debug(f"Tentando novamente em {sleep_time} segundos...")
                    sleep(sleep_time)
                continue

        logger.error("Todas as tentativas de coleta falharam")
        return pd.DataFrame()

    def get_missing_months_data(self, last_date: datetime) -> pd.DataFrame:
        """
        Obtém dados de todos os meses entre a última data no dataset e o mês atual.

        Args:
            last_date: Última data presente no dataset

        Returns:
            DataFrame com dados de todos os meses faltantes
        """
        current_date = datetime.now()
        all_data = pd.DataFrame()

        # Começar do mês da última data conhecida
        current_month = last_date.replace(day=1)

        # Enquanto não chegamos ao mês atual
        while current_month <= current_date:
            # Coletar dados do mês
            month_data = self.get_monthly_data(current_month.year, current_month.month)

            if not month_data.empty:
                all_data = pd.concat([all_data, month_data], ignore_index=True)

            # Avançar para o próximo mês
            if current_month.month == 12:
                current_month = current_month.replace(
                    year=current_month.year + 1, month=1
                )
            else:
                current_month = current_month.replace(month=current_month.month + 1)

            sleep(1)  # Delay para evitar sobrecarga da API

        return all_data

    def update_ransom_data(
        self, ransom_df: pd.DataFrame, check_all: bool = False
    ) -> pd.DataFrame:
        """
        Atualiza o dataset com novos registros da API.

        Args:
            ransom_df: Dataset atual
            check_all: Se True, verifica todos os registros novamente

        Returns:
            Dataset atualizado
        """
        try:
            # Converter discovered para datetime
            ransom_df["discovered"] = self._to_naive_utc(ransom_df["discovered"])

            # Ordenar por discovered
            ransom_df = ransom_df.sort_values("discovered", ascending=True)

            # Obter último timestamp
            last_discovered = ransom_df["discovered"].max()
            logger.analysis(
                f"Iniciando atualização do dataset a partir de {last_discovered.strftime('%Y-%m-%d %H:%M:%S')}"
            )

            # Obter dados de todos os meses faltantes
            new_data = self.get_missing_months_data(last_discovered)

            if new_data.empty:
                logger.info("Nenhum dado novo encontrado na API")
                return ransom_df

            # Converter discovered dos novos dados
            new_data["discovered"] = self._to_naive_utc(new_data["discovered"])

            # Identificar registros novos
            new_records = new_data[new_data["discovered"] >= last_discovered]

            if new_records.empty:
                logger.info("Nenhum registro novo encontrado")
                return ransom_df

            # Verificar duplicatas nos novos registros
            duplicates = new_records[
                new_records.duplicated(subset=["website", "group_name"], keep=False)
            ]

            if not duplicates.empty:
                # Contar duplicatas únicas (por website/grupo)
                unique_duplicates = duplicates.groupby(["website", "group_name"]).size()
                logger.analysis(
                    f"Encontradas {len(unique_duplicates)} duplicatas nos novos registros:"
                )

                for (website, group), group_df in duplicates.groupby(
                    ["website", "group_name"]
                ):
                    logger.info(f"Website: {website} | Grupo: {group}")
                    for _, row in group_df.iterrows():
                        logger.debug(
                            f"- {row['post_title']} [Discovered: {row['discovered']}]"
                        )

            # Remover duplicatas dos novos registros
            new_records = new_records.drop_duplicates(
                subset=["website", "group_name"], keep="first"
            )

            # Verificar duplicatas com registros existentes
            existing_pairs = set(zip(ransom_df["website"], ransom_df["group_name"]))
            duplicate_mask = new_records.apply(
                lambda x: (x["website"], x["group_name"]) in existing_pairs, axis=1
            )

            if duplicate_mask.any():
                logger.analysis(
                    f"Encontrados {sum(duplicate_mask)} registros já existentes no dataset:"
                )
                for _, row in new_records[duplicate_mask].iterrows():
                    logger.debug(f"- {row['post_title']} [Grupo: {row['group_name']}]")

                new_records = new_records[~duplicate_mask]

            if new_records.empty:
                logger.info("Nenhum registro novo após remoção de duplicatas")
                return ransom_df

            # Log de novos registros
            logger.analysis(
                f"Adicionando {len(new_records)} novos registros ao dataset:"
            )
            for _, row in new_records.iterrows():
                logger.debug(f"- {row['post_title']} [Grupo: {row['group_name']}]")

            # Classificar setores apenas para os novos registros
            new_records = self.classify_sectors(new_records)

            # Adicionar novos registros já classificados
            ransom_df = pd.concat([ransom_df, new_records]).reset_index(drop=True)

            # Ordenar e garantir colunas
            ransom_df = ransom_df.sort_values("discovered", ascending=True)
            ransom_df = ransom_df[self.columns]

            # Log final
            logger.analysis("Atualização concluída:")
            logger.info(f"- Total de registros: {len(ransom_df):,}")
            logger.info(f"- Novos registros: {len(new_records):,}")
            logger.info(
                f"- Período: {ransom_df['discovered'].min().strftime('%Y-%m-%d')} a {ransom_df['discovered'].max().strftime('%Y-%m-%d')}"
            )

            return ransom_df

        except Exception as e:
            logger.error(f"Erro ao atualizar dataset: {str(e)}")
            raise

    def _finalize_regenerated_data(self, all_data: pd.DataFrame) -> pd.DataFrame:
        """
        Classifica, ordena e aplica o schema final aos dados regenerados.

        Args:
            all_data: DataFrame completo coletado e tratado

        Returns:
            DataFrame regenerado com as colunas de classificação e o schema final
        """
        all_data["published"] = self._to_naive_utc(all_data["published"])
        all_data["discovered"] = self._to_naive_utc(all_data["discovered"])
        all_data = self.classify_sectors(all_data)
        all_data = all_data.sort_values("discovered", ascending=True)
        all_data = all_data[self.columns]
        return all_data

    def regenerate_dataset(self) -> pd.DataFrame:
        """
        Regenera o dataset completo a partir de janeiro de 2023.

        Returns:
            Dataset completo regenerado e processado
        """
        logger.info("Iniciando regeneração completa do dataset")
        logger.info("Coletando dados de 01/2023 até o presente")

        all_data = pd.DataFrame()
        current_date = datetime.now()

        try:
            # Loop através dos anos
            for year in range(2023, current_date.year + 1):
                # Determinar último mês
                last_month = 12 if year < current_date.year else current_date.month

                for month in range(1, last_month + 1):
                    logger.info(f"Processando {month:02d}/{year}")
                    url = f"{self.api_base_url}/{year}/{month}"

                    for attempt in range(self.max_retries):
                        try:
                            response = requests.get(url)
                            if response.status_code == 200:
                                month_data = pd.read_json(response.text)
                                logger.info(f"Coletados {len(month_data)} registros")

                                # Transformar dados da API v2 para formato antigo
                                month_data = self._transform_api_v2_response(month_data)

                                # Aplicar tratamentos
                                month_data = self.process_victims_data(month_data)
                                logger.info(
                                    f"Após tratamento: {len(month_data)} registros"
                                )

                                all_data = pd.concat(
                                    [all_data, month_data], ignore_index=True
                                )
                                break
                            else:
                                logger.error(
                                    f"Erro {response.status_code} ao acessar a API"
                                )
                                if attempt < self.max_retries - 1:
                                    sleep_time = self.retry_delay * (2**attempt)
                                    logger.info(
                                        f"Tentando novamente em {sleep_time} segundos..."
                                    )
                                    sleep(sleep_time)
                                continue

                        except Exception as e:
                            logger.error(f"Erro ao processar {month}/{year}: {str(e)}")
                            if attempt < self.max_retries - 1:
                                sleep_time = self.retry_delay * (2**attempt)
                                logger.info(
                                    f"Tentando novamente em {sleep_time} segundos..."
                                )
                                sleep(sleep_time)
                            continue

                    sleep(1)  # Delay para evitar sobrecarga da API

            if all_data.empty:
                raise Exception(
                    "Não foi possível regenerar o dataset - nenhum dado coletado"
                )

            # Processar dataset completo
            all_data = self._finalize_regenerated_data(all_data)

            logger.info("Dataset regenerado com sucesso:")
            logger.info(f"Total de registros: {len(all_data)}")
            logger.info(
                f"Período: de {all_data['discovered'].min().strftime('%Y-%m-%d')} "
                f"até {all_data['discovered'].max().strftime('%Y-%m-%d')}"
            )

            return all_data

        except Exception as e:
            logger.error(f"Erro ao regenerar dataset: {str(e)}")
            raise

    def run(self):
        """Executa o processo de atualização do dataset."""
        try:
            # Garantir que o diretório existe
            os.makedirs(os.path.dirname(self.csv_path), exist_ok=True)

            # Carregar ou criar dataset
            if os.path.exists(self.csv_path):
                ransom_df = pd.read_csv(self.csv_path)
                initial_records = len(ransom_df)
                logger.info(f"Dataset carregado com {initial_records:,} registros")

                # Atualizar dados
                ransom_df = self.update_ransom_data(ransom_df, check_all=False)

                # Salvar dataset
                ransom_df.to_csv(self.csv_path, index=False)
                logger.info(f"Dataset salvo em: {self.csv_path}")
                logger.info(
                    f"Registros no dataset: {initial_records:,} → {len(ransom_df):,} "
                    f"({len(ransom_df) - initial_records:+,})"
                )

            else:
                logger.warning("Dataset não encontrado")
                logger.info("Iniciando processo de regeneração...")
                ransom_df = self.regenerate_dataset()

                # Salvar dataset regenerado
                ransom_df.to_csv(self.csv_path, index=False)
                logger.info(f"Dataset inicial salvo em: {self.csv_path}")
                logger.info(f"Total de registros: {len(ransom_df):,}")

            logger.success(
                f"Execução finalizada em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )

        except Exception:
            log_exception(logger)
            raise


if __name__ == "__main__":
    try:
        ingestor = RansomIngestor()
        ingestor.run()
    except Exception:
        log_exception(logger)
        sys.exit(1)

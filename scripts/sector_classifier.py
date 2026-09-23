import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from time import sleep
from typing import Dict, List, Optional

import requests
from dotenv import load_dotenv

# Configurar imports baseado em como o script é executado
if __name__ == "__main__":
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    from scripts.logger_config import setup_logger
else:
    from .logger_config import setup_logger

# Configuração do nível de log
LOG_LEVEL = "DEBUG"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Configuração do Logging
logger, console_handler = setup_logger("sector_classifier", log_to_file=True)
console_handler.setLevel(getattr(logging, LOG_LEVEL))  # Aplica o nível configurado

# Carregar variáveis de ambiente
load_dotenv()

class SystemicClassifierError(Exception):
    """Erro sistêmico que impede o funcionamento do classificador."""
    pass

class OpenRouterClient:
    """
    Cliente para gerenciar comunicação com a API do OpenRouter.
    Lida com autenticação, retry logic e rate limiting.
    """

    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        self.base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        self.model = os.getenv("OPENROUTER_MODEL", "google/gemini-2.5-flash-lite")
        self.max_retries = int(os.getenv("MAX_RETRIES", 3))
        self.retry_delay = int(os.getenv("RETRY_DELAY", 2))
        self.cost_per_request = 0.0001  # Custo estimado por request em USD
        self.total_requests = 0
        self.total_cost = 0.0

        if not self.api_key:
            raise SystemicClassifierError("OpenRouter API key not found in environment variables")

    def call_api(self, prompt: str) -> Optional[str]:
        """
        Faz chamada à API com retry logic e tratamento de erros.
        Monitora custos e uso.
        """
        self.total_requests += 1
        self.total_cost += self.cost_per_request

        start_time = datetime.now()
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        data = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": prompt
                        }
                    ]
                }
            ]
        }

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    f"{self.base_url}/chat/completions", headers=headers, json=data
                )
                if response.status_code == 402:  # Payment Required
                    raise SystemicClassifierError("OpenRouter API credits exhausted")
                elif response.status_code == 401:  # Unauthorized
                    raise SystemicClassifierError("OpenRouter API key is invalid")
                elif response.status_code == 404:  # Model unavailable
                    raise SystemicClassifierError(
                        f"OpenRouter model not found: {self.model}"
                    )
                response.raise_for_status()

                # Log de custos e tempo
                elapsed_time = (datetime.now() - start_time).total_seconds()
                logger.debug(
                    f"Chamada à API concluída: tempo={elapsed_time:.2f}s, custo=${self.cost_per_request:.4f}"
                )

                return response.json()["choices"][0]["message"]["content"]

            except SystemicClassifierError:
                raise  # Re-lança erros sistêmicos
            except requests.exceptions.RequestException as e:
                logger.warning(
                    f"Tentativa {attempt + 1} de classificação falhou - {str(e)}"
                )
                if attempt < self.max_retries - 1:
                    sleep(self.retry_delay * (2**attempt))  # Exponential backoff
                continue

        logger.error("Falha na classificação: todas as tentativas falharam")
        return None


class SectorClassifier:
    """
    Classe principal para classificação de setores econômicos.
    Integra extração de conteúdo web com classificação via IA.
    """

    def __init__(self, sectors_file: Path):
        """
        Inicializa o classificador de setores.
        
        Args:
            sectors_file: Caminho para o arquivo JSON com as definições dos setores
        """
        self.sectors = self._load_sectors(sectors_file)
        self.valid_sectors = list(self.sectors.keys())
        self.api_client = OpenRouterClient()

    def _load_sectors(self, sectors_file: str) -> Dict:
        """Carrega e valida o arquivo de setores."""
        try:
            with open(sectors_file, "r", encoding="utf-8") as f:
                sectors = json.load(f)
            logger.debug(f"Carregados {len(sectors)} setores do arquivo {sectors_file}")
            return sectors
        except Exception as e:
            logger.error(f"Erro ao carregar arquivo de setores: {str(e)}")
            raise

    def get_classification_prompt(self, content: str, company_name: str) -> str:
        return f"""Classify the company into ONE of these sectors ONLY: {', '.join(self.valid_sectors)}

Brief sector descriptions:
- Manufacturing Industry: Companies that produce physical goods through manufacturing processes
- Healthcare and Medical: Healthcare providers, hospitals, medical services
- Business Services: Professional services like consulting, accounting, business software
- Retail and Commerce: Direct sales of products to consumers
- Information Technology: Technology products, software, hardware and digital solutions
- Government: Government bodies, institutions and services
- Financial Services: Banks, investment services, fintech and financial institutions
- Logistics and Transportation: Transport, logistics, storage and distribution companies
- Agriculture and Food Industry: Agricultural production, food processing and agribusiness
- Consumer Services: Direct consumer services not classified in other categories
- Energy and Utilities: Energy companies, public utilities and natural resources
- Tourism and Hospitality: Hotels, tourism, entertainment and hospitality services
- Telecommunications: Telecom providers, internet and telephony services
- Educational Services: Educational institutions, schools, universities and online education
- Real Estate Services: Real estate, property management and development
- Media and Entertainment: Media companies, content production and broadcasting
- Legal Services: Law firms and legal services providers
- Insurance Services: Insurance, reinsurance and brokerage companies
- Research and Development: Research institutions, scientific development and innovation
- Non-Profit Organizations: NGOs, charities and philanthropic institutions
- Natural Resources and Extractive Industry: Companies focused on extraction and primary processing of natural resources, including mining, logging, and other extractive activities not covered by more specific sectors like 'Energy and Utilities' or 'Agriculture and Food Industry'

Company: {company_name}
Content: {content}

Respond ONLY with the exact sector name from the list above. No other text."""

    
    def _clean_api_response(self, response: str) -> str:
        """
        Remove prefixos indesejados e formatação da resposta da API.
        
        Args:
            response: Resposta da API
            
        Returns:
            Resposta limpa
        """
        # Lista de prefixos a serem removidos
        prefixes = [
            "Setor:",
            "Setor da empresa:",
            "Resposta:",
            "Setor da Empresa:",
            "Setor: ",
            "Setor da empresa: ",
            "Resposta: ",
            "Setor da Empresa: ",
            "##",
            "#"
        ]
        
        # Remove os prefixos
        cleaned = response.strip()
        for prefix in prefixes:
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):].strip()
        
        # Remove formatação markdown e explicações
        cleaned = cleaned.replace('*', '').replace('_', '')
        
        # Pega apenas a primeira linha (remove explicações)
        cleaned = cleaned.split('\n')[0].strip()
        
        # Remove qualquer texto após um ponto
        cleaned = cleaned.split('.')[0].strip()
        
        # Remove qualquer texto após "Justificativa", "Observações", etc.
        markers = [
            "Justificativa",
            "Observações",
            "Considerações",
            "Motivos",
            "Conclusão",
            "Análise",
            "Portanto"
        ]
        for marker in markers:
            if marker.lower() in cleaned.lower():
                cleaned = cleaned[:cleaned.lower().index(marker.lower())].strip()
        
        return cleaned

    def classify_content(self, content: str, company_name: str = None) -> str:
        """
        Classifica o conteúdo em um setor.
        
        Args:
            content: Conteúdo a ser classificado
            company_name: Nome da empresa (opcional)
            
        Returns:
            Nome do setor
        """
        
        logger.debug(f"Preparando classificação{' para ' + company_name if company_name else ''}")
        
        prompt = self.get_classification_prompt(content, company_name or "")
        response = self.api_client.call_api(prompt)
        
        if response:
            cleaned_response = self._clean_api_response(response)            
            logger.info(f"Classificação concluída: {cleaned_response}")
            return cleaned_response
        else:
            logger.error(f"Falha na classificação{' para ' + company_name if company_name else ''}")
            return None

    def classify_batch(self, contents: List[str]) -> List[Optional[str]]:
        """
        Classifica múltiplos conteúdos em lote.
        Inclui métricas agregadas de custo e performance.
        """
        start_time = datetime.now()
        initial_cost = self.api_client.total_cost

        results = [self.classify_content(content) for content in contents]

        # Métricas do lote
        elapsed_time = (datetime.now() - start_time).total_seconds()
        batch_cost = self.api_client.total_cost - initial_cost
        success_count = sum(1 for r in results if r is not None)

        logger.info(
            f"Classificação em lote finalizada:\n"
            f"- Total processado: {len(contents)}\n"
            f"- Sucessos: {success_count}\n"
            f"- Falhas: {len(contents) - success_count}\n"
            f"- Tempo total: {elapsed_time:.2f}s\n"
            f"- Custo total: ${batch_cost:.4f}\n"
            f"- Custo médio: ${(batch_cost/len(contents)):.4f}"
        )

        return results

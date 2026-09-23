import logging
import re
import sys
import unicodedata
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

# Desabilitar avisos de SSL não verificado (necessário para sites com certificados inválidos/auto-assinados)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
logger, console_handler = setup_logger("web_extractor", log_to_file=True)
console_handler.setLevel(getattr(logging, LOG_LEVEL))  # Aplica o nível configurado


class WebContentExtractor:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

        # Configurações de timeout e retry
        self.timeout = 5  # Reduzido de 10 para 5 segundos
        self.max_retries = 2  # Reduzido para 2 tentativas
        self.retry_delay = 1  # Reduzido para 1 segundo

        # Limites de extração
        self.max_about_pages = 2  # Máximo de páginas "sobre" para visitar
        self.max_depth = 1  # Profundidade máxima de navegação
        self.visited_urls = set()  # Controle de URLs já visitadas

        # Termos multilíngues para seções "sobre"
        self.about_keywords = [
            # Inglês (EUA, UK, Austrália)
            "about",
            "about us",
            "company",
            "who we are",
            "our company",
            "overview",
            # Português (Brasil)
            "sobre",
            "quem somos",
            "empresa",
            "institucional",
            "nossa empresa",
            # Francês (França, Canadá)
            "à propos",
            "qui sommes-nous",
            "entreprise",
            "société",
            "aperçu",
            # Alemão (Alemanha)
            "über uns",
            "unternehmen",
            "wer wir sind",
            "firma",
            "überblick",
            # Italiano (Itália)
            "chi siamo",
            "azienda",
            "società",
            "about us",
            "panoramica",
            # Hindi/Inglês (Índia)
            "about",
            "company",
            "about us",
            "corporate",
            "overview",
            # Espanhol (Espanha)
            "sobre nosotros",
            "empresa",
            "quiénes somos",
            "compañía",
            "corporativo",
        ]

        # Elementos que geralmente contêm conteúdo relevante
        self.relevant_tags = ["main", "article", "section", "div"]
        self.relevant_classes = [
            "about",
            "company",
            "content",
            "main",
            "description",
            "overview",
            "profile",
            "corporate",
            "institucional",
        ]

        logger.debug(
            "WebContentExtractor inicializado com %d keywords", len(self.about_keywords)
        )

    def _normalize_url(self, url: str) -> str:
        """
        Nova lógica de normalização de URLs:
        1. Verifica se a URL contém asteriscos (URLs censuradas)
        2. Remove protocolo e www se existirem
        3. Tenta https://dominio.com
        4. Tenta https://www.dominio.com
        5. Se ambos falharem, busca no Google
        """
        logger.debug(f"Normalizando URL: {url}")

        # Verificar se a URL está censurada (contém asteriscos)
        if '*' in url:
            logger.warning(f"URL censurada detectada: {url}")
            return None

        # Remover protocolo e www se existirem
        clean_url = url.lower().strip()
        clean_url = re.sub(r"^https?://", "", clean_url)
        clean_url = re.sub(r"^www\.", "", clean_url)

        # Se a URL tem espaços, tentar buscar direto no Google
        if " " in clean_url:
            logger.debug(f"URL contém espaços, tentando mecanismos de busca: {clean_url}")
            google_result = self._search_google(clean_url)
            if google_result:
                logger.debug(f"URL alternativa encontrada: {google_result}")
                return google_result

        # Remover espaços e caracteres especiais
        clean_url = re.sub(r"[^\w\-.]", "", clean_url)

        logger.debug(f"URL normalizada: {clean_url}")

        # Tentar variações da URL
        variations = [f"https://{clean_url}", f"https://www.{clean_url}"]

        for test_url in variations:
            try:
                response = requests.head(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                )
                if response.status_code == 200:
                    logger.debug(f"URL válida encontrada: {test_url}")
                    return test_url
                logger.debug(
                    f"Tentativa falhou para {test_url} (status {response.status_code})"
                )
            except Exception as e:
                logger.debug(f"Tentativa falhou para {test_url} - {str(e)}")
                continue

        # Se nenhuma variação funcionou, tentar busca alternativa
        logger.debug(f"Tentando mecanismos de busca para: {clean_url}")
        google_result = self._search_google(clean_url)
        if google_result:
            return google_result

        logger.debug(
            f"Falha na extração: não foi possível encontrar URL válida para {url}"
        )
        return None

    def _search_google(self, query: str) -> Optional[str]:
        """
        Busca a URL no Google e retorna o primeiro resultado válido.
        """
        try:
            # Preparar query de busca mais simples e direta
            search_query = f'"{query}"' if " " in query else f"site:{query}"

            # Usar DuckDuckGo em vez do Google (menos restrições)
            search_url = f"https://duckduckgo.com/html/?q={search_query}"

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
                "Accept-Encoding": "gzip, deflate",
                "DNT": "1",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }

            response = requests.get(
                search_url, headers=headers, timeout=self.timeout, verify=False
            )
            response.raise_for_status()

            # Parsear resultados
            soup = BeautifulSoup(response.text, "html.parser")

            # Extrair links dos resultados do DuckDuckGo
            for result in soup.select(".result__url"):
                href = result.get("href", "")
                if href:
                    # Decodificar URL se necessário
                    if href.startswith("/"):
                        href = f"https:{href}"

                    # Verificar se é uma URL válida
                    if not any(
                        x in href.lower()
                        for x in [
                            "google.com",
                            "youtube.com",
                            "facebook.com",
                            "instagram.com",
                            "twitter.com",
                            "wikipedia.org",
                            "webcache",
                            "duckduckgo.com",
                            "bing.com",
                            "yahoo.com",
                        ]
                    ):
                        try:
                            response = requests.head(
                                href,
                                headers=self.headers,
                                timeout=self.timeout,
                                verify=False,
                                allow_redirects=True,
                            )
                            if response.status_code == 200:
                                logger.debug(
                                    f"URL válida encontrada via DuckDuckGo: {href}"
                                )
                                return href
                        except Exception:
                            continue

            # Se não encontrou nada no DuckDuckGo, tentar Bing
            bing_url = f"https://www.bing.com/search?q={search_query}"
            response = requests.get(
                bing_url, headers=headers, timeout=self.timeout, verify=False
            )
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")

            # Extrair links dos resultados do Bing
            for result in soup.select("li.b_algo h2 a"):
                href = result.get("href", "")
                if (
                    href
                    and href.startswith("http")
                    and not any(
                        x in href.lower()
                        for x in [
                            "google.com",
                            "youtube.com",
                            "facebook.com",
                            "instagram.com",
                            "twitter.com",
                            "wikipedia.org",
                            "webcache",
                            "duckduckgo.com",
                            "bing.com",
                            "yahoo.com",
                        ]
                    )
                ):
                    try:
                        response = requests.head(
                            href,
                            headers=self.headers,
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=True,
                        )
                        if response.status_code == 200:
                            logger.debug(f"URL válida encontrada via Bing: {href}")
                            return href
                    except Exception:
                        continue

            logger.warning(f"Nenhum resultado válido encontrado para: {query}")
            return None

        except Exception as e:
            logger.error(f"Erro na busca: {str(e)}")
            return None

    def extract_content(self, url: str) -> str:
        """
        Extrai o conteúdo relevante de uma URL.
        Nova abordagem: extrai todo o conteúdo possível e relevante.
        """
        # Resetar conjunto de URLs visitadas para cada nova extração
        self.visited_urls = set()

        try:
            logger.debug(f"Iniciando extração de conteúdo de {url}")

            # Normalizar URL
            normalized_url = self._normalize_url(url)
            if not normalized_url:
                logger.error(f"Falha na extração: URL inválida - {url}")
                return None

            # Adicionar à lista de visitados
            self.visited_urls.add(normalized_url)

            # Fazer requisição HTTP
            try:
                response = requests.get(
                    normalized_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                response.raise_for_status()
                html = response.text
                logger.debug(f"Conexão estabelecida com {normalized_url}")
            except Exception as e:
                logger.error(
                    f"Falha na extração: erro de conexão com {normalized_url} - {str(e)}"
                )
                return None

            # Adiciona a URL como primeira linha do conteúdo
            content_prefix = f"{normalized_url}\n"

            # Inicializar BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")

            # Remover elementos indesejados
            for tag in soup(["script", "style", "meta", "link", "iframe", "noscript"]):
                tag.decompose()

            all_content = []

            # 1. Extrair conteúdo da página principal
            main_content = self._extract_text_only(str(soup))
            if main_content:
                all_content.append(main_content)

            # 2. Buscar e extrair conteúdo de páginas "sobre"
            about_sections = self._find_about_sections(soup)
            if about_sections:
                all_content.extend(about_sections)

            # 3. Buscar conteúdo em seções relevantes
            keyword_sections = self._find_keyword_sections(soup)
            if keyword_sections:
                all_content.extend(keyword_sections)

            if not all_content:
                logger.warning(
                    f"Nenhum conteúdo relevante encontrado em {normalized_url}"
                )
                return None

            # Juntar todo o conteúdo
            content = " ".join(all_content)

            # Limpar e normalizar o texto
            content = self._clean_text(content)

            if content:
                # Adicionar URL como primeira linha
                content = content_prefix + content

                # Limitar tamanho do texto mantendo o mais relevante
                if len(content) > 2000:
                    # Dividir em sentenças
                    sentences = content.split(".")
                    relevant_content = []
                    current_length = 0

                    # Manter sentenças mais relevantes até atingir 2000 caracteres
                    for sentence in sentences:
                        if any(
                            keyword in sentence.lower()
                            for keyword in self.about_keywords
                        ):
                            relevant_content.append(sentence)
                            current_length += len(sentence)
                        if current_length >= 2000:
                            break

                    # Se ainda não atingiu 2000 caracteres, adicionar outras sentenças
                    if current_length < 2000:
                        for sentence in sentences:
                            if sentence not in relevant_content:
                                relevant_content.append(sentence)
                                current_length += len(sentence)
                            if current_length >= 2000:
                                break

                    content = ".".join(relevant_content)
                    logger.debug(
                        f"Conteúdo truncado de {len(' '.join(sentences))} para {len(content)} caracteres"
                    )

                logger.info(
                    f"Conteúdo extraído com sucesso de {normalized_url} ({len(content)} caracteres)"
                )
                return content

            logger.warning(f"Nenhum conteúdo extraído de {normalized_url}")
            return None

        except Exception as e:
            logger.error(
                f"Falha na extração: erro inesperado ao processar {url} - {str(e)}"
            )
            return None

    def _extract_text_only(self, html: str) -> str:
        """Extrai apenas o texto visível da página"""
        soup = BeautifulSoup(html, "html.parser")
        texts = soup.stripped_strings
        return " ".join(texts)

    def _find_about_sections(self, soup: BeautifulSoup) -> list:
        """Tenta encontrar seções 'Sobre' ou similares em várias línguas"""
        sections = []
        base_url = None
        about_pages_visited = 0

        try:
            # Lista para armazenar links "sobre" encontrados
            about_links = []

            # Procura em links de várias formas
            for link in soup.find_all("a"):
                try:
                    href = link.get("href", "").lower()
                    link_text = self._normalize_text(link.get_text()).lower()

                    # Verifica o texto do link
                    is_about_text = any(
                        kw.lower() in link_text for kw in self.about_keywords
                    )
                    # Verifica a URL do link
                    is_about_url = any(
                        kw.lower().replace(" ", "-") in href
                        or kw.lower().replace(" ", "_") in href
                        or kw.lower().replace(" ", "") in href
                        for kw in self.about_keywords
                    )

                    if is_about_text or is_about_url:
                        if href and href != "#" and not href.startswith("javascript:"):
                            about_links.append((link_text, href))
                except Exception as e:
                    logger.debug(f"Erro ao processar link: {str(e)}")
                    continue

            # Ordenar links por relevância (priorizar links mais relevantes)
            about_links.sort(
                key=lambda x: sum(
                    1 for kw in self.about_keywords if kw.lower() in x[0].lower()
                ),
                reverse=True,
            )

            # Processar apenas os links mais relevantes
            for link_text, href in about_links[: self.max_about_pages]:
                if about_pages_visited >= self.max_about_pages:
                    break

                logger.debug(
                    f"Encontrado link 'sobre': texto='{link_text}', href='{href}'"
                )

                try:
                    # Tentar resolver URL relativa
                    if href.startswith("/"):
                        # Extrair domínio da URL base do soup
                        if not base_url:
                            base_tags = soup.find_all("base", href=True)
                            if base_tags:
                                base_url = base_tags[0]["href"]
                            else:
                                # Tentar extrair do primeiro link absoluto
                                for a in soup.find_all("a", href=True):
                                    if a["href"].startswith(("http://", "https://")):
                                        parsed = urlparse(a["href"])
                                        base_url = f"{parsed.scheme}://{parsed.netloc}"
                                        break

                        if base_url:
                            about_url = urljoin(base_url, href)
                        else:
                            continue
                    elif not href.startswith(("http://", "https://")):
                        continue
                    else:
                        about_url = href

                    # Verificar se já visitamos esta URL
                    if about_url in self.visited_urls:
                        continue

                    self.visited_urls.add(about_url)
                    about_pages_visited += 1

                    about_response = requests.get(
                        about_url,
                        headers=self.headers,
                        timeout=self.timeout,
                        verify=False,
                    )
                    about_soup = BeautifulSoup(about_response.text, "html.parser")
                    logger.debug(
                        f"Acessando página 'sobre' ({about_pages_visited}/{self.max_about_pages}): {about_url}"
                    )

                    # Extrair conteúdo relevante
                    about_content = self._extract_relevant_content(about_soup)
                    if about_content:
                        sections.append(about_content)
                except Exception as e:
                    logger.debug(
                        f"Não foi possível acessar a página 'sobre' {href}: {str(e)}"
                    )
                    continue

        except Exception as e:
            logger.error(f"Erro ao buscar seções 'sobre': {str(e)}")

        return sections

    def _find_keyword_sections(self, soup: BeautifulSoup) -> list:
        """Tenta encontrar seções baseadas em palavras-chave no texto"""
        sections = []

        # Procura em IDs
        for keyword in self.about_keywords:
            normalized_keyword = self._normalize_text(keyword).lower()
            about_section = soup.find(
                id=lambda x: x and normalized_keyword in self._normalize_text(x).lower()
            )
            if about_section:
                sections.append(about_section.get_text())

        # Procura em classes
        for keyword in self.about_keywords:
            normalized_keyword = self._normalize_text(keyword).lower()
            about_section = soup.find(
                class_=lambda x: x
                and any(
                    normalized_keyword in self._normalize_text(cls).lower()
                    for cls in x.split()
                )
            )
            if about_section:
                sections.append(about_section.get_text())

        # Procura em headings seguidos de parágrafos
        for heading in soup.find_all(["h1", "h2", "h3"]):
            heading_text = self._normalize_text(heading.get_text()).lower()
            if any(
                normalized_keyword in heading_text
                for normalized_keyword in self.about_keywords
            ):
                content = []
                for sibling in heading.find_next_siblings():
                    if sibling.name in ["p", "div"]:
                        content.append(sibling.get_text())
                    elif sibling.name in ["h1", "h2", "h3"]:
                        break
                if content:
                    sections.append(" ".join(content))

        return sections

    def _extract_relevant_content(self, soup: BeautifulSoup) -> str:
        """Extrai conteúdo relevante da página"""
        content = []

        try:
            # Remover elementos indesejados
            for tag in soup(["script", "style", "meta", "link", "iframe", "noscript"]):
                tag.decompose()

            # 1. Procurar por elementos com classes relevantes
            relevant_elements = []
            for tag in self.relevant_tags:
                elements = soup.find_all(
                    tag,
                    class_=lambda x: x
                    and any(cls.lower() in x.lower() for cls in self.relevant_classes),
                )
                relevant_elements.extend(elements)

            # 2. Procurar por elementos com IDs relevantes
            for keyword in self.about_keywords:
                elements = soup.find_all(
                    id=lambda x: x and keyword.lower() in x.lower()
                )
                relevant_elements.extend(elements)

            # 3. Procurar por headings relevantes e seus conteúdos
            for heading in soup.find_all(["h1", "h2", "h3", "h4"]):
                heading_text = heading.get_text().lower()
                if any(
                    keyword.lower() in heading_text for keyword in self.about_keywords
                ):
                    # Pegar o heading
                    content.append(heading.get_text())
                    # Pegar todo o conteúdo até o próximo heading
                    for sibling in heading.find_next_siblings():
                        if sibling.name in ["h1", "h2", "h3", "h4"]:
                            break
                        if sibling.name in ["p", "div", "section", "article"]:
                            content.append(sibling.get_text())

            # 4. Extrair conteúdo dos elementos relevantes
            for element in relevant_elements:
                # Pegar texto do elemento
                element_text = element.get_text()
                if element_text:
                    content.append(element_text)

            # 5. Se não encontrou nada específico, pegar parágrafos principais
            if not content:
                # Pegar todos os parágrafos que não estão em header, footer ou nav
                for p in soup.find_all("p"):
                    if not any(
                        parent.name in ["header", "footer", "nav"]
                        for parent in p.parents
                    ):
                        content.append(p.get_text())

            # 6. Limpar e juntar o conteúdo
            cleaned_content = []
            for text in content:
                # Limpar espaços e quebras de linha
                cleaned = " ".join(text.split())
                if cleaned:
                    cleaned_content.append(cleaned)

            return " ".join(cleaned_content)

        except Exception as e:
            logger.error(f"Erro ao extrair conteúdo relevante: {str(e)}")
            return None

    def _clean_text(self, text: str) -> str:
        """
        Limpa e normaliza o texto extraído.
        Remove caracteres especiais mantendo acentuação.
        """
        if not text:
            return ""

        # Remover espaços extras e quebras de linha
        text = " ".join(text.split())

        # Remover caracteres especiais mantendo acentos
        text = re.sub(
            r'[^\w\s\-.,;:?!()\[\]{}"\'´`~^°ºª@#$%&*+=<>|/\\€£¥§©®™àáâãäåèéêëìíîïòóôõöùúûüýÿñçßæœøåþðđħłĸŋŧ¢α-ωΑ-Ω]',
            " ",
            text,
        )

        # Remover múltiplos espaços
        text = re.sub(r"\s+", " ", text).strip()

        return text

    def _normalize_text(self, text: str) -> str:
        """Remove acentos e normaliza o texto para comparação"""
        if not text:
            return ""
        # Decompõe os caracteres acentuados e remove os diacríticos
        return "".join(
            c
            for c in unicodedata.normalize("NFKD", text)
            if not unicodedata.combining(c)
        )


# Exemplo de uso
if __name__ == "__main__":
    extractor = WebContentExtractor()
    url = "qu4rtostudio.com.br"
    text = extractor.extract_content(url)

    if text:
        logger.info(
            "Conteúdo extraído com sucesso (primeiros 100 caracteres): %s", text
        )
    else:
        logger.error("Falha na extração")

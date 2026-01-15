from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urldefrag, urlparse

import importlib.util

import requests

if importlib.util.find_spec("bs4"):
    from bs4 import BeautifulSoup  # type: ignore
else:  # pragma: no cover - optional dependency
    BeautifulSoup = None


@dataclass
class CrawledPage:
    url: str
    status_code: Optional[int]
    headers: Dict[str, str]
    params: List[str] = field(default_factory=list)
    has_forms: bool = False
    form_methods: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class CrawlConfig:
    max_pages: int = 50
    max_depth: int = 2
    rate_limit: float = 2.0
    timeout: float = 10.0
    user_agent: str = "SecurityAuditAssistant/1.0"
    parallelism: int = 4


FORM_METHOD_RE = re.compile(r"method=\"?(get|post)\"?", re.IGNORECASE)
LINK_RE = re.compile(r"href=[\"']([^\"'#>]+)", re.IGNORECASE)


class Crawler:
    def __init__(self, base_url: str, config: CrawlConfig) -> None:
        self.base_url = base_url
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.user_agent})
        self.parsed_base = urlparse(base_url)
        self.rate_delay = 1.0 / max(config.rate_limit, 0.1)

    def _within_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self.parsed_base.netloc

    def _normalize(self, url: str) -> str:
        clean, _ = urldefrag(url)
        return clean

    def _fetch(self, url: str) -> Tuple[Optional[requests.Response], Optional[str]]:
        try:
            response = self.session.get(url, timeout=self.config.timeout, allow_redirects=True)
            return response, None
        except requests.RequestException as exc:
            return None, str(exc)

    def _extract_links(self, html: str, base: str) -> Iterable[str]:
        if BeautifulSoup:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("a", href=True):
                yield urljoin(base, tag["href"])
        else:
            for match in LINK_RE.findall(html):
                yield urljoin(base, match)

    def _extract_forms(self, html: str) -> Tuple[bool, List[str]]:
        methods = [m.lower() for m in FORM_METHOD_RE.findall(html)]
        return bool(methods), methods

    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        params = []
        if parsed.query:
            params.extend([part.split("=")[0] for part in parsed.query.split("&") if part])
        return params

    def _fetch_text(self, url: str) -> Optional[str]:
        response, _ = self._fetch(url)
        if response and response.ok:
            return response.text
        return None

    def _sitemap_urls(self) -> List[str]:
        sitemap_url = urljoin(self.base_url, "/sitemap.xml")
        body = self._fetch_text(sitemap_url)
        if not body:
            return []
        urls = re.findall(r"<loc>(.*?)</loc>", body)
        return [self._normalize(url) for url in urls if url]

    def _robots_urls(self) -> List[str]:
        robots_url = urljoin(self.base_url, "/robots.txt")
        body = self._fetch_text(robots_url)
        if not body:
            return []
        urls = []
        for line in body.splitlines():
            if line.lower().startswith("sitemap:"):
                urls.append(line.split(":", 1)[1].strip())
        return [self._normalize(url) for url in urls if url]

    def crawl(self) -> List[CrawledPage]:
        queue: Deque[Tuple[str, int]] = deque()
        visited: Set[str] = set()
        seed_urls = [self.base_url]
        for url in self._sitemap_urls():
            if self._within_scope(url):
                seed_urls.append(url)
        for url in self._robots_urls():
            if self._within_scope(url):
                seed_urls.append(url)

        for url in seed_urls:
            queue.append((self._normalize(url), 0))

        results: List[CrawledPage] = []

        while queue and len(results) < self.config.max_pages:
            url, depth = queue.popleft()
            if url in visited or depth > self.config.max_depth:
                continue
            visited.add(url)
            response, error = self._fetch(url)
            if response is None:
                results.append(
                    CrawledPage(
                        url=url,
                        status_code=None,
                        headers={},
                        params=self._extract_params(url),
                        error=error,
                    )
                )
                continue

            has_forms = False
            methods: List[str] = []
            text = None
            if response.headers.get("content-type", "").startswith("text/html"):
                text = response.text
                has_forms, methods = self._extract_forms(text)

            page = CrawledPage(
                url=response.url,
                status_code=response.status_code,
                headers={k: v for k, v in response.headers.items()},
                params=self._extract_params(response.url),
                has_forms=has_forms,
                form_methods=methods,
            )
            results.append(page)

            if text:
                for link in self._extract_links(text, response.url):
                    normalized = self._normalize(link)
                    if normalized not in visited and self._within_scope(normalized):
                        queue.append((normalized, depth + 1))

            time.sleep(self.rate_delay)

        return results

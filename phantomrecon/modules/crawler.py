from __future__ import annotations

import asyncio
import re
from collections import deque
from typing import Callable, Optional, Set
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from ..http_client import HttpClient
from ..models import DiscoveredPath, HttpResponse, ScanConfig


JS_URL_PATTERNS = [
    re.compile(r'(?:"|\'|`)(/[a-zA-Z0-9/_\-\.]+)(?:"|\'|`)', re.MULTILINE),
    re.compile(r'(?:url|href|src|action)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'XMLHttpRequest.*?open\s*\(.*?["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL),
    re.compile(r'["\']/(api|v\d|rest)/[a-zA-Z0-9/_\-\.]+["\']'),
]

CSS_URL_PATTERN = re.compile(r'url\(["\']?([^)"\'"]+)["\']?\)', re.IGNORECASE)

ROBOTS_PATTERN = re.compile(r'^(?:Allow|Disallow):\s*(.+)$', re.MULTILINE | re.IGNORECASE)

SITEMAP_URL_PATTERN = re.compile(r'<loc>\s*(.*?)\s*</loc>', re.IGNORECASE | re.DOTALL)


class Crawler:
    def __init__(
        self,
        config: ScanConfig,
        client: HttpClient,
        base_url: str,
        progress_callback: Optional[Callable] = None,
    ) -> None:
        self.config = config
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.progress_callback = progress_callback

        parsed = urlparse(base_url)
        self._base_scheme = parsed.scheme
        self._base_host = parsed.netloc

        self._visited: Set[str] = set()
        self._queued: Set[str] = set()
        self._discovered: list[DiscoveredPath] = []
        self._extracted_paths: Set[str] = set()

    async def crawl(self, max_pages: int = 200) -> tuple[list[DiscoveredPath], set[str]]:
        await self._fetch_robots_txt()
        await self._fetch_sitemap_xml()

        queue: deque[tuple[str, int]] = deque()
        queue.append((self.base_url, 0))
        self._queued.add(self.base_url)

        semaphore = asyncio.Semaphore(min(self.config.threads, 20))
        pages_crawled = 0

        while queue and pages_crawled < max_pages:
            batch: list[tuple[str, int]] = []
            while queue and len(batch) < self.config.threads:
                batch.append(queue.popleft())

            tasks = [self._crawl_page(url, depth, semaphore) for url, depth in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, tuple):
                    new_urls, discovered = result
                    for path in discovered:
                        self._discovered.append(path)
                    for new_url, depth in new_urls:
                        if new_url not in self._queued and pages_crawled + len(queue) < max_pages:
                            queue.append((new_url, depth))
                            self._queued.add(new_url)

            pages_crawled += len(batch)

        return self._discovered, self._extracted_paths

    async def _crawl_page(
        self,
        url: str,
        depth: int,
        semaphore: asyncio.Semaphore,
    ) -> tuple[list[tuple[str, int]], list[DiscoveredPath]]:
        if url in self._visited:
            return [], []
        self._visited.add(url)

        async with semaphore:
            resp = await self.client.get(url, allow_redirects=True)

        if not resp or resp.status_code == 0:
            return [], []

        discovered: list[DiscoveredPath] = []
        new_urls: list[tuple[str, int]] = []

        path = DiscoveredPath(
            url=url,
            status_code=resp.status_code,
            content_length=resp.content_length,
            content_type=resp.content_type,
            response_time=resp.response_time,
        )

        if resp.status_code == 200:
            content_type = resp.content_type.lower()

            if "text/html" in content_type:
                links, paths = self._parse_html(resp, depth)
                for link in links:
                    normalized = self._normalize_url(link)
                    if normalized and self._is_in_scope(normalized):
                        new_urls.append((normalized, depth + 1))
                        self._extracted_paths.add(urlparse(normalized).path)
                for p in paths:
                    self._extracted_paths.add(p)

            elif "javascript" in content_type or url.endswith(".js"):
                paths = self._extract_js_paths(resp.body, url)
                self._extracted_paths.update(paths)

            elif "text/css" in content_type or url.endswith(".css"):
                paths = self._extract_css_paths(resp.body, url)
                self._extracted_paths.update(paths)

            title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.body, re.IGNORECASE | re.DOTALL)
            if title_match:
                path.title = title_match.group(1).strip()[:200]

        discovered.append(path)
        return new_urls, discovered

    def _parse_html(self, resp: HttpResponse, depth: int) -> tuple[list[str], list[str]]:
        links: list[str] = []
        paths: list[str] = []

        try:
            soup = BeautifulSoup(resp.body, "lxml")
        except Exception:
            try:
                soup = BeautifulSoup(resp.body, "html.parser")
            except Exception:
                return [], []

        for tag in soup.find_all("a", href=True):
            href = tag.get("href", "")
            if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                links.append(urljoin(resp.url, href))

        for tag in soup.find_all(["form"], action=True):
            action = tag.get("action", "")
            if action:
                links.append(urljoin(resp.url, action))

        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "")
            if src:
                links.append(urljoin(resp.url, src))
                paths.append(urlparse(urljoin(resp.url, src)).path)

        for tag in soup.find_all("link", href=True):
            href = tag.get("href", "")
            if href and href.endswith(".css"):
                links.append(urljoin(resp.url, href))

        for tag in soup.find_all("script"):
            if not tag.get("src") and tag.string:
                js_paths = self._extract_js_paths(tag.string, resp.url)
                paths.extend(js_paths)

        for comment in soup.find_all(string=lambda text: isinstance(text, str) and "<!--" in str(text)):
            url_matches = re.findall(r'(?:href|src|url|action)[=:\s]+["\']?(/[^\s"\'<>]+)', str(comment))
            paths.extend(url_matches)

        return links, paths

    def _extract_js_paths(self, js_content: str, base_url: str) -> list[str]:
        paths: list[str] = []
        for pattern in JS_URL_PATTERNS:
            for match in pattern.finditer(js_content):
                path = match.group(1)
                if path.startswith("/") and len(path) > 1 and not path.startswith("//"):
                    paths.append(path)
                elif path.startswith("http"):
                    parsed = urlparse(path)
                    if parsed.netloc == self._base_host:
                        paths.append(parsed.path)
        return list(set(paths))

    def _extract_css_paths(self, css_content: str, base_url: str) -> list[str]:
        paths: list[str] = []
        for match in CSS_URL_PATTERN.finditer(css_content):
            url = match.group(1).strip()
            if url.startswith("/") and not url.startswith("//"):
                paths.append(url)
            elif not url.startswith(("http", "data:", "#")):
                full_url = urljoin(base_url, url)
                parsed = urlparse(full_url)
                if parsed.netloc == self._base_host:
                    paths.append(parsed.path)
        return paths

    async def _fetch_robots_txt(self) -> None:
        robots_url = f"{self.base_url}/robots.txt"
        resp = await self.client.get(robots_url, retries=1)
        if resp and resp.status_code == 200:
            for match in ROBOTS_PATTERN.finditer(resp.body):
                path = match.group(1).strip()
                if path and path != "/" and "*" not in path:
                    self._extracted_paths.add(path)

    async def _fetch_sitemap_xml(self) -> None:
        for sitemap_url in [f"{self.base_url}/sitemap.xml", f"{self.base_url}/sitemap_index.xml"]:
            resp = await self.client.get(sitemap_url, retries=1)
            if resp and resp.status_code == 200:
                for match in SITEMAP_URL_PATTERN.finditer(resp.body):
                    url = match.group(1).strip()
                    parsed = urlparse(url)
                    if parsed.netloc == self._base_host or not parsed.netloc:
                        self._extracted_paths.add(parsed.path)

    def _normalize_url(self, url: str) -> Optional[str]:
        try:
            parsed = urlparse(url)
            normalized = urlunparse((
                parsed.scheme or self._base_scheme,
                parsed.netloc or self._base_host,
                parsed.path,
                "",
                "",
                "",
            ))
            return normalized
        except Exception:
            return None

    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)

        if parsed.netloc != self._base_host:
            return False

        if parsed.scheme not in ("http", "https"):
            return False

        ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
        skip_extensions = {"jpg", "jpeg", "png", "gif", "svg", "ico", "pdf", "doc",
                           "docx", "xls", "xlsx", "ppt", "pptx", "mp4", "mp3",
                           "avi", "mov", "zip", "tar", "gz", "rar", "woff", "woff2", "ttf", "eot"}
        if ext in skip_extensions:
            return False

        if self.config.scope:
            return any(url.startswith(s) for s in self.config.scope)

        return True

from __future__ import annotations

import asyncio
import hashlib
import re
from pathlib import Path
from typing import AsyncIterator, Callable, Optional
from urllib.parse import urljoin, urlparse

from ..http_client import HttpClient
from ..models import DiscoveredPath, HttpResponse, ScanConfig, ScanModule
from ..wordlists import apply_extensions, get_builtin_wordlist_path, stream_wordlist


class Custom404Detector:
    def __init__(self) -> None:
        self._baselines: list[dict] = []
        self._calibrated: bool = False
        self._wildcard_hashes: set[str] = set()
        self._wildcard_sizes: list[int] = []
        self._soft404_patterns: list[re.Pattern] = []
        self._threshold_size: int = 0
        self._threshold_variance: float = 0.15

    async def calibrate(self, client: HttpClient, base_url: str) -> None:
        import random
        import string

        test_paths = [
            "".join(random.choices(string.ascii_lowercase, k=12)),
            "".join(random.choices(string.ascii_lowercase, k=10)) + ".php",
            "".join(random.choices(string.ascii_lowercase, k=8)) + "/",
        ]
        responses: list[HttpResponse] = []
        for path in test_paths:
            url = urljoin(base_url.rstrip("/") + "/", path)
            resp = await client.get(url, allow_redirects=True)
            if resp.status_code != 0:
                responses.append(resp)

        if not responses:
            return

        sizes = [r.content_length for r in responses]
        self._threshold_size = int(sum(sizes) / len(sizes)) if sizes else 0

        for resp in responses:
            body_hash = hashlib.md5(resp.body.encode(errors="ignore")).hexdigest()
            self._wildcard_hashes.add(body_hash)
            self._wildcard_sizes.append(resp.content_length)

        soft_404_keywords = [
            r"not\s+found",
            r"page\s+not\s+found",
            r"404",
            r"does\s+not\s+exist",
            r"no\s+such\s+(file|page|resource)",
            r"error\s+404",
            r"the\s+page\s+you",
            r"could\s+not\s+be\s+found",
        ]
        for kw in soft_404_keywords:
            self._soft404_patterns.append(re.compile(kw, re.IGNORECASE))

        self._calibrated = True

    def is_false_positive(self, resp: HttpResponse) -> bool:
        if resp.status_code in (404, 410):
            return True

        if resp.status_code == 0:
            return True

        body_hash = hashlib.md5(resp.body.encode(errors="ignore")).hexdigest()
        if body_hash in self._wildcard_hashes:
            return True

        if self._wildcard_sizes and resp.content_length > 0:
            avg_size = sum(self._wildcard_sizes) / len(self._wildcard_sizes)
            if avg_size > 0:
                size_diff = abs(resp.content_length - avg_size) / avg_size
                if size_diff < self._threshold_variance and resp.content_length < 1000:
                    return True

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if any(kw in location.lower() for kw in ["404", "error", "not-found", "notfound"]):
                return True

        if resp.status_code == 200:
            body_lower = resp.body.lower()
            for pattern in self._soft404_patterns:
                if pattern.search(body_lower):
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.body, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        title = title_match.group(1).lower()
                        if any(kw in title for kw in ["404", "not found", "error", "not exist"]):
                            return True

        return False

    def extract_title(self, body: str) -> Optional[str]:
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:200]
        return None


class BruteForcer:
    def __init__(self, config: ScanConfig, client: HttpClient, progress_callback: Optional[Callable] = None) -> None:
        self.config = config
        self.client = client
        self.progress_callback = progress_callback
        self.detector = Custom404Detector()
        self._discovered: list[DiscoveredPath] = []
        self._seen_urls: set[str] = set()

    async def run(self, base_url: str, wordlist_paths: list[str] | None = None) -> list[DiscoveredPath]:
        base_url = base_url.rstrip("/")

        await self.detector.calibrate(self.client, base_url)

        words = self._load_words(wordlist_paths)

        if self.config.extensions:
            words = apply_extensions(words, self.config.extensions)

        await self._scan_batch(base_url, words)

        if self.config.recursive:
            await self._recursive_scan(base_url, depth=0)

        return self._discovered

    def _load_words(self, custom_paths: list[str] | None) -> list[str]:
        if custom_paths:
            from ..wordlists import merge_wordlists
            return merge_wordlists([Path(p) for p in custom_paths])

        wl_path = get_builtin_wordlist_path(self.config.wordlist_size)
        return list(stream_wordlist(wl_path))

    async def _scan_batch(self, base_url: str, words: list[str]) -> None:
        semaphore = asyncio.Semaphore(self.config.threads)
        total = len(words)
        done = 0

        async def check_word(word: str) -> None:
            nonlocal done
            async with semaphore:
                url = f"{base_url}/{word.lstrip('/')}"
                if url in self._seen_urls:
                    return
                self._seen_urls.add(url)

                resp = await self.client.get(url, allow_redirects=self.config.follow_redirects)

                if self.progress_callback:
                    done += 1
                    self.progress_callback(done, total, url, resp.status_code if resp else 0)

                if resp and not self.detector.is_false_positive(resp):
                    if self._passes_filters(resp):
                        path = DiscoveredPath(
                            url=url,
                            status_code=resp.status_code,
                            content_length=resp.content_length,
                            content_type=resp.content_type,
                            response_time=resp.response_time,
                            is_directory=word.endswith("/") or resp.status_code == 301,
                            redirect_to=resp.headers.get("Location"),
                            title=self.detector.extract_title(resp.body),
                        )
                        self._discovered.append(path)

        tasks = [check_word(w) for w in words]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _recursive_scan(self, base_url: str, depth: int) -> None:
        if depth >= self.config.recursion_depth:
            return

        dirs_to_scan = [
            p.url for p in self._discovered
            if p.is_directory and p.url.startswith(base_url) and p.url != base_url
        ]

        for dir_url in dirs_to_scan:
            if depth + 1 > self.config.recursion_depth:
                break
            words = list(stream_wordlist(get_builtin_wordlist_path("small")))
            if self.config.extensions:
                words = apply_extensions(words, self.config.extensions)
            before_count = len(self._discovered)
            await self._scan_batch(dir_url.rstrip("/"), words)
            if len(self._discovered) > before_count:
                await self._recursive_scan(dir_url, depth + 1)

    def _passes_filters(self, resp: HttpResponse) -> bool:
        if self.config.include_codes and resp.status_code not in self.config.include_codes:
            return False
        if self.config.exclude_codes and resp.status_code in self.config.exclude_codes:
            return False
        if self.config.min_size and resp.content_length < self.config.min_size:
            return False
        if self.config.max_size and resp.content_length > self.config.max_size:
            return False
        if self.config.filter_regex:
            pattern = re.compile(self.config.filter_regex, re.IGNORECASE)
            if not pattern.search(resp.body):
                return False
        if self.config.exclude_regex:
            pattern = re.compile(self.config.exclude_regex, re.IGNORECASE)
            if pattern.search(resp.body):
                return False
        return True

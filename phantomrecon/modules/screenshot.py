from __future__ import annotations

import asyncio
import os
import re
import time
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse


class ScreenshotResult:
    def __init__(self, url: str, file_path: str, width: int = 1280, height: int = 800) -> None:
        self.url = url
        self.file_path = file_path
        self.width = width
        self.height = height
        self.timestamp = time.time()
        self.error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "file_path": self.file_path,
            "width": self.width,
            "height": self.height,
            "timestamp": self.timestamp,
            "error": self.error,
        }


class ScreenshotModule:
    def __init__(
        self,
        output_dir: str = "screenshots",
        threads: int = 5,
        timeout: int = 15,
        width: int = 1280,
        height: int = 800,
        full_page: bool = False,
        callback: Optional[Callable] = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.timeout = timeout
        self.width = width
        self.height = height
        self.full_page = full_page
        self.callback = callback
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._sem = asyncio.Semaphore(threads)

    async def screenshot_urls(self, urls: list[str]) -> list[ScreenshotResult]:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return [self._error_result(u, "playwright not installed") for u in urls]

        results = []
        tasks = [self._take_screenshot(u) for u in urls]
        done = await asyncio.gather(*tasks, return_exceptions=True)
        for r in done:
            if isinstance(r, ScreenshotResult):
                results.append(r)
        return results

    async def screenshot_single(self, url: str) -> ScreenshotResult:
        return await self._take_screenshot(url)

    async def _take_screenshot(self, url: str) -> ScreenshotResult:
        async with self._sem:
            file_path = self._url_to_path(url)
            result = ScreenshotResult(url=url, file_path=str(file_path),
                                      width=self.width, height=self.height)
            try:
                from playwright.async_api import async_playwright
                async with async_playwright() as p:
                    browser = await p.chromium.launch(
                        headless=True,
                        args=[
                            "--no-sandbox", "--disable-setuid-sandbox",
                            "--disable-dev-shm-usage", "--disable-gpu",
                            "--disable-web-security",
                        ],
                    )
                    context = await browser.new_context(
                        viewport={"width": self.width, "height": self.height},
                        ignore_https_errors=True,
                        user_agent=(
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36"
                        ),
                    )
                    page = await context.new_page()

                    try:
                        await page.goto(
                            url,
                            timeout=self.timeout * 1000,
                            wait_until="networkidle",
                        )
                    except Exception:
                        await page.goto(
                            url,
                            timeout=self.timeout * 1000,
                            wait_until="domcontentloaded",
                        )

                    await page.screenshot(
                        path=str(file_path),
                        full_page=self.full_page,
                        type="png",
                    )
                    await browser.close()

                if self.callback:
                    self.callback(result)

            except ImportError:
                result.error = "playwright not installed — run: pip install playwright && playwright install chromium"
            except Exception as e:
                result.error = str(e)
                self._try_fallback(url, file_path, result)

            return result

    def _try_fallback(self, url: str, file_path: Path, result: ScreenshotResult) -> None:
        try:
            import subprocess
            proc = subprocess.run(
                ["cutycapt", f"--url={url}", f"--out={file_path}", "--delay=2000"],
                timeout=self.timeout,
                capture_output=True,
            )
            if proc.returncode == 0 and file_path.exists():
                result.error = None
        except Exception:
            pass

        try:
            import subprocess
            proc = subprocess.run(
                ["chromium-browser", "--headless", "--no-sandbox",
                 f"--screenshot={file_path}", url],
                timeout=self.timeout,
                capture_output=True,
            )
            if proc.returncode == 0 and file_path.exists():
                result.error = None
        except Exception:
            pass

    def _url_to_path(self, url: str) -> Path:
        parsed = urlparse(url)
        safe = re.sub(r"[^\w\-_.]", "_", parsed.netloc + parsed.path)
        safe = safe[:80]
        ts = int(time.time() * 1000) % 100000
        return self.output_dir / f"{safe}_{ts}.png"

    @staticmethod
    def _error_result(url: str, msg: str) -> ScreenshotResult:
        r = ScreenshotResult(url=url, file_path="")
        r.error = msg
        return r

    async def screenshot_scan_result(self, result: Any, scan_id: Optional[int] = None) -> list[ScreenshotResult]:
        urls = []
        urls.append(result.target)
        for path in result.discovered_paths[:50]:
            if path.status_code in (200, 201, 301, 302, 403):
                urls.append(path.url)
        screenshots = await self.screenshot_urls(urls)
        if scan_id:
            try:
                from ..database import ScanDatabase
                db = ScanDatabase()
                for s in screenshots:
                    if not s.error and s.file_path:
                        db.save_screenshot(scan_id, s.url, s.file_path)
            except Exception:
                pass
        return screenshots

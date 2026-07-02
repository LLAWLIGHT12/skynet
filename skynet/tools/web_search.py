"""Web 搜索工具（疑惑消解）。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional

import aiohttp
from loguru import logger


@dataclass
class SearchResult:
    title: str
    snippet: str
    url: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"title": self.title, "snippet": self.snippet, "url": self.url}


class WebSearchTool:
    """按需 Web 搜索，支持 DuckDuckGo（无需 key）或 Tavily API。"""

    def __init__(
        self,
        provider: str = "duckduckgo",
        api_key: Optional[str] = None,
        max_results: int = 5,
        timeout: float = 15.0,
    ) -> None:
        self.provider = (provider or "duckduckgo").lower()
        self.api_key = api_key or os.environ.get("TAVILY_API_KEY", "")
        self.max_results = max_results
        self.timeout = timeout

    async def search(self, query: str) -> list[SearchResult]:
        if not query.strip():
            return []
        try:
            if self.provider == "tavily" and self.api_key:
                return await self._search_tavily(query)
            return await self._search_duckduckgo(query)
        except Exception as e:
            logger.warning("Web 搜索失败 [{}]: {}", query[:60], e)
            return []

    async def _search_duckduckgo(self, query: str) -> list[SearchResult]:
        try:
            try:
                from ddgs import DDGS
            except ImportError:
                from duckduckgo_search import DDGS
        except ImportError:
            logger.warning("未安装 ddgs / duckduckgo-search，跳过 Web 搜索")
            return []

        import asyncio

        def _run() -> list[SearchResult]:
            results: list[SearchResult] = []
            with DDGS() as ddgs:
                for r in ddgs.text(query, max_results=self.max_results):
                    results.append(SearchResult(
                        title=str(r.get("title", "")),
                        snippet=str(r.get("body", r.get("snippet", ""))),
                        url=str(r.get("href", r.get("link", ""))),
                    ))
            return results

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_run),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("Web 搜索超时 [{}]", query[:60])
            return []

    async def _search_tavily(self, query: str) -> list[SearchResult]:
        url = "https://api.tavily.com/search"
        payload = {
            "api_key": self.api_key,
            "query": query,
            "max_results": self.max_results,
            "search_depth": "basic",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=self.timeout) as resp:
                resp.raise_for_status()
                data = await resp.json()
        results: list[SearchResult] = []
        for item in data.get("results", []):
            results.append(SearchResult(
                title=str(item.get("title", "")),
                snippet=str(item.get("content", "")),
                url=str(item.get("url", "")),
            ))
        return results

    async def search_many(self, queries: list[str]) -> list[dict[str, Any]]:
        seen_urls: set[str] = set()
        merged: list[dict[str, Any]] = []
        for q in queries[:3]:
            for r in await self.search(q):
                if r.url and r.url in seen_urls:
                    continue
                if r.url:
                    seen_urls.add(r.url)
                merged.append(r.to_dict())
                if len(merged) >= self.max_results:
                    return merged
        return merged

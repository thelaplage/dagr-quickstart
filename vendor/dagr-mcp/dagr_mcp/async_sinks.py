"""Async sink contracts used by framework bindings."""

from __future__ import annotations

import asyncio
from typing import Any, Mapping, Protocol


class AsyncReceiptSink(Protocol):
    async def append(self, receipt: Mapping[str, Any]) -> str: ...


class AsyncReviewObjectSink(Protocol):
    async def create(self, review: Mapping[str, Any]) -> str: ...


class AsyncReceiptSinkFromSync:
    def __init__(self, sync_sink: Any):
        self.sync_sink = sync_sink

    async def append(self, receipt: Mapping[str, Any]) -> str:
        return await asyncio.to_thread(self.sync_sink.write, receipt)


class AsyncReviewObjectSinkFromSync:
    def __init__(self, sync_sink: Any):
        self.sync_sink = sync_sink

    async def create(self, review: Mapping[str, Any]) -> str:
        return await asyncio.to_thread(self.sync_sink.create_review_object, review)

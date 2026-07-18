"""WASP Network hub — FastAPI app aggregating anonymized node summaries.

Non-negotiable design principle (from the original project proposal): no raw
source code or raw findings are ever shared between teams here, only
anonymized aggregates (severity counts, node/team name, timestamp). See
wasp_network/models.py — NodeSummary intentionally has no room for `file`,
`line`, `message`, or `rule_id`. Do not add fields to this API that would
leak per-finding detail.
"""

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from wasp_network import store
from wasp_network.models import NodeSummary

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="WASP Network")

# Broadcast pattern: each connected SSE client gets its own asyncio.Queue.
# /ingest fans an update out to every queue in this set; each /events
# connection reads only from its own queue. This is the pattern recommended
# by sse-starlette for broadcasting the same event to multiple clients
# (no shared queue, so one slow/disconnected client can't block the others).
_subscribers: set[asyncio.Queue] = set()


def _nodes_payload() -> str:
    return json.dumps([n.model_dump() for n in store.get_all_nodes()])


async def _broadcast() -> None:
    payload = _nodes_payload()
    for queue in list(_subscribers):
        await queue.put(payload)


@app.post("/ingest")
async def ingest(summary: NodeSummary):
    store.upsert_node(summary)
    await _broadcast()
    return {"status": "ok", "node_id": summary.node_id}


@app.get("/nodes")
async def nodes():
    return store.get_all_nodes()


@app.get("/events")
async def events(request: Request):
    queue: asyncio.Queue = asyncio.Queue()
    _subscribers.add(queue)

    async def event_generator():
        try:
            # Send current state immediately so a freshly opened dashboard
            # doesn't wait for the next /ingest to show anything.
            yield {"event": "update", "data": _nodes_payload()}
            while True:
                if await request.is_disconnected():
                    break
                payload = await queue.get()
                yield {"event": "update", "data": payload}
        finally:
            _subscribers.discard(queue)

    return EventSourceResponse(event_generator())


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

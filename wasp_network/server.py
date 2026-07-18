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

from centinela.ledger import hash_chain
from wasp_network import store
from wasp_network.models import NodeSummary

STATIC_DIR = Path(__file__).parent / "static"

# Local node's own audit ledger. Exposed read-only via /ledger for the
# operator's dashboard — this data never crosses /ingest (the wire format
# between teams stays anonymized aggregates only, see models.py).
LOCAL_LEDGER_PATH = Path(__file__).parent.parent / "centinela" / "data" / "ledger.jsonl"

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


def _trim_entry(entry: dict) -> dict:
    """Flatten a ledger entry for display, dropping the bulky `raw` scanner
    output but keeping the evidence (file, line, message, rule_id) and the
    hash-chain fields (hash, prev_hash)."""
    data = entry.get("data", {})
    return {
        "index": entry.get("index"),
        "ts": entry.get("ts"),
        "type": entry.get("type"),
        "hash": entry.get("hash"),
        "prev_hash": entry.get("prev_hash"),
        "severity": data.get("severity"),
        "rule_id": data.get("rule_id"),
        "file": data.get("file"),
        "line": data.get("line"),
        "message": data.get("message"),
        "source": data.get("source"),
    }


@app.get("/ledger")
async def ledger(limit: int = 50):
    """LOCAL-ONLY evidence view: this node's own hash-chained audit ledger
    (findings with file/line/rule evidence + chain integrity status).

    This endpoint serves the node operator's own dashboard on their own
    machine. It is NOT part of the federated network API — nothing here is
    ever shared with other teams; /ingest keeps carrying anonymized
    aggregates only."""
    limit = max(1, min(limit, 500))
    ledger_path = str(LOCAL_LEDGER_PATH)
    entries = hash_chain.read_entries(ledger_path=ledger_path)
    trimmed = [_trim_entry(e) for e in entries[-limit:]][::-1]  # newest first
    return {
        "chain_valid": hash_chain.verify_chain(ledger_path=ledger_path),
        "total_entries": len(entries),
        "entries": trimmed,
    }


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

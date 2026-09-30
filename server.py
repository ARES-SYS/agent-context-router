#!/usr/bin/env python3
"""
Agent Context Router
Routes queries to the right knowledge source, validates context, and blocks poisoned chunks.
Zero dependencies beyond Python 3.10+ stdlib. ChromaDB optional.

POST /route  —  {"query": "...", "max_chunks": 5}
POST /health —  {"status": "ok"}
"""

import os
import re
import math
import json
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    import chromadb
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False

# ─── Configuration ────────────────────────────────────────────

DB_PATH = os.path.expanduser(os.environ.get("CTX_DB_PATH", "~/context_router_db"))
PORT = int(os.environ.get("CTX_PORT", "8899"))
MAX_CHUNKS = int(os.environ.get("CTX_MAX_CHUNKS", "5"))
ENTROPY_MAX = float(os.environ.get("CTX_ENTROPY_MAX", "7.5"))

# Source definitions: name → ChromaDB collection
SOURCES = {
    "code":         "code_memory",
    "general":      "general_memory",
    "security":     "security_memory",
    "operations":   "operations_memory",
}

# Intent keywords for classification
INTENT_KEYWORDS = {
    "code":       ["code", "script", "function", "python", "bash", "command", "fix", "compile", "git", "docker"],
    "security":   ["attack", "vuln", "threat", "exploit", "adversary", "incident", "alert"],
    "operations": ["deploy", "server", "backup", "config", "service", "restart", "monitor", "log"],
}

# ─── Injection patterns ───────────────────────────────────────

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+\w+", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*[:=]", re.IGNORECASE),
    re.compile(r"override\s+your\s+(instructions|programming)", re.IGNORECASE),
    re.compile(r"<\|im_start\|>|<\|im_end\|>", re.IGNORECASE),
]

# Example blocklist — add your own domains
KNOWN_BAD = []

# ─── Utilities ────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        px = data.count(chr(x)) / len(data)
        if px > 0:
            entropy -= px * math.log2(px)
    return entropy

def classify_intent(query: str) -> str:
    query_lower = query.lower()
    scores = {}
    for intent, keywords in INTENT_KEYWORDS.items():
        scores[intent] = sum(1 for kw in keywords if kw in query_lower)
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "general"

def scan_injection(text: str) -> list[str]:
    hits = []
    for pat in INJECTION_PATTERNS:
        if pat.search(text):
            hits.append(f"injection_pattern:{pat.pattern[:40]}")
    for bad in KNOWN_BAD:
        if bad.lower() in text.lower():
            hits.append(f"known_bad:{bad}")
    entropy = shannon_entropy(text)
    if entropy > ENTROPY_MAX:
        hits.append(f"high_entropy:{entropy:.2f}")
    return hits

# ─── ChromaDB client ──────────────────────────────────────────

_client = None

def get_client():
    global _client
    if _client is None and HAS_CHROMADB:
        os.makedirs(DB_PATH, exist_ok=True)
        _client = chromadb.PersistentClient(path=DB_PATH)
    return _client

def query_source(collection_name: str, query: str, n: int) -> list[dict]:
    if not HAS_CHROMADB:
        return []
    client = get_client()
    try:
        collection = client.get_or_create_collection(name=collection_name)
        results = collection.query(query_texts=[query], n_results=n)
        chunks = []
        if results['documents'] and results['documents'][0]:
            for i, doc in enumerate(results['documents'][0]):
                meta = results['metadatas'][0][i] if results['metadatas'] else {}
                chunks.append({"text": doc, "source": collection_name, "meta": meta})
        return chunks
    except Exception:
        return []

# ─── Router logic ─────────────────────────────────────────────

def route_query(query: str, max_chunks: int = MAX_CHUNKS) -> dict:
    intent = classify_intent(query)
    source_name = SOURCES.get(intent, "general_memory")

    chunks = query_source(source_name, query, max_chunks)

    # If primary source returns nothing, try general
    if not chunks and intent != "general":
        chunks = query_source("general_memory", query, max_chunks)
        source_name = "general_memory"

    # Validate each chunk
    blocked = []
    clean_chunks = []
    for ch in chunks:
        alerts = scan_injection(ch["text"])
        if alerts:
            blocked.append({"text": ch["text"][:80], "alerts": alerts})
        else:
            clean_chunks.append(ch)

    confidence = min(len(clean_chunks) / max(max_chunks, 1), 1.0)

    return {
        "source": source_name,
        "intent": intent,
        "chunks": clean_chunks,
        "blocked_chunks": blocked,
        "confidence": round(confidence, 2),
        "total_found": len(chunks),
        "total_clean": len(clean_chunks),
    }

# ─── HTTP Server ──────────────────────────────────────────────

class RouterHandler(BaseHTTPRequestHandler):

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return self._send_json(400, {"error": "invalid json"})

        if self.path == "/route":
            query = payload.get("query", "")
            if not query:
                return self._send_json(400, {"error": "missing query"})
            max_chunks = int(payload.get("max_chunks", MAX_CHUNKS))
            result = route_query(query, max_chunks)
            return self._send_json(200, result)

        if self.path == "/health":
            return self._send_json(200, {
                "status": "ok",
                "chromadb": HAS_CHROMADB,
                "sources": len(SOURCES),
            })

        return self._send_json(404, {"error": "not found"})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format, *args):
        print(f"[CTX] {args[0]}")


def main():
    print(f"[CTX] Agent Context Router starting on :{PORT}")
    print(f"[CTX] ChromaDB path: {DB_PATH}")
    print(f"[CTX] ChromaDB available: {HAS_CHROMADB}")
    print(f"[CTX] Sources: {list(SOURCES.keys())}")

    server = HTTPServer(("0.0.0.0", PORT), RouterHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[CTX] Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()

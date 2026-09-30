# Agent Context Router

**HTTP gateway for AI agents. Classifies intent, fetches context, validates it, blocks poisoned chunks. Zero dependencies.**

Built after discovering that context injection is the primary attack surface for RAG-based agents.

## Problem

Agents with large knowledge bases face three problems:

1. **Token waste**: dumping all context into every prompt burns resources
2. **Context poisoning**: malicious chunks get surfaced in responses
3. **Source confusion**: the agent can't tell which source to trust

## Solution

Context Router sits between the agent and its knowledge sources:

```
Query → [Classify intent] → [Score sources] → [Fetch top-N] → [Validate] → [Return clean context]
```

- **Classification**: what kind of task? code, security, operations, general
- **Scoring**: which ChromaDB collection is most relevant?
- **Fetch**: retrieve only the top-N chunks
- **Validation**: injection patterns, entropy anomalies, blocklist check

## API

```
POST /route
{
  "query": "How do I configure the firewall?",
  "max_chunks": 5
}

Response:
{
  "source": "operations_memory",
  "intent": "operations",
  "chunks": [...],
  "blocked_chunks": [],
  "confidence": 0.87
}
```

## Quick Start

```bash
# Zero deps mode (no ChromaDB needed)
python server.py

# With ChromaDB for actual context retrieval
pip install chromadb
python server.py

# Test
curl -X POST http://localhost:8899/route -d '{"query": "test query"}'
```

## Architecture

```
                   POST /route
                       |
            +----------v----------+
            |  Query Classifier   |  ← keyword intent detection
            +----------+----------+
                       |
            +----------v----------+
            |  Source Scorer      |  ← ChromaDB collections
            +----------+----------+
                       |
            +----------v----------+
            |  Context Fetcher    |  ← top-N retrieval
            +----------+----------+
                       |
            +----------v----------+
            |  Validator          |  ← injection scan, entropy
            +----------+----------+
                       |
                   {context}
```

## Security

Validates every chunk before it reaches the agent:

- Prompt injection patterns (ignore instructions, system override, etc.)
- Shannon entropy anomalies (encrypted/packed content)
- Custom blocklist for known-bad domains and patterns
- Source integrity (which collection the chunk came from)

## Why this exists

The agent's context window is the most valuable real estate in AI security.
Control the context, control the agent. This router is the gatekeeper.

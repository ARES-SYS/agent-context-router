# Agent Context Router — Design Reasoning

## Origin

Built a local AI memory system with persistent storage. It worked. The AI could remember.

Then I discovered it could be poisoned.

The ingestion function blindly ingested every `.txt` file. If an attacker dropped a file with carefully crafted text, the AI would retrieve it as context and act on it. The prompt template wrapped context directly into the system prompt — no validation, no sanitization, no routing.

## The three attacks

### 1. Context poisoning via ingestion
Malicious text files get ingested → stored as vectors → retrieved as context → agent obeys embedded instructions.

### 2. Cross-collection contamination
Mixing code snippets, personal notes, and research data in one collection. An unrelated chunk gets retrieved when the agent is writing production code.

### 3. Source trust collapse
When multiple chunks match a query from different collections, the agent can't prioritize. It might trust public data over private notes.

## Design decisions

### Source scoring, not source merging

Instead of querying all sources and merging, the router scores each source
and queries only the best one. This prevents cross-contamination:
- `code_memory` for development tasks
- `general_memory` for conversation
- `security_memory` for threat analysis
- `operations_memory` for infrastructure tasks

### Validation pipeline

Every chunk passes through 3 checks before reaching the agent:
1. **Pattern scan**: regex for known injection patterns
2. **Entropy check**: Shannon entropy flags encrypted/packed content
3. **Blocklist**: known-bad domains and patterns are stripped

### Zero-dependency intent classification

Keyword-based classification with zero imports. Production deployment
should use embedding-based classification — the same model the agent
already uses, no extra dependency.

## What I would do differently

1. **Streaming validation**: validate chunks as they stream in, reducing latency
2. **Provenance chain**: track which file/URL/session each chunk came from
3. **Differential retrieval**: compare agent retrieval vs. clean baseline, flag divergence
4. **Context signing**: HMAC over retrieved context so the agent verifies integrity

## Connection to the defense ecosystem

| Tool | Role | Connection |
|------|------|-----------|
| `agent-context-router` | Context gatekeeper | This repo |
| Prompt injection guard | Input filter | Blocks malicious queries before routing |
| Oracle poisoning advisory | Threat model | Documents the attack surface |
| Agent sovereignty audit | Integrity checker | Verifies context wasn't tampered with |

The router is the last line of defense before context hits the prompt.
If it fails, the agent is compromised.

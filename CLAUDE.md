# CLAUDE.md

Guidance for working in this repository. See `docs/DEVELOPMENT.md` for the full developer guide.

## What this is

**SkillSpector** — a security scanner for AI agent skills (the kind used by Claude Code, Codex CLI, Gemini CLI). It answers "Is this skill safe to install?" by detecting prompt injection, data exfiltration, privilege escalation, supply-chain risks, malicious patterns, etc. Apache-2.0, originated at NVIDIA. Python 3.12+.

The engine is a **LangGraph workflow** that scans a skill (Git URL / zip / file / directory) and produces a SARIF 2.1.0 report, a 0–100 risk score, and formatted output (terminal / JSON / Markdown / SARIF).

## Architecture

Linear graph with a parallel analyzer fan-out (no conditional edges). Built in `src/skillspector/graph.py` via `create_graph()`, exposed as `graph` from the package.

```
START → resolve_input → build_context → [23 analyzers in parallel] → meta_analyzer → report → END
```

- **resolve_input** (`nodes/resolve_input.py`) — normalizes any input to a local dir via `input_handler.py`; sets `skill_path` and `temp_dir_for_cleanup` (caller must clean up).
- **build_context** (`nodes/build_context.py`) — reads files into `file_cache`, parses `manifest`, populates `component_metadata`, flags `has_executable_scripts`.
- **analyzers** (`nodes/analyzers/`) — each returns `AnalyzerNodeResponse` (`{"findings": list[Finding]}`); state reducer `operator.add` appends to `findings`. Three families:
  - `static_patterns_*` (14 pattern analyzers) + `static_yara` — regex/signature; run via `static_runner.run_static_patterns`.
  - `behavioral_ast` (AST1–AST8) + `behavioral_taint_tracking` (TT1–TT5) — Python AST analysis.
  - `mcp_least_privilege` (LP1–LP4), `mcp_tool_poisoning` (TP1–TP4), `mcp_rug_pull` (RP1–RP3).
  - `semantic_*` (security_discovery, developer_intent, quality_policy) — LLM-backed; emit `{"findings": []}` when `use_llm` is False.
- **meta_analyzer** (`nodes/meta_analyzer.py`) — optional per-file LLM filter/enrich of `findings` → `filtered_findings` via `LLMMetaAnalyzer`; falls back when `use_llm` is False.
- **report** (`nodes/report.py`) — applies baseline suppression, builds SARIF, computes `risk_score` / `risk_severity` (LOW/MEDIUM/HIGH/CRITICAL) / `risk_recommendation` (SAFE/CAUTION/DO_NOT_INSTALL), writes `report_body`.

State is `SkillspectorState` (TypedDict, `total=False`) in `state.py`. Data models (`Finding`, `AnalyzerFinding`, `Location`, `Severity`) in `models.py`. SARIF models in `sarif_models.py`.

## Entry points

- **CLI** (`cli.py`, Typer): `skillspector scan <path-or-url>` with `--format terminal|json|markdown|sarif`, `--output FILE`, `--no-llm`, `--baseline`. Exit code 1 if `risk_score > 50`, 2 on error.
- **MCP server** (`mcp_server.py`): exposes a `scan_skill` tool.
- **Programmatic**: `from skillspector import graph; graph.invoke({"input_path": "...", "output_format": "json", "use_llm": True})`.
- **LangGraph Studio**: `make langgraph-dev` (graph id `skillspector_scan`).

## LLM providers

Pluggable, in `providers/` — each a subpackage with `provider.py` + bundled `model_registry.yaml`. Active provider chosen by `SKILLSPECTOR_PROVIDER` (default `nv_build`): `nv_build` (build.nvidia.com), `openai`, `anthropic`, `anthropic_proxy`. Credentials: `NVIDIA_INFERENCE_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`. `SKILLSPECTOR_MODEL` overrides the default model. LLM plumbing in `llm_utils.py` (`get_chat_model`, `chat_completion`); token budgets in `constants.py`.

## Commands

All `make` targets assume an **activated venv** (`uv venv .venv && source .venv/bin/activate`).

| Task | Command |
|------|---------|
| Install (dev) | `make install-dev` |
| Run tests | `make test` (= `test-unit` + `test-integration`) |
| Coverage | `make test-cov` |
| Lint / format | `make lint` / `make format` (Ruff, line-length 100, target py312) |
| Build | `make build` |
| Docker | `make docker-build`, `make docker-smoke` |

Tests live in `tests/unit/`, `tests/integration/`, `tests/nodes/`, `tests/nodes/analyzers/`, `tests/provider/`.

## Adding / modifying an analyzer

1. Implement a node returning `{"findings": list[Finding]}`.
2. Register it in **`nodes/analyzers/__init__.py`** — add the id to `ANALYZER_NODE_IDS` and the node to `ANALYZER_NODES`. No `graph.py` change needed (edges are wired in a loop).
3. Static pattern modules expose `analyze(content, file_path, file_type) -> list[AnalyzerFinding]`; use `pattern_defaults.py` for category/remediation metadata and `static_runner` to convert to `Finding`.

## Repo conventions

- Source files carry the NVIDIA Apache-2.0 SPDX header — keep it on new files.
- Internal logging uses stdlib `logging` (`from skillspector.logging_config import get_logger`); user-facing output uses Rich `console.print()`.
- Suppression / baselines: `suppression.py` + `.skillspector-baseline.example.yaml`; see `docs/SUPPRESSION.md`.

## Branch context

The current branch `feat-automated-reasoning` is named for a feature that is **not yet implemented** — there are no "automated reasoning" references in the source as of this writing. The branch currently carries the OSS-synced 2.3.7 state (ahead of the older `main`).

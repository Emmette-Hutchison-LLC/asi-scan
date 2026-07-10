# asi-scan

**Runtime security scanner for agentic AI systems, mapped to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (ASI01–ASI10).**

`asi-scan` connects to a live **MCP** (Model Context Protocol) agent system and runs
**active, multi-step behavioral probes** — then asserts on what actually happened at
runtime: did an unauthenticated tool call really return a privileged result? did poisoned
context really persist and get re-served a turn later? did the runtime really get fooled
by a shadowing attack?

## Why it exists

Existing tooling stops short of this layer:

- **garak / Promptfoo / DeepTeam / PyRIT** test the **model prompt/response** layer and
  infer success from text output.
- **Snyk agent-scan / Invariant mcp-scan** do **static supply-chain** analysis — reading
  declared tool descriptions to flag malicious or misconfigured components.

Neither actively *exploits* a running agent system at the protocol/runtime level, and
neither maps findings to ASI01–ASI10. `asi-scan` does. Because it observes real state
instead of guessing from text, its detectors are **deterministic assertions** with a low
false-positive rate. It **complements** the static and model-layer tools — it does not
replace them.

## Status

Early development. See [`docs/design/`](docs/design/) for the v0.1 design and
[`docs/plans/`](docs/plans/) for the implementation plan.

## Install & run

```bash
uv sync --all-extras --dev
uv run asi-scan scan --target self-test --format md
```

`--target self-test` runs the bundled vulnerable mock server. Scanning any real
MCP endpoint requires `--authorize` and is only supported from v0.2 onward.

## Known limitations

Scope limits to know before pointing it at real systems:

- **Remote MCP targets are not wired yet.** Current builds run against the bundled
  self-test server (and any in-process `FastMCP` target); a `--authorize`-gated adapter for
  live stdio / HTTP MCP servers lands in a later v0.2 milestone.
- **Probes run sequentially.** No concurrency yet — scans run one probe at a time.

Resolved since v0.1: absent-tool paths now read **INCONCLUSIVE** rather than SAFE; a probe
that raises is **isolated** (recorded as an INCONCLUSIVE finding while the scan continues);
`call_tool` surfaces MCP `isError` results instead of swallowing them; and SARIF `level`
reflects each finding's **severity** (CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO →
note).

## Intended use & safety

`asi-scan` is an offensive dual-use security tool. Use it only against systems you are
authorized to test — authorized security assessments, your own deployments, security
research, and CTF/education. It ships pointed only at a bundled deliberately-vulnerable
mock server; scanning any other target is opt-in and requires explicit authorization.

## License

MIT © Emmette Hutchison LLC

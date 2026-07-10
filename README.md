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

## Known limitations (v0.1)

v0.1 runs against the bundled self-test server; remote MCP targets arrive in v0.2. A few
deliberate scope limits to know before pointing it at real systems:

- **Absent tools read as SAFE, not INCONCLUSIVE.** If a target does not expose the tool a
  probe needs, that probe currently reports SAFE rather than INCONCLUSIVE. The deterministic,
  low-false-positive guarantee holds for targets that expose the expected tools.
- **No per-probe error isolation yet.** A probe that raises aborts the scan; probes run
  sequentially.
- **MCP tool errors are not distinguished.** `call_tool` does not yet inspect the MCP
  `isError` flag.
- **SARIF severity is uniform.** All results are emitted at SARIF `level: error` regardless
  of finding severity.

These are tracked for v0.2, when remote-target support lands.

## Intended use & safety

`asi-scan` is an offensive dual-use security tool. Use it only against systems you are
authorized to test — authorized security assessments, your own deployments, security
research, and CTF/education. It ships pointed only at a bundled deliberately-vulnerable
mock server; scanning any other target is opt-in and requires explicit authorization.

## License

MIT © Emmette Hutchison LLC

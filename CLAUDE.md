# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Knowledge graph (read this first)

A pre-built knowledge graph of this codebase lives in `graphify-out/`. Before exploring
the source by hand, treat questions about architecture, file relationships, or "where does X
live" as a **graphify query** — run the `/graphify` skill against it instead of grepping cold.

- `graphify-out/GRAPH_REPORT.md` — human-readable overview: 1998 nodes / 4532 edges across
  ~112 communities, the **god nodes** (most-connected abstractions, e.g. `rich_echo()`,
  `_get_instance_port()`, `simplify_response()`, `safe_get()`, `validate_address()`),
  community hubs, surprising cross-module connections, and knowledge gaps.
- `graphify-out/graph.json` — full graph data; `graph.html` — interactive viewer.

The report is the fastest way to learn the big-picture structure without reading dozens of files.

## What this is

GhydraMCP connects [Ghidra](https://ghidra-sre.org/) to AI assistants for reverse engineering.
It is **three components that all speak the same HATEOAS REST API**:

1. **Java Ghidra plugin** (`src/main/java/eu/starsong/ghidra/`) — a Javalin/Jetty HTTP server
   embedded in Ghidra that exposes the program over REST. This is the source of truth.
2. **Python CLI `ghydra`** (`ghydra/`) — Click + Rich terminal client. **The recommended path.**
3. **Python MCP bridge** (`bridge_mcp_hydra.py`) — single-file MCP server.

The CLI and the bridge are two independent clients of the same HTTP API; a feature added to the
plugin generally needs wiring into both.

## Multi-instance model

Each open Ghidra CodeBrowser runs its own HTTP server on a port in the range **8192–8447**
(first window 8192, second 8193, …). Clients auto-discover running instances by scanning that
range. Most operations target "the current instance"; every CLI command and MCP tool accepts an
optional `port` to address a specific one. In the bridge, `_get_instance_port()` is the central
resolver for this.

## Build & test commands

### Java plugin (Maven, Java 21, Ghidra 11.x/12.x)

The build needs Ghidra module jars: set `GHIDRA_HOME` to your install (recommended) or drop the
jars in `lib/`. `-Dghidra.version` must match the install.

```bash
GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC mvn clean package -Dghidra.version=12.1.2
# -> target/Ghydra-[version].zip            (plugin only)
# -> target/Ghydra-Complete-[version].zip   (plugin + bridge)

mvn clean package -P plugin-only       # plugin zip only
mvn clean package -P complete-only     # combined package only
mvn test                               # JUnit tests in src/test/java
```

Iterating on the installed extension: rebuild, swap `lib/Ghydra.jar` into the installed
extension, restart Ghidra.

### Python CLI / bridge (Python 3.11+)

```bash
pip install -e .          # installs `ghydra` and `ghydramcp` console scripts
ghydra instances list     # smoke test against a running Ghidra
```

### Tests (require a running Ghidra with the plugin loaded)

These are **integration tests against a live instance** — they auto-skip if Ghidra isn't
reachable (default port 8192). There is no mock layer.

```bash
python run_tests.py            # all suites
python run_tests.py --http     # HTTP API tests only (test_http_api.py)
python run_tests.py --mcp      # MCP bridge tests only (test_mcp_client.py)

# Run a single suite / single test directly:
python test_http_api.py
python -m unittest test_http_api.GhydraMCPHttpApiTests.test_functions_endpoint
```

`test_javalin_port.py`, `test_data_operations.py`, `test_comments.py` cover edge cases and
mutation round-trips (mutate, then revert).

## Java plugin architecture

Layered, registered in `GhydraPlugin.java` → `server/GhydraServer.java`:

- **`server/`** — `GhydraServer` builds the Javalin app and registers `Resource`s;
  `GhidraContext` carries per-request access to the current `Program`/`PluginTool`;
  `GsonMapper` is the JSON mapper.
- **`resource/`** — one class per REST namespace (`FunctionResource`, `DataResource`,
  `StructResource`, `SymbolResource`, `AnalysisResource`, …). Resources are thin route handlers.
- **`service/`** — business logic and actual Ghidra API access (`FunctionService`,
  `DecompilerService`, `StructService`, …). **Put logic here, not in resources.**
- **`dto/`** — request/response objects (`FunctionDto`, `StructDto`, …); most expose a static
  `from(...)` factory that maps a Ghidra object to the DTO.
- **`hateoas/`** — `Response`, `Links`, `Paginator`, `PaginatedResult`: every response is the
  standard `{id, instance, success, result, timestamp, _links}` envelope; lists add
  `size/offset/limit` plus `next`/`prev` links.
- **`middleware/`** — `CorsHandler`, `ErrorHandler` (controlled error envelopes / status codes).
- **`util/`** — `TransactionHelper` (wrap program mutations in a Ghidra transaction),
  `GhidraSwing`/`GhidraSupplier` (marshal onto the Swing EDT), `DecompilerCache`, `GhidraUtil`
  (address/data-type resolution, e.g. `resolveDataType` for `uint32_t[4]`-style syntax).
- **`api/ApiConstants.java`** — `PLUGIN_VERSION` and `API_VERSION`.

Any operation that changes the program must run inside a transaction (via `TransactionHelper`)
and on the EDT (via `GhidraSwing`/`GhidraSupplier`).

## Python CLI architecture (`ghydra/`)

- **`cli/`** — one Click command group per namespace (`functions.py`, `data.py`, `structs.py`,
  `analysis.py`, `instances.py`, …); `main.py` is the entry point (`cli`).
- **`client/`** — `http_client.py` (`GhidraHTTPClient`, the GET/POST/PATCH/PUT/DELETE wrapper),
  `models.py`, `exceptions.py` (`GhidraConnectionError`, `GhidraAPIError`).
- **`formatters/`** — `BaseFormatter` interface with `TableFormatter` (default, Rich tables) and
  `JSONFormatter` (selected by global `--json`). Add a format method to all three when adding a
  command with new output.
- **`config/`** — `ConfigManager` reads `~/.ghydra` config.
- **`utils/`** — `validators.py` (`normalize_hex_address`, port/byte validation), `output.py`
  (Rich markup), `pager.py`.

Global flags on every command: `--host`, `--port`, `--json`, `--no-color`.

## Conventions

- **API version compatibility is enforced at runtime.** The bridge checks `REQUIRED_API_VERSION`
  against the plugin's `API_VERSION`. Only bump `API_VERSION` (`api/ApiConstants.java` +
  `REQUIRED_API_VERSION` in `bridge_mcp_hydra.py`) for **breaking** API changes. Bump
  `PLUGIN_VERSION` / `BRIDGE_VERSION` for any change to the respective component.
- **Fully-qualified names (FQN):** functions, symbols, data, variables, and xrefs are matched by
  namespace-qualified name (`MyClass::method`); a bare name resolves in the global namespace
  only; renaming with `::` moves a symbol into that namespace (created if absent). Local
  variables are not namespaced.
- **Timeouts are intentionally large** for big binaries: HTTP `GHYDRA_TIMEOUT` default 900s,
  decompile `GHYDRA_DECOMP_TIMEOUT` default 1200s. Incomplete decompiles return retry metadata.
- The bridge's `simplify_response()` strips `id`/`instance`/`timestamp` from the top level of
  responses before returning them to the MCP client.
- Conventional-commit messages (`feat:`, `fix:`, `docs:`, …); update `CHANGELOG.md` for
  user-facing changes; branch as `feature/…`, `fix/…`, `docs/…`.

## Reference docs

- `README.md` — full tool/namespace catalog and client setup.
- `GHIDRA_HTTP_API.md` — REST endpoint reference. `GHYDRA_CLI.md` — full CLI reference.
- `CONTRIBUTING.md` — versioning rules, release process. `TESTING.md` — test details.

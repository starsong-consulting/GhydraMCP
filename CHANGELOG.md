# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `GET /analysis/callpaths` + `analysis_find_call_paths` tool + `ghydra analysis call-paths`: bounded call-path discovery between two functions.
- `GET /analysis/strings/usage` + `analysis_trace_string_usage` tool + `ghydra analysis string-usage`: string-usage tracing with an optional reverse-call-graph walk.
- **Unicorn dynamic emulation:** Python-side [Unicorn Engine](https://www.unicorn-engine.org/) x86-64 emulation (`unicorn_*` MCP tools, `ghydra dynamic` CLI) with lazy page mapping from the Ghidra image — unmapped pages are fetched on demand over the existing `/memory` API, so an agent can emulate code (e.g. an in-binary unpacker) and read back the decrypted bytes without a live debugger. Engine talks to Ghidra through an injected byte-provider, so it is unit-testable with a fake client (no Ghidra required). Optional extra: `pip install ghydramcp[unicorn]`.
- **PCode emulation (dynamic analysis):** drive Ghidra's built-in `EmulatorHelper` over the API — `/emulation/*` REST endpoints, `emulation_*` MCP tools, and a `ghydra emulation` CLI group. Reset a session at an address, run/step (with optional instruction-address tracing), read/write registers and memory, and set/clear breakpoints — e.g. to run a function and read back the emulated output (unpacking, decryption). One session per program; pure PCode interpretation bounded by `max_steps` (no live OS process); sessions are freed on plugin teardown. Adds the Ghidra `Emulation` module jar to the build. Plugin → `v3.1.0-rc.1`, bridge → `v3.1.0-rc.1` (API_VERSION unchanged — additive).
- **Unicorn emulation hardening:** distinct `LAZY_CAP_REACHED` stop reason when the lazy-page budget (`max_lazy_pages`) is exhausted (was a generic `ERROR`); an explicit zero-fill map primitive (`unicorn_map` MCP tool + `ghydra dynamic map`) and an opt-in default scratch stack on `unicorn_reset` (`stack=True`) so stack-using code runs without manual mapping; a `trace_truncated` signal when a trace hits the cap; and a lock around the Unicorn session registry. `ProviderError` now subclasses `GhidraError`. Bridge → `v3.1.0-rc.3` (API_VERSION unchanged — additive).
- Unicorn engine: import/syscall hooking (`unicorn_hook_set/clear/list`) with
  return_const/skip/log/trap actions, and a high-level `unicorn_call(func, args)`
  primitive (x86-64 SysV/MS) that stubs imports and reports the return value.
  Bridge bumped to v3.1.0-rc.4 (additive; API_VERSION unchanged).

### Fixed
- **Compound-RE operations no longer silently claim completeness.** `/analysis/callpaths` now reports `unresolved_edges` — call edges the DFS could not traverse (thunks/PLT stubs, indirect/computed calls, non-entry targets); an empty `paths` with `unresolved_edges > 0` does not prove `from` cannot reach `to`. `/analysis/strings/usage` reports `unresolved_refs` — references whose source is outside a defined function, so a non-zero value means `directUsers`/`callers` under-report. Both counters surface in the bridge tool output and the CLI table header. The `callpaths` `self` link now URL-encodes `from`/`to` (FQNs may contain `::`/`&`/spaces). The three compound-RE DTOs (`CallPathDto`, `CallerRefDto`, `StringUsageDto`) now enforce their invariants in the canonical constructor (length/size match, `depth >= 1`, non-null, immutable defensive copies) rather than only in the `of()` factory. Doc fix: `truncated` is set by `max_paths`/`max_visited_edges`, not `max_depth`; HTTP-API example responses corrected to show function-summary objects (not bare names). Plugin → `v3.2.1`, bridge → `v3.3.1` (API_VERSION unchanged — additive fields).
- **Unicorn emulation fails loud on missing image bytes:** the lazy page mapper now serves only real Ghidra image bytes. Any address Ghidra cannot satisfy faults with a distinct `LAZY_FETCH_FAILED` stop reason and a surfaced `last_error`, instead of silently mapping a zero page and reporting `success: true`. `unicorn_run` now derives `success` from the stop reason (true only for `DONE`; `COUNT`/`ERROR`/`LAZY_FETCH_FAILED` return `success: false` with an error envelope so the cause is surfaced), and `ghydra dynamic dump` aborts (non-zero exit, no hex on stdout) on a faulted run while `ghydra dynamic run` prints `last_error`. Bridge → `v3.1.0-rc.2` (API_VERSION unchanged — field values only).

## [3.0.0-rc.1] - 2026-06-18

### Changed
- **Breaking: fully-qualified symbol names.** Functions, symbols, data labels, variables, and xrefs now use the fully-qualified name (namespace path, e.g. `FOM::SharedMemory::ReadUInt`; global-namespace members are unprefixed) for lookup, filtering, and output. `GET /functions/by-name/{fqn}` takes a URL-encoded FQN; a bare name resolves in the global namespace only. Renaming a function, data label, or symbol to an `A::B::name` value moves it into that namespace (created if absent); a leading `::` or `Global::` moves it to the global namespace. The separate `namespace` field is removed from function and symbol responses (folded into the FQN `name`). Local variable names stay bare and reject `::`. `API_VERSION` bumped to 3000. Reimplemented from PR #18 against the Javalin layer. (#18)

### Added
- **`analysis` link on `/program`:** the program resource now advertises an `analysis` link (to `/analysis/status`) for HATEOAS discoverability.
- **Run Ghidra scripts via the API:** `GET /scripts` (list) and `POST /scripts/run` (run an existing script by `name`, or compile and run ad-hoc GhidraScript `source`, with `args`), plus `scripts_list`/`scripts_run` bridge tools and `ghydra scripts list`/`run`. Captures the script's output. Lets an agent do multi-stage/batch work (mass rename, signature transfer) in one call. Arbitrary code execution, so it is disabled unless the server is started with `-Dghydra.dev.allowScripts=true` (or `GHYDRA_ALLOW_SCRIPTS=1`). (#3)
- **Scalar search:** find constant values in instructions (`GET /scalars`, `scalars_search` bridge tool, `ghydra scalars search`), like Ghidra's "Search For Scalars". Filter by containing function (`in_function`) or by a nearby called function (`to_function`, e.g. the `0` passed to `memset`). The `in_function` filter scans only the matching functions; unfiltered scans on large programs are time-bounded and report `scanTruncated`. Reimplemented from PR #17 against the Javalin layer. (#17)
- **Save endpoint:** `POST /program/save` persists the current program to the project (`?all=true` saves every open program with unsaved changes).
- **Dev-only shutdown endpoint:** `POST /dev/shutdown` quits Ghidra so the build/deploy/restart loop can be automated. Off by default; enable with `-Dghydra.dev.allowShutdown=true` or `GHYDRA_DEV_SHUTDOWN=1`. With unsaved changes it refuses (409) unless `?save=true` (save, then exit) or `?force=true` (discard, then exit).

### Fixed
- **HATEOAS links:** templated links with a single string argument (an address or name) emitted a literal `{}` href with the value misplaced into a `method` field; they now substitute correctly across all endpoints. Action links use a new `linkWithMethod`.
- **Disassembly truncation:** the bridge text output now reports the total instruction count and the next offset when a function's disassembly is paginated, instead of silently showing the first 100. `functions_disassemble` no longer documents `limit=0` as "all".
- **Agent-clean CLI output:** color is auto-disabled when stdout is not a terminal (and honors `NO_COLOR`), so piped or captured `ghydra` output no longer carries ANSI codes that corrupted hex-address parsing.

## [3.0.0-beta] - 2026-06-16

### Changed
- **Ghidra 11.x + 12.x:** The plugin builds and runs against both Ghidra 11.x and 12.x; CI builds a matrix over the latest of each. Per-version extension artifacts are stamped with the matching `ghidraVersion` (which must equal the running Ghidra exactly).
- **Ghidra 12.x:** Migrated the plugin to build against Ghidra 12.x (tested on 12.1.2). Build with `GHIDRA_HOME` pointing at the install, or `-Dghidra.version=` to stamp the extension.
- **Javalin HTTP server:** The plugin now embeds a Javalin/Jetty server with a layered `resource`/`service`/`dto`/`hateoas`/`middleware`/`server` structure, replacing the previous JDK `HttpServer` + `endpoints/` implementation. Shaded into a single `Ghydra.jar`.

### Fixed
- **Locked buffer crashes:** DB-iterator traversals are marshalled onto the EDT (`GhidraSwing.runRead`), fixing `IOException: Locked buffer` crashes during concurrent analysis.
- **StackOverflow containment:** A self-referential pointer made Ghidra's own label resolution recurse without bound; reads now contain the resulting `Error` and fail the request cleanly instead of crashing the EDT.
- **Call graph callees:** Callee discovery scans the whole function body instead of just the entry address, so `/analysis/callgraph` and `/analysis/callees` return results.
- **Client errors return 400:** Malformed input (bad addresses, hex, JSON bodies, invalid params) maps to HTTP 400 instead of 500; `/xrefs` pagination no longer returns empty pages past the first.
- **Bridge/CLI field sync:** Bridge and CLI formatters match the server's response field names (decompilation, variables, xrefs, segments, memory), and integral JSON numbers are no longer rendered as floats.

## [2.0.0] - 2025-11-11

### Added
- **MCP Integration Refactor:** Refactored the Python bridge for improved MCP integration. (337f89e)
  - Introduced MCP resources for loading context (e.g., instances, functions, disassembly).
  - Added namespaced tools (e.g., `instance.*`, `function.*`, `data.*`) for better organization and discoverability.
  - Implemented a "current working instance" concept to simplify commands by implicitly targeting the active Ghidra instance.
- **Analysis Prompts:** Added pre-defined prompts for common analysis tasks, including `reverse_engineer_binary` for comprehensive analysis. (337f89e, 3134581)
- **String Data Listing:** Added a new endpoint to list string data in the binary, with pagination and filtering by content. Python bridge support via `list_strings()` function. (f71f4aa)
- **Comprehensive Data Manipulation:** Added tools/endpoints for creating (`create_data`), deleting (`delete_data`), renaming (`rename_data`), changing type (`set_data_type`), and combined updates (`update_data`) for data items. Supports common types (byte, word, dword, string, etc.). (6c28553, 5797fb3, 28870e9)
- **Enhanced Cross-Reference (Xrefs) Analysis:** Implemented accurate xref tools (`get_references_to`, `get_references_from`) using Ghidra's ReferenceManager. Features include detailed info, bi-directional search, type filtering, and simplified bridge output. (96788f3)
- **Memory Operations:** Added tools/endpoints for reading (`read_memory`) and writing (`write_memory`) to program memory. (454c739)
- **Function Addressing Flexibility:** MCP bridge now supports addressing functions by name or address. (4f3042f)
- **API Version Check:** Bridge script now verifies compatibility with the Java plugin (expects API v2). (fedd2d0)
- **Enhanced Decompiler Controls:** Added options for raw vs. clean pseudocode output and multiple simplification styles. (454c739)

### Changed
- **Bridge Refactor & Namespacing:** Reorganized bridge tools into namespaces (e.g., `instance.list_instances`, `function.get_function_details`) as part of the MCP integration refactor. (337f89e)
- **Breaking: HATEOAS API v2 & Bridge Update:** Migrated fully to a HATEOAS-driven API (v2). The Python bridge (`bridge_mcp_hydra.py`) now *exclusively* uses this API, removing legacy support. Responses are simplified for AI agents, including text representations for structured data (e.g., disassembly). All endpoints require HATEOAS compliance (e.g., `_links`). (4bc2267, 4f3042f)
- **Optimized Variable Listing:** Improved performance of the `/variables` endpoint with efficient pagination and a `globalOnly` filter. (6c865c4)
- **Standardized Responses:** Unified all endpoints to use structured JSON and standardized HATEOAS links. (454c739, 4bc2267)
- **Improved Error Handling:** Enhanced error reporting and parameter validation across the API and bridge. (454c739, 4f3042f, 3df129f)
- **API Documentation:** Updated documentation to reflect the HATEOAS v2 API and new features. (28870e9, 3fd0cf4)

### Fixed
- **Real Instruction Disassembly:** The `/disassembly` endpoint now provides actual instruction disassembly instead of placeholders. (3df129f)
- **Ghidra 11+ Compatibility:** Resolved various API compatibility issues, particularly for cross-references (`XrefsEndpoints`). (5dc59ce, 2b1fe6c, 0eaa19a, 9443101)
- **Data Operations:** Fixed issues with HTTP request body consumption, parameter naming (`type` vs `dataType`), and name preservation during type changes. (28870e9)
- **Function Commenting:** Corrected `set_decompiler_comment` to apply comments at the function level. (2a1607c)
- **Call Graph Parameter Handling:** Updated the CallGraph endpoint to properly accept both function name and address parameters for flexibility. (fa8cc64)
- **Endpoint Functionality:** Addressed various issues including endpoint registration, handling of program-dependent endpoints, URL encoding, transaction management, and inconsistent response formats. (various commits, e.g., 4bc2267)

## [1.4.0] - 2025-04-08

### Added
- Structured JSON communication between Python bridge and Java plugin
- Consistent response format with metadata (timestamp, port, instance type)
- Comprehensive test suites for HTTP API and MCP bridge
- Test runner script for easy test execution
- Detailed testing documentation in TESTING.md
- Origin checking for API requests
- Mutating tests for API functionality

### Changed
- Improved error handling in API responses
- Enhanced JSON parsing in the Java plugin
- Updated documentation with JSON communication details
- Standardized API responses across all endpoints
- Improved version handling in build system

### Fixed
- Build complete package in `package` phase
- Versioning and naming of JAR files
- GitHub Actions workflow permissions
- Extension ZIP inclusion in complete package
- ProgramManager requirement
- Git tag fetching functionality
- MCP bridge test failures

## [1.3.0] - 2025-04-02

### Added
- Added docstrings for all @mcp.tool functions
- Variable manipulation tools (rename/retype variables)
- New endpoints for function variable management
- Dynamic version output in API responses
- Enhanced function analysis capabilities
- Support for searching variables by name
- New tools for working with function variables:
  - get_function_by_address
  - get_current_address
  - get_current_function
  - decompile_function_by_address
  - disassemble_function
  - set_decompiler_comment
  - set_disassembly_comment
  - rename_local_variable
  - rename_function_by_address
  - set_function_prototype
  - set_local_variable_type

### Changed
- Improved version handling in build system
- Reorganized imports in bridge_mcp_hydra.py
- Updated MANIFEST.MF with more detailed description

## [1.2] - 2025-03-30

### Added
- Enhanced function analysis capabilities
- Additional variable manipulation tools
- Support for multiple Ghidra instances

### Changed
- Improved error handling in API calls
- Optimized performance for large binaries

## [1.1] - 2025-03-30

### Added
- Initial release of GhydraMCP bridge
- Basic Ghidra instance management tools
- Function analysis tools 
- Variable manipulation tools

## [1.0] - 2025-03-24

### Added
- Initial project setup
- Basic MCP bridge functionality

[unreleased]: https://github.com/starsong-consulting/GhydraMCP/compare/v3.0.0-rc.1...HEAD
[3.0.0-rc.1]: https://github.com/starsong-consulting/GhydraMCP/compare/v3.0.0-beta...v3.0.0-rc.1
[2.0.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.2...v1.3.0
[1.2]: https://github.com/teal-bauer/GhydraMCP/compare/v1.1...v1.2
[1.1]: https://github.com/teal-bauer/GhydraMCP/compare/1.0...v1.1
[1.0]: https://github.com/teal-bauer/GhydraMCP/releases/tag/1.0
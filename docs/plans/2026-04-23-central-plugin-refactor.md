# Central Plugin Refactor — Design Note

> One HTTP server on port 8192 in the FrontEndTool. All program data reachable via path-based
> addressing. No per-CodeBrowser ports. Headless-cached Program access so files work whether
> or not a CodeBrowser has them open.

## Goals

- One port, one plugin instance (FrontEndTool)
- URL addresses every program by path: `/files/{urlencoded_path}/...`
- File-scoped endpoints auto-open the program headlessly if no tool has it loaded
- Tool-scoped endpoints (`/tools/{name}/...`) for cursor/selection state
- Cache opened programs with a short idle TTL
- No forwarding or proxying between ports — 8192 is the only port

## Ghidra constraints that shape this

1. `Plugin` classes instantiate per `Tool` by default. `ApplicationLevelOnlyPlugin` is the
   Ghidra-provided marker that restricts a plugin to the FrontEndTool only.
2. `Program` objects are consumer-refcounted. Opening a file via
   `DomainFile.getDomainObject(consumer, ...)` requires releasing with
   `program.release(consumer)` when done. Leaking a consumer prevents proper close.
3. Same `Program` instance is shared across tools. If a CodeBrowser has testbin open and we
   separately open it headlessly, we get the same DB (Ghidra's open-program-cache ensures
   this), so edits are visible across tools.
4. Auto-analysis runs on the tool that opened the file; it holds long-running transactions.
   Our `TransactionHelper` already handles nested-endTransaction false-return — keeps working.

## URL mapping

Single source of truth for what moves where. `{path}` is always URL-encoded.

### Dropped (no longer useful in single-port model)

| Old | Why |
|-----|-----|
| `GET /instances` | Replaced by `GET /tools` + `GET /files` |
| `GET /instances/{port}` | No ports to list |
| `POST /registerInstance`, `POST /unregisterInstance` | Bridge used these for cross-instance coordination; unneeded |

### Top-level (no file/tool context)

| Old | New | Notes |
|-----|-----|-------|
| `GET /` | `GET /` | Unchanged — root links update |
| `GET /info` | `GET /info` | Unchanged |
| `GET /plugin-version` | `GET /plugin-version` | Unchanged |
| `GET /project` | `GET /project` | Unchanged (already project-scoped) |
| `GET /project/files` | `GET /files` | Renamed for consistency |
| `POST /project/open` | `POST /tools/new?file={path}` OR `POST /tools/{name}/files/{path}/open` | New shape — see Tool-scoped |
| `GET /projects` | Drop | Only one project ever open |
| `GET /projects/{name}` | Drop | Same |

New:
- `GET /files/{path}` — single file info (returns `{path, contentType, isOpen, inTool, fileId, version}`)
- `GET /tools` — list running tools with metadata (name, toolType, openFiles[])
- `GET /tools/{name}` — single tool detail

### File-scoped — every program-data endpoint moves here

All of these auto-open the file headlessly if it isn't already open.

| Old | New |
|-----|-----|
| `GET /program`, `/programs/current` | `GET /files/{path}/program` |
| `GET /functions` | `GET /files/{path}/functions` |
| `GET /functions/{address}` | `GET /files/{path}/functions/{address}` |
| `GET /functions/{address}/decompile` | `GET /files/{path}/functions/{address}/decompile` |
| `GET /functions/{address}/disassembly` | `GET /files/{path}/functions/{address}/disassembly` |
| `GET /functions/{address}/variables` | `GET /files/{path}/functions/{address}/variables` |
| `PATCH /functions/{address}` | `PATCH /files/{path}/functions/{address}` |
| `DELETE /functions/{address}` | `DELETE /files/{path}/functions/{address}` |
| `POST /functions` | `POST /files/{path}/functions` |
| `PATCH /functions/{address}/variables/{varName}` | `PATCH /files/{path}/functions/{address}/variables/{varName}` |
| `GET /functions/by-name/{name}` + subtree | `GET /files/{path}/functions/by-name/{name}` + subtree |
| `GET /data`, `/strings`, `/data/{address}` | `GET /files/{path}/data`, `/files/{path}/strings`, `/files/{path}/data/{address}` |
| All `/data/{address}` mutations (PUT/POST/PATCH/DELETE + legacy `/data/update`, `/data/type`, `/data/delete`) | Same prefix under `/files/{path}/data/...` |
| `GET /memory`, `/memory/search`, `/memory/{address}`, `/memory/{address}/disassembly` | `/files/{path}/memory/...` |
| `GET`, `POST /memory/{address}/comments/{type}` | `/files/{path}/memory/{address}/comments/{type}` |
| `PATCH /programs/current/memory/{address}` | `PATCH /files/{path}/memory/{address}` — and rename (memory write now a PATCH on memory, not under programs/current) |
| `GET /symbols` + subtree | `GET /files/{path}/symbols` + subtree |
| `GET /segments`, `/segments/{name}` | `/files/{path}/segments`, `/files/{path}/segments/{name}` |
| `GET /xrefs` + all variants | `/files/{path}/xrefs` + all variants |
| `GET /analysis/status`, `POST /analysis/run`, `GET /analysis/dataflow`, `GET /analysis/callgraph`, `/callers`, `/callees` | `/files/{path}/analysis/...` |
| `GET /structs` + full CRUD subtree + legacy POST routes | `/files/{path}/structs/...` |
| `GET /datatypes`, `POST /datatypes/{struct,enum,union}` | `/files/{path}/datatypes/...` |
| `GET /variables` | `GET /files/{path}/variables` |
| `GET /classes`, `/namespaces` | `/files/{path}/classes`, `/files/{path}/namespaces` |

### Tool-scoped (interactive / cursor state)

| Old | New |
|-----|-----|
| `GET /address` | `GET /tools/{name}/address` |
| `GET /function` | `GET /tools/{name}/function` |

New:
- `POST /tools/new?file={path}` — spawn a new CodeBrowser for a file, returns the tool name
- `POST /tools/{name}/files/{path}/open` — open a file in an existing tool
- `POST /tools/{name}/files/{path}/close` — close
- `GET /tools/{name}/files` — what files the tool has open

## Key new components

### `GhydraPlugin` changes
- `implements ApplicationLevelOnlyPlugin` instead of `ApplicationLevelPlugin`
- Constructor no longer chooses a port — always 8192 (or fails to start)
- Drops `activeInstances` static map (no multi-instance)
- Stores references to the `ToolManager` for discovering CodeBrowsers at request time

### `ProgramResolver` (new service, util layer)

Resolves URL path `{urlencoded_file_path}` to a live `Program` reference.

Algorithm:
1. URL-decode the path
2. Look up `DomainFile` via `project.getProjectData().getFile(path)`. 404 if null.
3. Walk `toolManager.getRunningTools()`. For each tool, ask its `ProgramManager` service for
   `getAllOpenPrograms()`. If any matches this `DomainFile`, borrow it (add ourselves as an
   additional consumer).
4. If no tool has it, check our own `ProgramCache`. Return the cached one (refresh TTL) if
   present.
5. Otherwise, call `DomainFile.getDomainObject(programCache, false, false, monitor)` to
   open headlessly. Store in cache with `(program, addedAt, lastAccessedAt)`.
6. Always `program.addConsumer(this)` while the request is live; release after handler
   returns — a try-with-resources-style wrapper in the context.

### `ProgramCache` (new util)

- `ConcurrentHashMap<String, CachedProgram>` keyed by canonical path
- Each entry: `{program, openedAt, lastAccessedAt, consumer}`
- Background thread (ScheduledExecutor) evicts entries idle > 60s
- On evict: `program.release(consumer)` — Ghidra closes it if no other consumer holds a ref
- On plugin `dispose()`, evict all

### `GhidraContext` changes

- New method `resolveProgram()` — replaces `requireProgram()`. Uses URL path param (Javalin
  `ctx.pathParam("path")`), delegates to `ProgramResolver`. Program lifecycle managed per
  request (consumer add/release).
- `tool()` becomes `resolveTool()` — URL-based tool lookup for `/tools/{name}/...` routes

### Resource registration — prefix wrapping

Every resource wraps its routes in a Javalin router group:

```java
app.routes(() -> {
    path("/files/{path}", () -> {
        path("/functions", () -> {
            get(ctx -> list(toGhidraCtx(ctx)));
            get("/{address}", ctx -> getByAddress(toGhidraCtx(ctx)));
            // ...
        });
    });
});
```

Each resource owns its subtree registration — keeps code local.

## Files to touch

**New:**
- `util/ProgramCache.java` (~120 LOC)
- `util/ProgramResolver.java` (~80 LOC)

**Structurally changed:**
- `GhydraPlugin.java` — marker interface, constructor, remove activeInstances
- `server/GhidraContext.java` — `resolveProgram()`, `resolveTool()`
- `server/GhydraServer.java` — register routes under new prefixes

**Route updates (17 resources):** all switch to `resolveProgram()` and move under file prefix.

**Special cases:**
- `InstanceResource.java` — deleted entirely (functionality moves to ToolResource/FileResource)
- `ProjectResource.java` — simplified (drop `/projects/*`)
- `UiResource.java` — routes change to `/tools/{name}/address`, `/function`
- `RootResource.java` — updated link list on `GET /`
- New `ToolResource.java` for `/tools`, `/tools/{name}`, `/tools/new`

**Bridge + CLI:** every URL in `bridge_mcp_hydra.py` and `ghydra/cli/` changes. Most are
simple f-string edits (add `files/{file}/` prefix).

**Tests:** rewrite all test URLs. Add an env var `GHYDRAMCP_TEST_FILE` for the file path to
scope endpoints to.

**Docs:** README, CLAUDE.md, plan doc itself.

## Migration / rollback

- Do this on a sub-branch off `feat/javalin-port` so we can A/B
- Land the multi-port version as-is (48/0/5) first, then the central-plugin version on top
- If central-plugin regresses anything subtle, revert the top commits, keep multi-port

## Open questions I'll default on

Unless you say otherwise:
- Cache TTL: 60s idle
- Cache max size: 16 programs (LRU evict on overflow)
- Tool name source: `tool.getName()` is the primary key (e.g. "CodeBrowser", "Debugger"). If
  two tools share a name, append a numeric suffix — resolved via a stable ordering.
- URL encoding for file paths: standard percent-encoding; we URL-decode on the server
- Error code if requested file doesn't exist: 404 with `FILE_NOT_FOUND`
- Error code if file exists but can't be opened (corrupt / wrong version): 500 with
  `FILE_OPEN_FAILED`

## Estimated cost

- New components: ~200 LOC
- 17 resource files: mechanical prefix adds, ~30 min total
- Test rewrites: ~1 hour
- Bridge + CLI prefix edits: ~45 min
- Verification against live Ghidra with multiple CodeBrowsers: ~30 min
- Total: **3–4 hours focused work** plus one live smoke cycle

## Not in scope (follow-ups)

- Versioned API prefix (`/v2/files/...`) — add only if we need to coexist with the old
  shape. Simpler to break once.
- WebSocket push for program changes — the old Javalin rewrite included WebSocket server
  jars but never wired up events. Separate feature.
- Authentication — no plugin currently has auth; this refactor doesn't add it.

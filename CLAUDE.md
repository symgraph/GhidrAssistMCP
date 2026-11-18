# GhidrAssistMCP workspace guide

GhidrAssistMCP is a Ghidra extension exposing static analysis, annotation, project operations, and program data through MCP. Work through the workspace symlink and preserve unrelated user changes. Never add a Co-Authored-By commit line.

## Build and validation

Use Java 25 or newer and the Gradle version supported by the selected Ghidra installation. The wrapper pins a supported Gradle release. The workspace's documented installation is Ghidra 12.0; Ghidra 12.1 is also available locally.

```bash
GHIDRA_INSTALL_DIR=/home/jtang613/tools/ghidra_12.0_PUBLIC /opt/gradle/bin/gradle buildExtension test
```

The product release version is `3.1.0`, declared in `build.gradle` and the backend server metadata. Keep them synchronized when bumping releases. ZIPs and jar manifests carry that version. `extension.properties.version` must retain the Ghidra compatibility token.

The extension ZIP is written to `dist/`. `installExtension` changes the Ghidra installation and user extension directories; building alone does not install it. Tests are under `src/test/java/` and use JUnit Jupiter. Include HTTP protocol tests when transport behavior changes, catalog contracts for names/schemas, and focused lifetime tests for concurrency changes.

## Architecture

- `GhidrAssistMCPInitializer`: GUI module bootstrap, skipped in headless Ghidra.
- `GhidrAssistMCPApplicationPlugin`: project-manager application owner and CodeBrowser discovery.
- `GhidrAssistMCPPlugin`: lightweight CodeBrowser adapter, with per-window cursor/focus context.
- `GhidrAssistMCPManager`: one shared runtime, backend, server, configuration, and bounded log. The project manager keeps it alive after all browsers close.
- `GhidrAssistMCPProvider`: a per-window view of shared state. Providers never own the transport or independently load settings into the backend.
- `GhidrAssistMCPBackend`: catalog, validation, program resolution, result/error handling, caching, resources, prompts, and jobs.
- `GhidrAssistMCPServer`: Streamable HTTP `/mcp` plus legacy SSE `/sse` and `/message`; retains SDK server instances for live catalog changes and shutdown.
- `tools/RationalizedToolCatalog` and `tools/ExplicitTool`: operation-specific public contracts over shared implementations. The public catalog has 100 tools, 93 enabled by default.
- `project/`: GUI project creation/open/save/close through public Ghidra APIs and the application-owned frontend.
- `ProjectOperationGate`: fail-fast lifecycle exclusion across tools, resources, prompts, and physical async-worker cleanup.
- `tasks/`: custom job tracking, bounded pending work, cancellation, and execution cleanup.
- `cache/`: program identity/revision-aware raw result caching.
- `decompiler/`: isolated per-call decompiler sessions, using the owning CodeBrowser's options.

Use public Ghidra APIs. Keep Swing/ProgramManager operations on the event thread and expensive program loading, decompilation, and server lifecycle work off it. Retain program consumers across asynchronous work and release them on completion, cancellation before execution, failed submission, and shutdown.

## MCP contracts

Use descriptive `verb_noun` names. Reads and mutations should be separate public tools; keep discriminators inside shared implementations. `get_disassembly` reads instructions, while `disassemble_bytes` changes the listing. `get_function_hash` computes SHA-256; `get_function_byte_pattern` returns a masked prefix; `get_function_prototype` reads the C declaration.

Validate inputs and return `isError=true` for operation failures. Preserve all content kinds, structured content, metadata, and error flags when adding context. Output schemas must cover every successful result shape, including an initial custom async-job handle where applicable. Prefer typed results for new tools and preserve text compatibility.

Program-specific tools accept `program_name`, preferably an exact project path. Unknown/ambiguous explicit targets must never fall back to an active program. Cursor tools use the focused browser. Project/job tools declare that they do not require a program. `import_file.program_name` is the new imported program's name, not a target selector.

`create_project`, `open_project`, `save_project`, and `close_project` are synchronous lifecycle operations with structured results. They do not require a program or accept `program_name`. Declare `isProjectLifecycleOperation()` so the backend serializes transitions against other MCP work. Create/open never replace an active project. Open uses an exact absolute `.gpr` path with `restore_state=false` by default. Close defaults to refusing unsaved changes; `save` and `discard_changes` are explicit, mutually exclusive choices. Keep the frontend/runtime alive when a project closes. Saving project session metadata alone does not save dirty program files: use the controller's checked file-save path. Recheck the active project and open-data membership immediately before closing on the event thread. Automatic view attachment must preserve the existing configuration-dirty flag. Unsaved tool configuration/plugin data can still prevent safe closure after a project save; explicit discard is required to drop it. Running commands and busy domain-object locks always prevent saving/closing. The metadata-save receipt uses a private project SaveState checkpoint and verifies the persisted project-state file because Ghidra's void save API swallows I/O failures; use the JDK XML parser and keep this verification tested against supported host versions. The current public guards do not invoke plugin-specific close veto callbacks, so include installed plugins in GUI acceptance.

`import_file`, `export_program`, and script operations remain disabled by default. Legacy settings migrate to canonical operations. Old backend aliases support internal compatibility only; they are not exposed as HTTP tools. Clients must refresh their catalog after upgrade.

MCP Java SDK 2.0.1 is supplied through `mcp-core` and `mcp-json-jackson2`. Streamable HTTP supports protocol `2025-11-25`, while legacy SSE uses `2024-11-05`; full `2026-07-28` support belongs to a future SDK migration. Do not claim that the application's job tools implement the negotiated MCP Tasks extension.

Generated `lib/` may contain stale jars from prior builds. The Gradle configuration excludes those jars from compilation and packaging. Shadow bundles the selected SDK, Jackson, NetworkNT, Jetty, Servlet, Reactor, and SLF4J runtime under private `ghidrassistmcp.internal.*` packages in one jar; Ghidra API and host Gson remain external. A subprocess test loads the packaged jar after Ghidra's libraries to check isolation and HTTP behavior.

## Documentation

`README.md` describes installation, startup, endpoints, and usage. `docs/modernization-review.md` contains the complete previous-to-current tool mapping, architecture decisions, compatibility notes, proposed additions, and validation matrix. Keep them consistent with the live catalog. There are no analyzer/loader/exporter skeleton components in this extension.

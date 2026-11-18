/* 
 * 
 */
package ghidrassistmcp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.cache.McpCache;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.prompts.AnalyzeFunctionPrompt;
import ghidrassistmcp.prompts.DocumentFunctionPrompt;
import ghidrassistmcp.prompts.IdentifyVulnerabilityPrompt;
import ghidrassistmcp.prompts.McpPrompt;
import ghidrassistmcp.prompts.McpPromptRegistry;
import ghidrassistmcp.prompts.TraceDataFlowPrompt;
import ghidrassistmcp.prompts.TraceNetworkDataPrompt;
import ghidrassistmcp.resources.ExportsResource;
import ghidrassistmcp.resources.FunctionListResource;
import ghidrassistmcp.resources.ImportsResource;
import ghidrassistmcp.resources.McpResource;
import ghidrassistmcp.resources.McpResourceRegistry;
import ghidrassistmcp.resources.ProgramInfoResource;
import ghidrassistmcp.resources.StringsResource;
import ghidrassistmcp.tasks.McpProgramContext;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskManager;
import ghidrassistmcp.tools.AnalysisControlTool;
import ghidrassistmcp.tools.RationalizedToolCatalog;
import ghidrassistmcp.tools.AnalysisOptionsTool;
import ghidrassistmcp.tools.AnalyzeProgramTool;
import ghidrassistmcp.tools.AssembleCodeTool;
import ghidrassistmcp.tools.BookmarksTool;
import ghidrassistmcp.tools.CancelTaskTool;
import ghidrassistmcp.tools.ClassTool;
import ghidrassistmcp.tools.CloseProgramTool;
import ghidrassistmcp.tools.CommentsTool;
import ghidrassistmcp.tools.CreateDataVarTool;
import ghidrassistmcp.tools.CreateFunctionTool;
import ghidrassistmcp.tools.DisassembleAtTool;
import ghidrassistmcp.tools.GetBasicBlocksTool;
import ghidrassistmcp.tools.ImportFileTool;
import ghidrassistmcp.tools.OpenProgramTool;
import ghidrassistmcp.tools.ProjectFilesTool;
import ghidrassistmcp.tools.ExportProgramTool;
import ghidrassistmcp.tools.GetCodeTool;
import ghidrassistmcp.tools.GetPseudocodeBatchTool;
import ghidrassistmcp.tools.GetCurrentAddressTool;
import ghidrassistmcp.tools.GetCurrentFunctionTool;
import ghidrassistmcp.tools.GetEntryPointsTool;
import ghidrassistmcp.tools.GetFunctionInfoTool;
import ghidrassistmcp.tools.GetFunctionSignatureTool;
import ghidrassistmcp.tools.GetFunctionStackLayoutTool;
import ghidrassistmcp.tools.GetFunctionStatisticsTool;
import ghidrassistmcp.tools.GetHexdumpTool;
import ghidrassistmcp.tools.GetTaskStatusTool;
import ghidrassistmcp.tools.GhidraScriptsTool;
import ghidrassistmcp.tools.ListDataTool;
import ghidrassistmcp.tools.ListExportsTool;
import ghidrassistmcp.tools.ListProgramsTool;
import ghidrassistmcp.tools.ListFunctionsTool;
import ghidrassistmcp.tools.ListImportsTool;
import ghidrassistmcp.tools.ListNamespacesTool;
import ghidrassistmcp.tools.ListRelocationsTool;
import ghidrassistmcp.tools.ListSegmentsTool;
import ghidrassistmcp.tools.ListStringsTool;
import ghidrassistmcp.tools.ListTasksTool;
import ghidrassistmcp.tools.ProgramInfoTool;
import ghidrassistmcp.tools.RenameSymbolBatchTool;
import ghidrassistmcp.tools.RenameSymbolTool;
import ghidrassistmcp.tools.PatchBytesTool;
import ghidrassistmcp.tools.SearchBytesTool;
import ghidrassistmcp.tools.SearchFunctionsByNameTool;
import ghidrassistmcp.tools.SearchStringsTool;
import ghidrassistmcp.tools.StructTool;
import ghidrassistmcp.tools.TypesTool;
import ghidrassistmcp.tools.VariablesTool;
import ghidrassistmcp.tools.XrefsTool;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.json.schema.JsonSchemaValidator;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Implementation of the MCP backend that manages tools and program state.
 * Works with the singleton GhidrAssistMCPManager to support multiple CodeBrowser windows.
 */
public class GhidrAssistMCPBackend implements McpBackend {

    private final Map<String, McpTool> tools = new ConcurrentHashMap<>();
    private final Map<String, McpTool> legacyAliases = new ConcurrentHashMap<>();
    private final Map<String, Boolean> toolEnabledStates = new ConcurrentHashMap<>();
    private final List<McpEventListener> eventListeners = new CopyOnWriteArrayList<>();
    private final List<Runnable> toolCatalogListeners = new CopyOnWriteArrayList<>();
    private final ObjectMapper schemaMapper = new ObjectMapper();
    private final JsonSchemaValidator schemaValidator = io.modelcontextprotocol.json.McpJsonDefaults.getSchemaValidator();
    private volatile GhidrAssistMCPManager manager;
    private volatile boolean asyncExecutionEnabled = true;
    private final McpTaskManager taskManager;
    private final ProjectOperationGate projectOperationGate = new ProjectOperationGate();
    private final McpResourceRegistry resourceRegistry;
    private final McpPromptRegistry promptRegistry;
    private final McpCache cache;
    private final DecompilerService decompilerService;
    
    public GhidrAssistMCPBackend() {
        this.decompilerService = new DecompilerService(program -> {
            if (manager == null) {
                return null;
            }
            return manager.getToolForProgram(program);
        });

        // Initialize task manager for async operations
        this.taskManager = new McpTaskManager();

        // Initialize resource registry
        this.resourceRegistry = new McpResourceRegistry();
        registerBuiltinResources();

        // Initialize prompt registry
        this.promptRegistry = new McpPromptRegistry();
        registerBuiltinPrompts();

        // Initialize result cache
        this.cache = new McpCache();

        // Register built-in tools (renamed: list_* → get_*, etc.)
        registerTool(new ProgramInfoTool());         // get_binary_info
        registerTool(new ListProgramsTool());        // list_binaries
        registerTool(new ListFunctionsTool());       // get_functions
        registerTool(new GetFunctionInfoTool());     // analyze_function
        registerTool(new GetFunctionSignatureTool());
        registerTool(new ListSegmentsTool());        // get_segments
        registerTool(new ListImportsTool());         // get_imports
        registerTool(new ListExportsTool());         // get_exports
        registerTool(new ListStringsTool());         // get_strings
        registerTool(new ListDataTool());            // get_data_vars
        registerTool(new ListNamespacesTool());       // get_namespaces
        registerTool(new ListRelocationsTool());     // get_relocations
        registerTool(new GetCurrentAddressTool());
        registerTool(new GetCurrentFunctionTool());
        registerTool(new GetHexdumpTool());          // get_data_at

        // Register consolidated tools (replace individual tools)
        registerTool(new CommentsTool());            // comments (replaces set_comment)
        registerTool(new VariablesTool(decompilerService)); // variables (replaces set_local_variable_type + set_function_prototype)
        registerTool(new TypesTool());               // types (replaces get/set/delete/list_data_type[s])
        registerTool(new XrefsTool());               // xrefs (absorbs get_call_graph)
        registerTool(new StructTool(decompilerService)); // struct (advanced struct operations)

        // Register standalone tools
        registerTool(new GetCodeTool(decompilerService));
        registerTool(new GetPseudocodeBatchTool(decompilerService));
        registerTool(new GetBasicBlocksTool());
        registerTool(new RenameSymbolTool(decompilerService));
        registerTool(new RenameSymbolBatchTool(decompilerService)); // batch_rename
        registerTool(new SearchBytesTool());
        registerTool(new BookmarksTool());           // bookmarks (actions: list/set/remove)
        registerTool(new ClassTool());               // classes

        // Register new tools (Phase 4 — feature parity)
        registerTool(new SearchFunctionsByNameTool());
        registerTool(new GetFunctionStatisticsTool());
        registerTool(new GetFunctionStackLayoutTool());
        registerTool(new SearchStringsTool());
        registerTool(new CreateDataVarTool());
        registerTool(new CreateFunctionTool());       // create_function
        registerTool(new DisassembleAtTool());         // disassemble_at
        registerTool(new GetEntryPointsTool());

        // Register project-level tools
        registerTool(new OpenProgramTool());          // open_program: open/list project files in CodeBrowser
        registerTool(new CloseProgramTool());         // close_program: close open programs in CodeBrowser
        registerTool(new ProjectFilesTool());         // project_files: list/delete project files and folders
        registerTool(new AssembleCodeTool());         // assemble_code: assemble instructions and optionally patch bytes
        registerTool(new PatchBytesTool());           // patch_bytes: write patched bytes into program memory

        // Register Auto Analysis tools
        registerTool(new AnalysisOptionsTool());      // analysis_options: list/set/reset/save/apply presets
        registerTool(new AnalyzeProgramTool());       // analyze_program: run Auto Analysis
        registerTool(new AnalysisControlTool());      // analysis_control: status/cancel queued analysis

        // Register tools that are disabled by default (security-sensitive)
        registerTool(new ImportFileTool());
        toolEnabledStates.put("import_file", false); // disabled by default: exposes host file-system read access
        registerTool(new GhidraScriptsTool());
        toolEnabledStates.put("scripts", false); // disabled by default: creates/deletes/runs host-side Ghidra scripts
        registerTool(new ExportProgramTool());
        toolEnabledStates.put("export_program", false); // disabled by default: writes files to host filesystem

        // Register async task management tools
        registerTool(new GetTaskStatusTool());
        registerTool(new CancelTaskTool());
        registerTool(new ListTasksTool());

        List<McpTool> originalTools = new ArrayList<>(tools.values());
        Map<String, Boolean> originalDefaults = new HashMap<>(toolEnabledStates);
        legacyAliases.putAll(tools);
        tools.clear();
        toolEnabledStates.clear();
        for (McpTool canonical : RationalizedToolCatalog.rationalize(originalTools)) {
            registerTool(canonical);
            toolEnabledStates.put(canonical.getName(),
                originalDefaults.getOrDefault(canonical.getLegacyName(), true));
        }
        legacyAliases.keySet().removeAll(tools.keySet());
        Msg.info(this, "GhidrAssistMCP Backend initialized with " + tools.size() + " tools");
    }
    
    @Override
    public void registerTool(McpTool tool) {
        tools.put(tool.getName(), tool);
        // Tools are enabled by default when registered
        toolEnabledStates.put(tool.getName(), true);
        Msg.info(this, "Registered MCP tool: " + tool.getName());
        notifyToolCatalogChanged();
    }
    
    @Override
    public void unregisterTool(String toolName) {
        McpTool removed = tools.remove(toolName);
        toolEnabledStates.remove(toolName);
        if (removed != null) {
            Msg.info(this, "Unregistered MCP tool: " + toolName);
            notifyToolCatalogChanged();
        }
    }
    
    @Override
    public List<McpSchema.Tool> getAvailableTools() {
        List<McpSchema.Tool> toolList = new ArrayList<>();
        for (McpTool tool : tools.values()) {
            // Only include enabled tools in the available tools list
            if (toolEnabledStates.getOrDefault(tool.getName(), true)) {
                // Augment the schema with program_name parameter for multi-program support
                McpSchema.JsonSchema augmentedSchema = getToolInputSchema(tool);

                // Build tool annotations based on McpTool interface methods
                McpSchema.ToolAnnotations annotations = new McpSchema.ToolAnnotations(
                    null,  // title - will use tool name
                    tool.isReadOnly(),
                    tool.isDestructive(),
                    tool.isIdempotent(),
                    tool.isOpenWorld(),
                    null   // returnDirect
                );

                toolList.add(McpSchema.Tool.builder()
                    .name(tool.getName())
                    .title(tool.getName())
                    .description(tool.getDescription())
                    .inputSchema(augmentedSchema)
                    .outputSchema(getToolOutputSchema(tool))
                    .annotations(annotations)
                    .build());
            }
        }
        // Sort tools alphabetically by name for consistent ordering
        toolList.sort((a, b) -> a.name().compareToIgnoreCase(b.name()));
        return toolList;
    }

    private McpSchema.JsonSchema getToolInputSchema(McpTool tool) {
        McpSchema.JsonSchema schema = tool.getInputSchema();
        return tool.supportsProgramSelection() ? augmentSchemaWithProgramName(schema) : schema;
    }

    /** Long operations may return either their final result or a custom task handle. */
    private Map<String, Object> getToolOutputSchema(McpTool tool) {
        Map<String, Object> declared = tool.getOutputSchema();
        if (declared == null || !tool.isLongRunning()) {
            return declared;
        }
        Map<String, Object> taskHandle = Map.of(
            "type", "object",
            "properties", Map.of(
                "task_id", Map.of("type", "string"),
                "tool", Map.of("type", "string"),
                "status", Map.of("type", "string", "enum",
                    List.of("pending", "running", "completed", "failed", "cancelled")),
                "poll_interval_ms", Map.of("type", "integer", "minimum", 1)),
            "required", List.of("task_id", "tool", "status", "poll_interval_ms"),
            "additionalProperties", false);
        // Keep one stable catalog contract when async execution is toggled in Settings.
        return Map.of("type", "object", "oneOf", List.of(declared, taskHandle));
    }

    /**
     * Augment a tool's input schema with the universal 'program_name' parameter.
     * This allows all tools to optionally target a specific open program.
     */
    private McpSchema.JsonSchema augmentSchemaWithProgramName(McpSchema.JsonSchema originalSchema) {
        // Create the program_name property schema
        Map<String, Object> programNameSchema = new HashMap<>();
        programNameSchema.put("type", "string");
        programNameSchema.put("description", "Optional: Name or Ghidra project path of the program/binary to operate on. " +
            "Use list_open_programs and prefer the listed Project Path when multiple programs share a name. " +
            "If not specified, uses the currently active program.");

        if (originalSchema == null) {
            // Create a schema with just program_name
            Map<String, Object> props = new HashMap<>();
            props.put("program_name", programNameSchema);
            return new McpSchema.JsonSchema("object", props, List.of(), null, null, null);
        }

        // Get original properties or empty map
        Map<String, Object> originalProps = originalSchema.properties();
        Map<String, Object> newProps;

        if (originalProps != null) {
            newProps = new HashMap<>(originalProps);
        } else {
            newProps = new HashMap<>();
        }

        // Add program_name parameter
        newProps.put("program_name", programNameSchema);

        // Return new schema with augmented properties
        return new McpSchema.JsonSchema(
            originalSchema.type(),
            newProps,
            originalSchema.required(),
            false,
            originalSchema.defs(),
            originalSchema.definitions()
        );
    }
    
    @Override
    public McpSchema.CallToolResult callTool(String toolName, Map<String, Object> arguments) {
        return callToolInternal(toolName, arguments, null);
    }

    @Override
    public boolean supportsRequestMonitoring(String toolName) {
        McpTool tool = tools.get(toolName);
        if (tool == null) tool = legacyAliases.get(toolName);
        return tool != null && tool.supportsRequestMonitoring();
    }

    @Override
    public McpSchema.CallToolResult callToolMonitored(String toolName,
            Map<String, Object> arguments, TaskMonitor monitor) {
        return callToolInternal(toolName, arguments, Objects.requireNonNull(monitor));
    }

    private McpSchema.CallToolResult callToolInternal(String toolName,
            Map<String, Object> arguments, TaskMonitor requestMonitor) {
        arguments = arguments == null ? Map.of() :
            Collections.unmodifiableMap(new LinkedHashMap<>(arguments));
        McpTool tool = tools.get(toolName);
        if (tool == null) {
            tool = legacyAliases.get(toolName);
        }
        if (tool == null) {
            Msg.warn(this, "Tool not found: " + toolName);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Tool not found: " + toolName)
                .isError(true)
                .build();
        }

        if (requestMonitor != null && !tool.supportsRequestMonitoring()) {
            return errorResult("Tool does not support request monitoring: " + toolName);
        }

        // Check if tool is enabled
        if (!isToolEnabled(toolName)) {
            Msg.warn(this, "Tool is disabled: " + toolName);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Tool is disabled: " + toolName)
                .isError(true)
                .build();
        }

        Runnable releaseLease = () -> { };
        Runnable releaseOperation = () -> { };
        try {
            releaseOperation = tool.isProjectLifecycleOperation()
                ? projectOperationGate.acquireTransition() : projectOperationGate.acquireOperation();
            // Notify listeners of the request
            notifyToolRequest(toolName, arguments);

            Msg.info(this, "Executing tool: " + toolName);

            @SuppressWarnings("unchecked")
            Map<String, Object> inputSchema = schemaMapper.convertValue(
                getToolInputSchema(tool), Map.class);
            var validation = schemaValidator.validate(inputSchema, arguments);
            if (!validation.valid()) {
                return errorResult("Invalid arguments for " + toolName + ": " + validation.errorMessage());
            }

            // Resolve the target program - check if program_name is specified
            Program targetProgram = tool.supportsProgramSelection()
                    ? resolveTargetProgram(arguments) : getCurrentProgram();
            if (tool.requiresProgramContext(arguments) && targetProgram == null) {
                return errorResult("No program is open. Use list_project_files and open_program first.");
            }

            if (targetProgram != null && tool.requiresProgramContext(arguments)
                    && !"close_program".equals(tool.getLegacyName())) {
                releaseLease = retainProgram(targetProgram);
            }

            // Check cache for cacheable tools
            String cacheDiscriminator = tool.isCacheable() && targetProgram != null
                    ? tool.getCacheDiscriminator(arguments, targetProgram, this)
                    : "";
            if (tool.isCacheable() && targetProgram != null) {
                String cacheKey = cache.generateKey(toolName, arguments, McpCache.programIdentity(targetProgram),
                    cacheDiscriminator);
                McpSchema.CallToolResult cachedResult = cache.get(cacheKey, targetProgram);
                if (cachedResult != null) {
                    Msg.info(this, "Cache hit for tool: " + toolName);
                    McpSchema.CallToolResult decorated = addActiveContextToResult(cachedResult,
                        captureProgramContext(targetProgram));
                    notifyToolResponse(toolName, decorated);
                    return decorated;
                }
            }

            // Check if this is a long-running tool that should be executed asynchronously
            if (requestMonitor == null && tool.isLongRunning() && asyncExecutionEnabled) {
                return executeToolAsync(tool, toolName, arguments,
                    tool.requiresProgramContext(arguments) ? targetProgram : null);
            }

            // Execute synchronously for normal tools
            long modificationNumber = tool.isCacheable() && targetProgram != null
                    ? targetProgram.getModificationNumber() : 0;
            McpSchema.CallToolResult rawResult = requestMonitor == null
                ? tool.execute(arguments, targetProgram, this)
                : tool.executeMonitored(arguments, targetProgram, this, requestMonitor);
            McpSchema.CallToolResult result = normalizeLegacyResult(tool, rawResult, arguments);

            // Cache raw successful results only while the program revision remains stable.
            if (tool.isCacheable() && targetProgram != null && result != null
                    && !Boolean.TRUE.equals(result.isError())
                    && modificationNumber == targetProgram.getModificationNumber()) {
                String cacheKey = cache.generateKey(toolName, arguments, McpCache.programIdentity(targetProgram),
                    cacheDiscriminator);
                cache.put(cacheKey, result, targetProgram);
                Msg.debug(this, "Cached result for tool: " + toolName);
            }

            result = addActiveContextToResult(result,
                resolveResultProgramContext(tool, arguments, targetProgram));

            // Notify listeners of the response
            notifyToolResponse(toolName, result);

            return result;
        } catch (Exception e) {
            Msg.error(this, "Error executing tool " + toolName, e);
            McpSchema.CallToolResult errorResult = McpSchema.CallToolResult.builder()
                .addTextContent("Error executing tool " + toolName + ": " + e.getMessage())
                .isError(true)
                .build();

            // Notify listeners of the error response
            notifyToolResponse(toolName, errorResult);

            return errorResult;
        } finally {
            try {
                releaseLease.run();
            } finally {
                releaseOperation.run();
            }
        }
    }

    /** Bridge established legacy failure messages until implementations return typed errors. */
    private McpSchema.CallToolResult normalizeLegacyResult(McpTool tool,
            McpSchema.CallToolResult result, Map<String, Object> arguments) {
        if (result == null) {
            return errorResult("Tool returned no result: " + tool.getName());
        }
        if ("get_task_status".equals(tool.getLegacyName())) {
            McpTask task = taskManager.getTask((String) arguments.get("task_id"));
            if (task != null && task.getStatus() == McpTask.Status.FAILED) {
                return task.getResult() != null ? task.getResult()
                    : new McpSchema.CallToolResult(result.content(), true,
                        result.structuredContent(), result.meta());
            }
        }
        // Retrieved comments and script source can legitimately begin with error-like text.
        if (java.util.Set.of("get_comment", "get_function_comment", "get_script_source")
                .contains(tool.getName()) || Boolean.TRUE.equals(result.isError())
                || result.content().isEmpty()
                || !(result.content().get(0) instanceof McpSchema.TextContent text)) {
            return result;
        }
        String firstLine = text.text().stripLeading().split("\\R", 2)[0];
        boolean failure = firstLine.matches("(?i)^(Error(?:\\b|:)|Failed\\b|Cannot\\b|"
            + "Unable to\\b|Could not\\b|Invalid\\b|Unknown (?:action|format)\\b|"
            + "Missing required\\b|No program (?:currently )?(?:loaded|open)|"
            + "Decompilation failed\\b|(?:Function|Variable|Structure|Data type|Task|Program|"
            + "Bookmark|Class|Script).*not found\\b|.*(?:is|are) required\\b).*");
        return failure ? new McpSchema.CallToolResult(result.content(), true,
            result.structuredContent(), result.meta()) : result;
    }

    private static McpSchema.CallToolResult errorResult(String message) {
        return McpSchema.CallToolResult.builder().addTextContent(message).isError(true).build();
    }

    /**
     * Execute a long-running tool asynchronously and return a task ID.
     */
    private McpSchema.CallToolResult executeToolAsync(McpTool tool, String toolName,
                                                       Map<String, Object> arguments, Program targetProgram) {
        // Create a reference to this backend for the async execution
        final GhidrAssistMCPBackend backend = this;

        McpTask task = submitTask(toolName, arguments, targetProgram, taskContext -> {
            try {
                McpSchema.CallToolResult result = normalizeLegacyResult(tool,
                    tool.execute(arguments, targetProgram, backend, taskContext), arguments);
                // Store the raw result, but retain context in the response shown to listeners.
                // get_task_status decorates the stored result once using this task's snapshot.
                notifyToolResponse(toolName,
                    addActiveContextToResult(result, taskContext.getProgramContext()));
                return result;
            } catch (Exception e) {
                Msg.error(this, "Async tool execution failed: " + toolName, e);
                throw new RuntimeException(e);
            }
        });

        // Return task information immediately
        return McpSchema.CallToolResult.builder()
            .addTextContent("Task submitted for async execution.\n\n" +
                "Task ID: " + task.getTaskId() + "\n" +
                "Tool: " + toolName + "\n" +
                "Status: " + task.getStatus() + "\n\n" +
                "Use get_task_status with this task_id to check progress and retrieve results.\n" +
                "Use cancel_task to cancel if needed.")
            .structuredContent(Map.of("task_id", task.getTaskId(), "tool", toolName,
                "status", task.getStatus().name().toLowerCase(java.util.Locale.ROOT),
                "poll_interval_ms", 1000))
            .build();
    }

    /**
     * Get the task manager for async operations.
     */
    public McpTaskManager getTaskManager() {
        return taskManager;
    }

    /**
     * Submit an async task while retaining a stable snapshot of its target program.
     */
    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                              Program targetProgram,
                              Function<McpTask, McpSchema.CallToolResult> taskExecutor) {
        Runnable releaseOperation = projectOperationGate.acquireOperation();
        Runnable releaseProgram = () -> { };
        try {
            releaseProgram = targetProgram != null ? retainProgram(targetProgram) : () -> { };
            final Runnable programLease = releaseProgram;
            Runnable release = () -> {
                try {
                    programLease.run();
                } finally {
                    releaseOperation.run();
                }
            };
            return taskManager.submitTask(toolName, arguments,
                captureProgramContext(targetProgram), taskExecutor, release);
        } catch (RuntimeException error) {
            try {
                releaseProgram.run();
            } finally {
                releaseOperation.run();
            }
            throw error;
        }
    }

    /** Keep the database alive for an operation even when its CodeBrowser closes. */
    private Runnable retainProgram(Program program) {
        Object consumer = new Object();
        if (!program.addConsumer(consumer)) {
            throw new IllegalStateException("Program is already closed: " + program.getName());
        }
        java.util.concurrent.atomic.AtomicBoolean released = new java.util.concurrent.atomic.AtomicBoolean();
        return () -> {
            if (released.compareAndSet(false, true)) {
                program.release(consumer);
            }
        };
    }

    /**
     * Capture program identity without retaining a live Program reference in the task manager.
     */
    public McpProgramContext captureProgramContext(Program program) {
        if (program == null) {
            return McpProgramContext.empty();
        }

        DomainFile domainFile = program.getDomainFile();
        String projectPath = domainFile != null ? domainFile.getPathname() : null;
        String fileId = domainFile != null ? domainFile.getFileID() : null;
        return new McpProgramContext(program.getName(), projectPath, fileId);
    }

    /**
     * Get the resource registry.
     */
    public McpResourceRegistry getResourceRegistry() {
        return resourceRegistry;
    }

    /**
     * Register built-in MCP resources.
     */
    private void registerBuiltinResources() {
        resourceRegistry.registerResource(new ProgramInfoResource());
        resourceRegistry.registerResource(new FunctionListResource());
        resourceRegistry.registerResource(new StringsResource());
        resourceRegistry.registerResource(new ImportsResource());
        resourceRegistry.registerResource(new ExportsResource());
        resourceRegistry.registerResource(new ghidrassistmcp.resources.SegmentsResource());
        Msg.info(this, "Registered " + resourceRegistry.getResourceCount() + " MCP resources");
    }

    /**
     * Register built-in MCP prompts.
     */
    private void registerBuiltinPrompts() {
        promptRegistry.registerPrompt(new AnalyzeFunctionPrompt(decompilerService));
        promptRegistry.registerPrompt(new IdentifyVulnerabilityPrompt(decompilerService));
        promptRegistry.registerPrompt(new DocumentFunctionPrompt(decompilerService));
        promptRegistry.registerPrompt(new TraceDataFlowPrompt(decompilerService));
        promptRegistry.registerPrompt(new TraceNetworkDataPrompt(decompilerService));
        promptRegistry.registerPrompt(
            new ghidrassistmcp.prompts.CompareFunctionsPrompt(decompilerService));
        promptRegistry.registerPrompt(new ghidrassistmcp.prompts.ReverseEngineerStructPrompt());
        Msg.info(this, "Registered " + promptRegistry.getPromptCount() + " MCP prompts");
    }

    /**
     * Get the prompt registry.
     */
    public McpPromptRegistry getPromptRegistry() {
        return promptRegistry;
    }

    /**
     * Get available prompts for the MCP SDK.
     */
    public List<McpPrompt> getAvailablePrompts() {
        return promptRegistry.getAllPrompts();
    }

    /** Generate a prompt while project changes are excluded and its program remains open. */
    public McpSchema.GetPromptResult generatePrompt(McpPrompt prompt, Map<String, String> arguments) {
        Runnable releaseOperation = projectOperationGate.acquireOperation();
        Runnable releaseProgram = () -> { };
        try {
            Program program = getCurrentProgram();
            releaseProgram = program != null ? retainProgram(program) : () -> { };
            return prompt.generatePrompt(arguments, program);
        } finally {
            try {
                releaseProgram.run();
            } finally {
                releaseOperation.run();
            }
        }
    }

    /**
     * Get the result cache.
     */
    public McpCache getCache() {
        return cache;
    }

    /**
     * Get cache statistics summary.
     */
    public String getCacheStats() {
        return cache.getStats();
    }

    /**
     * Clear the cache (e.g., when program is significantly modified).
     */
    public void clearCache() {
        cache.clear();
    }

    /**
     * Read a resource by URI.
     *
     * @param uri The resource URI
     * @return The resource content
     */
    public String readResource(String uri) {
        McpResource resource = resourceRegistry.findResource(uri);
        if (resource == null) {
            return null;
        }
        Map<String, String> params = resource.extractParams(uri);
        String selector = params.get("name");
        Runnable releaseOperation = projectOperationGate.acquireOperation();
        try {
            Program program = selector != null
                ? resolveProgram(java.net.URLDecoder.decode(selector.replace("+", "%2B"), java.nio.charset.StandardCharsets.UTF_8))
                : getCurrentProgram();
            Runnable release = program != null ? retainProgram(program) : () -> { };
            try {
                return resourceRegistry.readResource(uri, program);
            } finally {
                release.run();
            }
        } catch (IllegalArgumentException error) {
            throw io.modelcontextprotocol.spec.McpError.RESOURCE_NOT_FOUND.apply(uri);
        } finally {
            releaseOperation.run();
        }
    }

    /**
     * Get available resources for the MCP SDK.
     */
    public List<McpResource> getAvailableResources() {
        return resourceRegistry.getAllResources();
    }

    @Override
    public void onProgramActivated(Program program) {
        // Program activation is now handled dynamically - no caching needed
        if (program != null) {
            Msg.info(this, "Program activated: " + program.getName());
            // Notify listeners for logging purposes
            notifySessionEvent("Program activated: " + program.getName());
        }
    }

    @Override
    public void onProgramDeactivated(Program program) {
        // Program deactivation is now handled dynamically - no state clearing needed
        if (program != null) {
            Msg.info(this, "Program deactivated: " + program.getName());
        }
    }
    
    @Override
    public McpSchema.Implementation getServerInfo() {
        return new McpSchema.Implementation("ghidrassistmcp", "3.0.0");
    }
    
    @Override
    public McpSchema.ServerCapabilities getCapabilities() {
        return McpSchema.ServerCapabilities.builder()
            .tools(true)
            .resources(false, false)  // subscribe=false, listChanged=false
            .prompts(false)           // listChanged=false
            .build();
    }
    
    /**
     * Resolve the target program based on arguments.
     * If 'program_name' is specified, look up that program across ALL open tools.
     * Otherwise, return the currently active program.
     *
     * @param arguments The tool arguments that may contain 'program_name'
     * @return The resolved program to operate on
     */
    private Program resolveTargetProgram(Map<String, Object> arguments) {
        Object requested = arguments.get("program_name");
        if (requested == null) {
            return getCurrentProgram();
        }
        String selector = (String) requested;
        if (selector.isBlank()) {
            throw new IllegalArgumentException("program_name must be a non-empty name or project path");
        }
        return resolveProgram(selector);
    }

    /** Resolve an explicit selector without falling back to whichever window has focus. */
    public Program resolveProgram(String selector) {
        List<Program> candidates = new ArrayList<>(getAllOpenPrograms());
        Program current = getCurrentProgram();
        if (current != null && !candidates.contains(current)) {
            candidates.add(current);
        }
        String name = selector.trim();
        for (int matchMode = 0; matchMode < 3; matchMode++) {
            List<Program> matches = new ArrayList<>();
            for (Program candidate : candidates) {
                DomainFile file = candidate.getDomainFile();
                String path = file != null ? file.getPathname() : "";
                boolean matchesSelector = switch (matchMode) {
                    case 0 -> name.equals(path) || name.equals(candidate.getName());
                    case 1 -> name.equalsIgnoreCase(path) || name.equalsIgnoreCase(candidate.getName());
                    default -> candidate.getName().toLowerCase(java.util.Locale.ROOT)
                        .contains(name.toLowerCase(java.util.Locale.ROOT));
                };
                if (matchesSelector) {
                    matches.add(candidate);
                }
            }
            if (matches.size() == 1) {
                return matches.get(0);
            }
            if (matches.size() > 1) {
                throw new IllegalArgumentException("Program selector is ambiguous: " + selector +
                    ". Use a unique Project Path from list_open_programs.");
            }
        }
        throw new IllegalArgumentException("Program not found: " + selector +
            ". Use list_open_programs to select an open program.");
    }

    /**
     * Get the currently active program from the manager.
     * This queries ALL registered tools for the currently active program.
     */
    public Program getCurrentProgram() {
        if (manager != null) {
            return manager.getCurrentProgram();
        }
        return null;
    }

    /**
     * Get all open programs from ALL registered tools.
     */
    public List<Program> getAllOpenPrograms() {
        if (manager != null) {
            return manager.getAllOpenPrograms();
        }
        return new ArrayList<>();
    }
    
    /**
     * Add an event listener for MCP operations.
     */
    public void addEventListener(McpEventListener listener) {
        if (listener != null) {
            eventListeners.add(listener);
            Msg.info(this, "Added MCP event listener: " + listener.getClass().getSimpleName() + " (total listeners: " + eventListeners.size() + ")");
        }
    }
    
    /**
     * Remove an event listener.
     */
    public void removeEventListener(McpEventListener listener) {
        if (listener != null) {
            eventListeners.remove(listener);
            Msg.info(this, "Removed MCP event listener: " + listener.getClass().getSimpleName());
        }
    }
    
    /**
     * Set the manager reference for multi-tool program discovery.
     */
    public void setManager(GhidrAssistMCPManager manager) {
        this.manager = manager;
        Msg.info(this, "Manager reference set for multi-tool support");
    }

    /**
     * Get the currently active plugin instance for UI context access.
     * This allows tools to access current address, current function, etc.
     *
     * @return The active plugin instance, or null if none is active
     */
    public GhidrAssistMCPPlugin getActivePlugin() {
        if (manager != null) {
            return manager.getActivePlugin();
        }
        return null;
    }
    
    /**
     * Notify listeners of a tool request.
     */
    private void notifyToolRequest(String toolName, Map<String, Object> arguments) {
        String params = arguments != null ? arguments.toString() : "{}";
        if (params.length() > 60) {
            params = params.substring(0, 57) + "...";
        }
        
        Msg.info(this, "Notifying " + eventListeners.size() + " listeners of tool request: " + toolName);
        
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onToolRequest(toolName, params);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of tool request", e);
            }
        }
    }
    
    /**
     * Notify listeners of a tool response.
     */
    private void notifyToolResponse(String toolName, McpSchema.CallToolResult result) {
        String response = "Empty response";
        if (result != null && !result.content().isEmpty()) {
            var firstContent = result.content().get(0);
            if (firstContent instanceof McpSchema.TextContent) {
                response = ((McpSchema.TextContent) firstContent).text();
                if (response.length() > 60) {
                    response = response.substring(0, 57) + "...";
                }
            }
        }
        
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onToolResponse(toolName, response);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of tool response", e);
            }
        }
    }
    
    /**
     * Notify listeners of a session event.
     */
    private void notifySessionEvent(String event) {
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onSessionEvent(event);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of session event", e);
            }
        }
    }
    
    /**
     * Notify listeners of a general log message.
     */
    @SuppressWarnings("unused")
    private void notifyLogMessage(String message) {
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onLogMessage(message);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of log message", e);
            }
        }
    }
    
    /**
     * Resolve the context that belongs to a response. Completed task results retain the target
     * from their original invocation rather than inheriting the program active while polling.
     */
    private McpProgramContext resolveResultProgramContext(McpTool tool,
                                                           Map<String, Object> arguments,
                                                           Program targetProgram) {
        if ("get_task_status".equals(tool.getLegacyName())) {
            Object taskId = arguments.get("task_id");
            if (taskId instanceof String id) {
                McpTask task = taskManager.getTask(id);
                if (task != null) {
                    return task.getProgramContext();
                }
            }
        }
        return tool.requiresProgramContext(arguments) ? captureProgramContext(targetProgram)
            : McpProgramContext.empty();
    }

    /**
     * Add active context information to tool results to help LLM understand which binary is in focus.
     * This prepends context metadata to the first text content in the result.
     */
    private McpSchema.CallToolResult addActiveContextToResult(McpSchema.CallToolResult result,
                                                               McpProgramContext targetProgram) {
        if (result == null || result.content() == null || result.content().isEmpty()) {
            return result;
        }

        // Build context information
        StringBuilder contextInfo = new StringBuilder();

        // Get the current active program from manager
        McpProgramContext activeProgram = captureProgramContext(getCurrentProgram());

        // Add context header
        contextInfo.append("[Context] ");

        if (targetProgram.hasProgram()) {
            contextInfo.append("Operating on: ").append(targetProgram.displayName());
            if (Objects.equals(targetProgram.programName(), activeProgram.programName())
                    && !targetProgram.identifiesSameProgram(activeProgram)
                    && targetProgram.projectPath() != null) {
                contextInfo.append(" (").append(targetProgram.projectPath()).append(")");
            }

            // If active program is different, mention it
            if (activeProgram.hasProgram() &&
                    !targetProgram.identifiesSameProgram(activeProgram)) {
                contextInfo.append(" | Active window: ").append(activeProgram.displayName());
            }
        } else if (activeProgram.hasProgram()) {
            contextInfo.append("Active window: ").append(activeProgram.displayName());
        } else {
            contextInfo.append("No program currently active");
        }

        // Add available programs count if multiple are open
        if (manager != null) {
            List<Program> allPrograms = manager.getAllOpenPrograms();
            if (allPrograms.size() > 1) {
                contextInfo.append(" | Total open programs: ").append(allPrograms.size());
            }
        }

        contextInfo.append("\n\n");

        List<McpSchema.Content> contents = new ArrayList<>(result.content());
        for (int i = 0; i < contents.size(); i++) {
            if (contents.get(i) instanceof McpSchema.TextContent text) {
                contents.set(i, new McpSchema.TextContent(text.annotations(),
                    contextInfo + text.text(), text.meta()));
                break;
            }
        }
        return new McpSchema.CallToolResult(contents, result.isError(),
            result.structuredContent(), result.meta());
    }

    /**
     * Set whether async execution is enabled for long-running tools.
     */
    public void setAsyncExecutionEnabled(boolean enabled) {
        this.asyncExecutionEnabled = enabled;
        Msg.info(this, "Async tool execution " + (enabled ? "enabled" : "disabled"));
    }

    /**
     * Check whether async execution is enabled for long-running tools.
     */
    public boolean isAsyncExecutionEnabled() {
        return asyncExecutionEnabled;
    }

    /**
     * Set the enabled state of a tool.
     */
    public void setToolEnabled(String toolName, boolean enabled) {
        boolean changed = false;
        for (McpTool tool : tools.values()) {
            if (tool.getName().equals(toolName) || tool.getLegacyName().equals(toolName)) {
                Boolean previous = toolEnabledStates.put(tool.getName(), enabled);
                changed |= !Objects.equals(previous, enabled);
            }
        }
        if (changed) {
            notifyToolCatalogChanged();
        }
    }

    /**
     * Get the enabled state of a tool.
     */
    public boolean isToolEnabled(String toolName) {
        if (tools.containsKey(toolName)) {
            return toolEnabledStates.getOrDefault(toolName, true);
        }
        // Hidden direct-backend aliases are allowed only when every child is enabled.
        // They are never registered in the wire catalog, and cannot bypass policy.
        List<McpTool> children = tools.values().stream()
            .filter(tool -> tool.getLegacyName().equals(toolName)).toList();
        return !children.isEmpty() && children.stream()
            .allMatch(tool -> toolEnabledStates.getOrDefault(tool.getName(), true));
    }

    /**
     * Get all tool enabled states.
     */
    public Map<String, Boolean> getToolEnabledStates() {
        return new HashMap<>(toolEnabledStates);
    }
    
    /**
     * Update multiple tool enabled states at once.
     */
    public void updateToolEnabledStates(Map<String, Boolean> newStates) {
        for (McpTool tool : tools.values()) {
            Boolean enabled = newStates.get(tool.getName());
            if (enabled == null) {
                enabled = newStates.get(tool.getLegacyName());
            }
            if (enabled != null) {
                toolEnabledStates.put(tool.getName(), enabled);
            }
        }
        notifyToolCatalogChanged();
    }

    /** Canonical-to-legacy configuration mapping; exact saved names take precedence. */
    public Map<String, String> getToolLegacyNames() {
        Map<String, String> names = new HashMap<>();
        for (McpTool tool : tools.values()) {
            names.put(tool.getName(), tool.getLegacyName());
        }
        return names;
    }

    /**
     * Get all tools (including disabled ones) for configuration purposes.
     */
    public List<McpSchema.Tool> getAllTools() {
        List<McpSchema.Tool> toolList = new ArrayList<>();
        for (McpTool tool : tools.values()) {
            toolList.add(McpSchema.Tool.builder()
                .name(tool.getName())
                .title(tool.getName())
                .description(tool.getDescription())
                .inputSchema(getToolInputSchema(tool))
                .outputSchema(getToolOutputSchema(tool))
                .build());
        }
        // Sort tools alphabetically by name for consistent ordering
        toolList.sort((a, b) -> a.name().compareToIgnoreCase(b.name()));
        return toolList;
    }
    public void addToolCatalogListener(Runnable listener) {
        toolCatalogListeners.add(listener);
    }

    public void removeToolCatalogListener(Runnable listener) {
        toolCatalogListeners.remove(listener);
    }

    private void notifyToolCatalogChanged() {
        for (Runnable listener : toolCatalogListeners) {
            try {
                listener.run();
            } catch (RuntimeException error) {
                Msg.error(this, "Failed to refresh MCP tool catalog", error);
            }
        }
    }

    /** Dispose the shared runtime when Ghidra closes, not when a browser closes. */
    public void shutdown() {
        taskManager.shutdown();
        cache.clear();
        toolCatalogListeners.clear();
        eventListeners.clear();
    }

}

package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidrassistmcp.McpTool;

/** One discoverable name and input contract per user intent; implementations remain shared. */
public final class RationalizedToolCatalog {
    private final Map<String, McpTool> originals = new HashMap<>();
    private final List<McpTool> tools = new ArrayList<>();

    private RationalizedToolCatalog(Collection<McpTool> originals) {
        originals.forEach(tool -> this.originals.put(tool.getName(), tool));
    }

    public static List<McpTool> rationalize(Collection<McpTool> originals) {
        RationalizedToolCatalog c = new RationalizedToolCatalog(originals);
        c.build();
        // This tool already exposes its canonical contract, including its output schema.
        McpTool batchPseudocode = c.originals.get("get_pseudocode_batch");
        if (batchPseudocode == null) throw new IllegalArgumentException("Missing original tool: get_pseudocode_batch");
        c.tools.add(batchPseudocode);
        c.tools.add(new GetFunctionHashTool());
        c.tools.add(new GetFunctionPrototypeTool());
        for (ProjectControlTool.Operation operation : ProjectControlTool.Operation.values()) {
            c.tools.add(new ProjectControlTool(operation));
        }
        c.tools.sort(Comparator.comparing(McpTool::getName));
        if (c.tools.stream().map(McpTool::getName).distinct().count() != c.tools.size()) {
            throw new IllegalStateException("Duplicate canonical MCP tool name");
        }
        return List.copyOf(c.tools);
    }

    private ExplicitTool tool(String legacy, String name, String description) {
        McpTool original = originals.get(legacy);
        if (original == null) throw new IllegalArgumentException("Missing original tool: " + legacy);
        ExplicitTool tool = new ExplicitTool(original, name, description);
        tools.add(tool);
        return tool;
    }

    private ExplicitTool action(String legacy, String action, String name, String description) {
        return tool(legacy, name, description).select("action", action).required();
    }

    private void build() {
        tool("get_binary_info", "get_program_info", "Get program metadata: name, language, compiler, image base, memory size, and function count.").readOnly();
        tool("list_binaries", "list_open_programs", "List programs across every CodeBrowser, including exact project paths for program_name targeting.").readOnly().context(false, false);
        tool("get_functions", "list_functions", "List functions by address with pagination; pattern is a name substring, case_sensitive defaults to true.").readOnly();
        tool("analyze_function", "get_function_info", "Get a function's entry address, body ranges, parameters, return type, and C prototype.").alias("function", "function_name").parameters("function").required("function").readOnly();
        tool("get_function_signature", "get_function_byte_pattern", "Get GhidrAssist's masked prefix byte pattern, up to 64 bytes with '?' wildcards. This pattern is not a C prototype or cryptographic hash.").alias("function", "function_name_or_address").parameters("function").required("function").readOnly();
        tool("get_segments", "list_memory_blocks", "List Ghidra memory blocks/segments and their ranges and permissions.").readOnly();
        tool("get_imports", "list_imports", "List imported functions and symbols with pagination.").readOnly();
        tool("get_exports", "list_exports", "List exported functions and symbols with pagination.").readOnly();
        tool("get_strings", "list_strings", "List defined string data; min_length defaults to 4, filter is a case-sensitive substring, with pagination.").readOnly();
        tool("get_data_vars", "list_data_variables", "List defined data elements, optionally filtered by data type, with pagination.").readOnly();
        tool("get_namespaces", "list_namespaces", "List program namespaces with pagination.").readOnly();
        tool("get_relocations", "list_relocations", "List relocation entries with pagination.").readOnly();
        tool("get_current_address", "get_current_address", "Get the cursor address from the focused CodeBrowser. This is UI context, not a program-selected query.").readOnly().context(false, true);
        tool("get_current_function", "get_current_function", "Get the function containing the focused CodeBrowser cursor. This is UI context, not a program-selected query.").readOnly().context(false, true);
        tool("get_data_at", "get_hexdump", "Read memory as a hex and ASCII dump, using an address and byte length (maximum 65536).").alias("length", "len").parameters("address", "length").required("address", "length").readOnly();

        action("comments", "get", "get_comment", "Get one listing comment at an address; comment_type defaults to eol.").parameters("address", "comment_type").required("address").readOnly();
        action("comments", "get", "get_function_comment", "Get the function-level comment for a named function.").alias("function", "function_name").parameters("function").required("function").readOnly();
        action("comments", "list", "list_function_comments", "List the function comment and listing comments inside a named function.").alias("function", "function_name").parameters("function").required("function").readOnly();
        action("comments", "set", "set_comment", "Set a listing comment at an address; comment_type defaults to eol.").parameters("address", "comment", "comment_type").required("address", "comment").mutation(false, true);
        action("comments", "set", "set_function_comment", "Set the function-level comment for a named function.").alias("function", "function_name").parameters("function", "comment").required("function", "comment").mutation(false, true);
        action("comments", "remove", "remove_comment", "Remove a listing comment at an address; comment_type defaults to eol.").parameters("address", "comment_type").required("address").mutation(true, true);

        action("variables", "list", "list_function_variables", "Decompile a named function and list its parameters and local variables, types, and storage.").alias("function", "function_name").parameters("function").required("function").readOnly();
        action("variables", "rename", "rename_local_variable", "Rename a local variable or parameter in a function, preserving decompiler storage identity.").select("scope", "local").alias("function", "function_name_or_address").parameters("function", "variable_name", "new_name").required("function", "variable_name", "new_name").mutation(false, false);
        action("variables", "rename", "rename_global_variable", "Rename a global/data symbol by its address or existing name.").select("scope", "global").alias("symbol", "address_or_name").parameters("symbol", "new_name").required("symbol", "new_name").mutation(false, false).longRunning(false);
        action("variables", "retype", "set_local_variable_type", "Change the data type of a local variable in a named function.").alias("function", "function_name").parameters("function", "variable_name", "data_type").required("function", "variable_name", "data_type").mutation(false, true);
        action("variables", "set_prototype", "set_function_prototype", "Parse and apply a C function prototype at a function's entry address.").alias("address", "function_address").parameters("address", "prototype").required("address", "prototype").mutation(true, true).longRunning(false);

        action("types", "list", "list_data_types", "List data types with optional name/category substring filters and pagination.").parameters("filter", "category", "offset", "limit").readOnly();
        action("types", "get", "get_data_type", "Get a data type's details by name and optional category path.").parameters("name", "category").required("name").readOnly();
        action("types", "set", "set_data_type", "Apply a data type to memory at an address. Supports array suffixes and array_count; replaces existing code/data units.").parameters("address", "data_type", "array_count").required("address", "data_type").mutation(true, true);
        // create_struct is served by the more capable struct implementation, avoiding a duplicate tool.
        action("types", "create_enum", "create_enum", "Create an enumeration data type from name/value pairs.").parameters("name", "category", "size", "values").required("name", "values").mutation(false, false);
        action("types", "create_typedef", "create_typedef", "Create a typedef data type for an existing base type.").parameters("name", "category", "base_type").required("name", "base_type").mutation(false, false);
        action("types", "delete", "delete_data_type", "Delete a data type from the program; dependent data/type definitions can change.").parameters("name", "category").required("name").mutation(true, false);

        tool("xrefs", "get_xrefs_to", "Get incoming references to an address, including reference types.").select("direction", "to").parameters("address", "limit").required("address").readOnly();
        tool("xrefs", "get_xrefs_from", "Get outgoing references from an address, including reference types.").select("direction", "from").parameters("address", "limit").required("address").readOnly();
        tool("xrefs", "get_callers", "List functions that directly call a named function.").select("direction", "to").parameters("function", "limit").required("function").readOnly();
        tool("xrefs", "get_callees", "List functions directly called by a named function.").select("direction", "from").parameters("function", "limit").required("function").readOnly();
        tool("xrefs", "get_call_graph", "Get a recursive caller/callee graph for a function; direction defaults to both and depth defaults to 2 (maximum 5).").select("include_calls", true).parameters("function", "direction", "depth").required("function").readOnly();

        action("struct", "create", "create_structure", "Create a structure from a name/size or a C definition. Optional packing and category are supported.").parameters("name", "size", "packed", "category", "c_definition").oneOfParameters("name", "c_definition").mutation(false, false).longRunning(false);
        action("struct", "modify", "replace_structure", "Replace a structure definition from C text, optionally renaming it; existing fields can be removed.").parameters("structure_name", "c_definition", "new_name", "allow_empty").required("structure_name", "c_definition").mutation(true, false).longRunning(false);
        action("struct", "merge", "merge_structure", "Merge a C structure definition into an existing structure; optionally update its packing.").parameters("structure_name", "c_definition", "update_packing").required("structure_name", "c_definition").mutation(true, false).longRunning(false);
        action("struct", "set_field", "set_structure_field", "Insert or replace a structure field at a byte offset; supports pointers and arrays.").parameters("structure_name", "field_offset", "field_name", "data_type", "comment", "pointer_level", "array_count", "field_length", "op", "grow").required("structure_name", "field_offset", "data_type").mutation(true, false).longRunning(false);
        action("struct", "name_gap", "name_structure_gap", "Name an undefined structure gap as a byte array; overwriting defined fields defaults to false.").parameters("structure_name", "field_offset", "field_name", "field_length", "comment", "grow", "allow_overwrite").required("structure_name", "field_offset", "field_name", "field_length").mutation(true, true).longRunning(false);
        action("struct", "auto_create", "infer_structure_from_variable", "Infer and apply a structure for a decompiler variable in a function. This modifies program data types and variable types.").alias("function", "function_identifier").parameters("function", "variable_name").required("function", "variable_name").mutation(false, false);
        action("struct", "rename_field", "rename_structure_field", "Rename a structure field, identified by old_field_name or its byte offset.").parameters("structure_name", "old_field_name", "offset", "new_field_name").required("structure_name", "new_field_name").oneOfParameters("old_field_name", "offset").mutation(false, false).longRunning(false);
        action("struct", "field_xrefs", "get_structure_field_xrefs", "Find decompiler and optional instance references to a structure field, identified by field_name or field_offset, with pagination.").parameters("structure_name", "field_name", "field_offset", "instance_address", "offset", "limit").required("structure_name").oneOfParameters("field_name", "field_offset").readOnly();

        tool("get_code", "get_pseudocode", "Decompile one function into C-like pseudocode. Prefer get_pseudocode_batch for grouped reads.").select("format", "decompiler").parameters("function").required("function").readOnly();
        tool("get_code", "get_disassembly", "Read existing assembly instructions and EOL comments for a function. This does not define or change instructions.").select("format", "disassembly").parameters("function").required("function").readOnly().longRunning(false);
        tool("get_code", "get_pcode", "Get decompiler P-code operations for a function; raw selects a flat operation list instead of basic-block grouping.").select("format", "pcode").parameters("function", "raw").required("function").readOnly();
        tool("get_basic_blocks", "get_control_flow_graph", "Get a function's basic blocks with predecessor/successor control-flow edges.").readOnly();
        tool("rename_symbol", "rename_function", "Rename a function by its current name; new_name may include a namespace such as Namespace::Name.").select("target_type", "function").alias("function", "identifier").parameters("function", "new_name").required("function", "new_name").mutation(false, false);
        tool("rename_symbol", "rename_label", "Rename or create a data/label symbol at an address.").select("target_type", "data").alias("address", "identifier").parameters("address", "new_name").required("address", "new_name").mutation(false, true);
        tool("batch_rename", "rename_symbols_batch", "Rename multiple functions, data/labels, or local variables, with per-item partial-success reporting.").mutation(false, false);
        tool("search_bytes", "search_bytes", "Find hex-byte patterns in program memory; use ?? wildcards, with a bounded result limit.").readOnly();
        action("bookmarks", "list", "list_bookmarks", "List bookmarks, optionally filtered by a category substring.").parameters("category").readOnly();
        action("bookmarks", "set", "set_bookmark", "Set a bookmark at an address, with optional type, category, and comment; type defaults to NOTE.").parameters("address", "type", "category", "comment").required("address").mutation(false, true);
        action("bookmarks", "remove", "remove_bookmark", "Remove bookmarks at an address. Omitting type removes every bookmark type at that address.").parameters("address", "type").required("address").mutation(true, true);
        action("classes", "list", "list_classes", "List classes with optional name-substring filtering and pagination; case_sensitive defaults to true.").parameters("pattern", "case_sensitive", "offset", "limit").readOnly().longRunning(false);
        action("classes", "get_info", "get_class_info", "Get class methods, fields, and available vtable/type information for a named class.").parameters("class_name").required("class_name").readOnly();

        tool("search_functions_by_name", "search_functions", "Search function names by case-insensitive substring; use list_functions for pagination or case-sensitive filtering.").readOnly();
        tool("get_function_statistics", "get_program_function_statistics", "Get program-wide counts and aggregate function size/parameter statistics.").readOnly();
        tool("get_function_stack_layout", "get_function_stack_layout", "Get a function's stack frame size, return-address offset, and stack variables.").alias("function", "function_name_or_address").parameters("function").required("function").readOnly();
        tool("search_strings", "search_strings", "Search defined string contents by substring, case-insensitive by default, with a bounded result limit.").readOnly();
        tool("create_data_var", "create_data_variable", "Define typed data and an optional label at an address; clears code/data units covered by that type.").mutation(true, true);
        tool("create_function", "create_function", "Define a function at an entry address using flow analysis. Optional clear_existing removes existing code/data first.").mutation(true, true);
        tool("disassemble_at", "disassemble_bytes", "Define instructions from bytes at an address/range, modifying the listing. Optional clear_existing removes existing code/data.").mutation(true, true);
        tool("get_entry_points", "list_entry_points", "List program entry-point addresses and corresponding symbols/functions.").readOnly();

        action("open_program", "open", "open_program", "Open a project program by exact path or unique name, launching CodeBrowser when needed. Optional analyze_after_open submits an analysis task.").parameters("name", "folder", "suppress_analysis_prompt", "analyze_after_open", "analysis_mode", "analysis_options").required("name").context(false, false).mutation(false, false);
        tool("close_program", "close_program", "Close a program by name/path or the current program. Changed programs require save=true or explicit ignore_changes=true.").context(false, false).mutation(true, true);
        action("project_files", "list", "list_project_files", "List files/folders in the active Ghidra project; recursive defaults to false. Available before CodeBrowser is open.").parameters("folder", "recursive").readOnly().context(false, false);
        action("project_files", "delete", "delete_project_file", "Delete a Ghidra project file/database entry. Requires confirm=true; the original imported host file is retained.").select("target_type", "file").parameters("path", "confirm").required("path", "confirm").mutation(true, false).context(false, false);
        action("project_files", "delete", "delete_project_folder", "Delete a project folder, optionally recursively. Requires confirm=true.").select("target_type", "folder").parameters("path", "recursive", "confirm").required("path", "confirm").mutation(true, false).context(false, false);
        tool("assemble_code", "assemble_instructions", "Encode assembly instruction text at an address and return bytes without changing program memory.").select("patch", false).parameters("address", "code").required("address", "code").readOnly();
        tool("assemble_code", "patch_instructions", "Assemble instruction text and patch it into program memory. clear_code_units defaults to true.").select("patch", true).parameters("address", "code", "clear_code_units").required("address", "code").mutation(true, true);
        tool("patch_bytes", "patch_bytes", "Replace program-memory bytes at an address using a hex string or byte array; optionally clear overlapping code/data units.").mutation(true, true);

        action("analysis_options", "list", "list_analysis_options", "List Auto Analysis options, including registered plugin analyzers, with filtering and pagination.").parameters("filter", "offset", "limit").readOnly();
        action("analysis_options", "set", "set_analysis_options", "Set named Auto Analysis option values on a program.").parameters("options").required("options").mutation(false, true);
        action("analysis_options", "reset", "reset_analysis_options", "Reset Auto Analysis options to defaults; omit option_names to reset all options.").parameters("option_names").mutation(true, true);
        action("analysis_options", "save_preset", "save_analysis_preset", "Save named Auto Analysis option values as a local preset.").parameters("preset_name", "options", "option_names").required("preset_name").mutation(false, true);
        action("analysis_options", "apply_preset", "apply_analysis_preset", "Apply a saved Auto Analysis preset to a program.").parameters("preset_name").required("preset_name").mutation(false, true);
        action("analysis_options", "list_presets", "list_analysis_presets", "List saved Auto Analysis presets.").parameters().readOnly().context(false, false);
        action("analysis_options", "delete_preset", "delete_analysis_preset", "Delete a saved Auto Analysis preset.").parameters("preset_name").required("preset_name").mutation(true, true).context(false, false);
        tool("analyze_program", "analyze_program", "Run Ghidra Auto Analysis on current/all open programs, with full or pending-changes mode, optional address range and option overrides.").mutation(true, false);
        action("analysis_control", "status", "get_analysis_status", "Get Auto Analysis status for the current program or all open programs.").parameters("scope").readOnly().context(true, false);
        action("analysis_control", "cancel", "cancel_analysis", "Request cancellation of queued/running Auto Analysis for the current program or all open programs.").parameters("scope").mutation(false, true).context(true, false);

        tool("import_file", "import_file", "Import a host binary into the active project, optionally opening it in CodeBrowser. Disabled by default; program_name names the imported program.").context(false, false);
        action("scripts", "list", "list_scripts", "List available Ghidra scripts with optional name filtering and pagination. Disabled by default.").parameters("filter", "user_only", "offset", "limit").readOnly().context(false, false);
        action("scripts", "get", "get_script_source", "Read a Ghidra script's source up to max_bytes. Disabled by default.").parameters("name", "max_bytes").required("name").readOnly().context(false, false);
        action("scripts", "create", "create_script", "Create a Ghidra script in the user script directory, optionally from a template. Disabled by default.").parameters("name", "source", "overwrite").required("name").mutation(true, false).context(false, false);
        action("scripts", "delete", "delete_script", "Delete a Ghidra script from the user script directory; requires confirm=true. Disabled by default.").parameters("name", "confirm").required("name", "confirm").mutation(true, false).context(false, false);
        action("scripts", "run", "run_script", "Run an existing Ghidra script with optional arguments against the selected program. Disabled by default.").parameters("name", "args").required("name").mutation(true, false);
        tool("export_program", "export_program", "Export program bytes or its original-file representation to a host path. Disabled by default; overwrite defaults to false.");
        tool("get_task_status", "get_task_status", "Get a custom asynchronous job's status or completed result by task_id.").readOnly().context(false, false);
        tool("cancel_task", "cancel_task", "Request cancellation of a custom asynchronous job by task_id.").mutation(false, true).context(false, false);
        tool("list_tasks", "list_tasks", "List custom asynchronous jobs, optionally filtered by status.").readOnly().context(false, false);
    }
}

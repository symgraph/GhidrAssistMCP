/*
 * MCP tool for structure operations.
 * Consolidates create_struct, modify_struct, auto_create_struct, rename_structure_field, and struct_field_xrefs.
 */
package ghidrassistmcp.tools;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.decompiler.DecompilerSession;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for structure operations.
 * Consolidates create_struct, modify_struct, auto_create_struct, rename_structure_field, and struct_field_xrefs.
 */
public class StructTool implements McpTool {

    private final DecompilerService decompilerService;

    public StructTool(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    private static class ComponentSnapshot {
        final int offset;
        final DataType dataType;
        final int length;
        final String fieldName;
        final String comment;

        ComponentSnapshot(int offset, DataType dataType, int length, String fieldName, String comment) {
            this.offset = offset;
            this.dataType = dataType;
            this.length = length;
            this.fieldName = fieldName;
            this.comment = comment;
        }
    }

    private static class StructureSnapshot {
        final boolean packed;
        final List<ComponentSnapshot> components;

        StructureSnapshot(boolean packed, List<ComponentSnapshot> components) {
            this.packed = packed;
            this.components = components;
        }
    }

    /**
     * Inner class to hold field reference results for field_xrefs action.
     */
    private static class FieldReference {
        Address address;
        String functionName;
        Address functionAddress;
        String accessType;  // "READ", "WRITE", "UNKNOWN"
        String context;
        String source;      // "DECOMPILER" or "ADDRESS"

        FieldReference(Address address, String functionName, Address functionAddress,
                      String accessType, String context, String source) {
            this.address = address;
            this.functionName = functionName;
            this.functionAddress = functionAddress;
            this.accessType = accessType;
            this.context = context;
            this.source = source;
        }

        @Override
        public String toString() {
            return String.format("[%s] %s: %s", accessType, address, context);
        }
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isLongRunning() {
        // auto_create and field_xrefs actions require decompilation
        return true;
    }

    @Override
    public String getName() {
        return "struct";
    }

    @Override
    public String getDescription() {
        return "Structure operations: create, modify, merge, set_field, name_gap, auto_create, rename_field, or field_xrefs";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        // Note: This is a single tool with action-specific parameters.
        // We express this as a single object schema with rich per-field descriptions.
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Structure operation to perform",
                    "enum", List.of("create", "modify", "merge", "set_field", "name_gap", "auto_create", "rename_field", "field_xrefs")
                )),

                // create
                Map.entry("name", Map.of(
                    "type", "string",
                    "description", "For action='create': structure name (required if c_definition is not provided)"
                )),
                Map.entry("size", Map.of(
                    "type", "integer",
                    "description", "For action='create' with name: initial struct size in bytes (default 0)",
                    "default", 0,
                    "minimum", 0
                )),
                Map.entry("packed", Map.of(
                    "type", "boolean",
                    "description", "For action='create' with name: if true, enable packing (no implicit alignment/padding). Default false.",
                    "default", false
                )),
                Map.entry("category", Map.of(
                    "type", "string",
                    "description", "For action='create': optional category path (e.g. \"/mytypes\" or \"/auto_structs\")"
                )),
                Map.entry("c_definition", Map.of(
                    "type", "string",
                    "description", "For action='create' or 'modify': C-like struct definition. Prefer exactly one struct definition.\n" +
                        "Examples:\n" +
                        "  \"struct Foo { int a; char b; };\"\n" +
                        "  \"typedef struct Bar { uint x; } Bar;\"\n" +
                        "Notes:\n" +
                        "- For modify, if multiple structs are defined, the tool will try to pick the one matching structure_name; otherwise it errors."
                )),

                // modify
                Map.entry("structure_name", Map.of(
                    "type", "string",
                    "description", "For action='modify'/'rename_field'/'field_xrefs': target structure name (searched in '/', '/auto_structs/', and by bare name)"
                )),
                Map.entry("new_name", Map.of(
                    "type", "string",
                    "description", "For action='modify': optional new name to rename the structure to"
                )),
                Map.entry("allow_empty", Map.of(
                    "type", "boolean",
                    "description", "For action='modify': if true, allow replacing a non-empty struct with an empty parsed definition. Default false (safety).",
                    "default", false
                )),
                Map.entry("update_packing", Map.of(
                    "type", "boolean",
                    "description", "For action='merge': if true, update the target structure's packing setting to match the parsed C definition. Default false.",
                    "default", false
                )),

                // auto_create
                Map.entry("function_identifier", Map.of(
                    "type", "string",
                    "description", "For action='auto_create': function name or address identifying which function to decompile"
                )),
                Map.entry("variable_name", Map.of(
                    "type", "string",
                    "description", "For action='auto_create': variable name in the decompiler output to infer/apply a structure to"
                )),

                // rename_field
                Map.entry("old_field_name", Map.of(
                    "type", "string",
                    "description", "For action='rename_field': existing field name to rename (provide either old_field_name or offset)"
                )),
                Map.entry("new_field_name", Map.of(
                    "type", "string",
                    "description", "For action='rename_field': new field name"
                )),
                Map.entry("offset", Map.of(
                    "type", "integer",
                    "description", "For action='rename_field': field offset (in bytes) if renaming by offset. For action='field_xrefs': pagination offset (number of results to skip).",
                    "minimum", 0
                )),

                // set_field / name_gap
                Map.entry("data_type", Map.of(
                    "type", "string",
                    "description", "For action='set_field': base data type name (e.g. \"uint\", \"int\", \"MyStruct\"). Must exist in the program DataTypeManager."
                )),
                Map.entry("comment", Map.of(
                    "type", "string",
                    "description", "For action='set_field'/'name_gap': optional field comment"
                )),
                Map.entry("pointer_level", Map.of(
                    "type", "integer",
                    "description", "For action='set_field': number of pointer indirections to apply to data_type (e.g. 1 for T*, 2 for T**). Default 0.",
                    "default", 0,
                    "minimum", 0
                )),
                Map.entry("array_count", Map.of(
                    "type", "integer",
                    "description", "For action='set_field': if provided, wraps the (possibly pointer-adjusted) type in an array of this many elements.",
                    "minimum", 1
                )),
                Map.entry("field_length", Map.of(
                    "type", "integer",
                    "description", "For action='set_field'/'name_gap': explicit length in bytes. Required when the resolved data type has variable/unknown length. For name_gap, this is the gap size.",
                    "minimum", 1
                )),
                Map.entry("op", Map.of(
                    "type", "string",
                    "description", "For action='set_field': how to apply the field at offset.",
                    "enum", List.of("replace", "insert"),
                    "default", "replace"
                )),
                Map.entry("grow", Map.of(
                    "type", "boolean",
                    "description", "For action='set_field'/'name_gap': if true, grows structure size as needed when offset+length exceeds current size. Default true.",
                    "default", true
                )),
                Map.entry("allow_overwrite", Map.of(
                    "type", "boolean",
                    "description", "For action='name_gap': if false (default), refuses to overwrite any non-undefined bytes in the target range.",
                    "default", false
                )),

                // field_xrefs + set_field/name_gap naming
                Map.entry("field_name", Map.of(
                    "type", "string",
                    "description", "For action='set_field'/'name_gap': field name to apply at the target offset. For action='field_xrefs': field name to find references for (provide either field_name or field_offset)."
                )),
                Map.entry("field_offset", Map.of(
                    "type", "integer",
                    "description", "For action='field_xrefs': field offset (in bytes) to find references for (provide either field_name or field_offset)",
                    "minimum", 0
                )),
                Map.entry("instance_address", Map.of(
                    "type", "string",
                    "description", "For action='field_xrefs': optional base address of a struct instance to find instance-based references (in addition to type-based)"
                )),
                Map.entry("limit", Map.of(
                    "type", "integer",
                    "description", "For action='field_xrefs': maximum number of references to return (default 100)",
                    "default", 100,
                    "minimum", 1
                ))
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return execute(arguments, currentProgram, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String action = (String) arguments.get("action");
        if (action == null || action.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("action parameter is required ('create', 'modify', 'auto_create', 'rename_field', or 'field_xrefs')")
                .build();
        }

        action = action.toLowerCase();

        switch (action) {
            case "create":
                return executeCreate(arguments, currentProgram);
            case "modify":
                return executeModify(arguments, currentProgram);
            case "merge":
                return executeMerge(arguments, currentProgram);
            case "set_field":
                return executeSetField(arguments, currentProgram);
            case "name_gap":
                return executeNameGap(arguments, currentProgram);
            case "auto_create":
                return executeAutoCreate(arguments, currentProgram);
            case "rename_field":
                return executeRenameField(arguments, currentProgram);
            case "field_xrefs":
                return executeFieldXrefs(arguments, currentProgram);
            default:
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid action. Use 'create', 'modify', 'merge', 'set_field', 'name_gap', 'auto_create', 'rename_field', or 'field_xrefs'")
                    .build();
        }
    }

    // ========== CREATE ACTION ==========

    private McpSchema.CallToolResult executeCreate(Map<String, Object> arguments, Program currentProgram) {
        String name = (String) arguments.get("name");
        String cDefinition = (String) arguments.get("c_definition");
        String category = (String) arguments.get("category");
        Number sizeNum = (Number) arguments.get("size");
        Boolean packed = (Boolean) arguments.get("packed");

        // Validate input - need either name or c_definition
        if ((name == null || name.isEmpty()) && (cDefinition == null || cDefinition.isEmpty())) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either 'name' (for empty struct) or 'c_definition' must be provided for create action")
                .build();
        }

        int txId = currentProgram.startTransaction("Create Structure");
        boolean committed = false;
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            Structure result;

            if (cDefinition != null && !cDefinition.isEmpty()) {
                result = createStructFromCDefinition(dtm, cDefinition, category);
            } else {
                int size = sizeNum != null ? sizeNum.intValue() : 0;
                result = createEmptyStruct(dtm, name, size, category, packed != null && packed);
            }

            if (result == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to create structure")
                    .build();
            }

            committed = true;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully created structure '" + result.getName() +
                    "' with " + result.getNumComponents() + " components, size " +
                    result.getLength() + " bytes at category " + result.getCategoryPath())
                .build();

        } catch (Exception e) {
            String msg = "Error creating structure: " + e.getMessage();
            Msg.error(this, msg, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent(msg)
                .build();
        } finally {
            currentProgram.endTransaction(txId, committed);
        }
    }

    private Structure createEmptyStruct(DataTypeManager dtm, String name, int size,
                                        String category, boolean packed) {
        CategoryPath categoryPath = category != null && !category.isEmpty()
            ? new CategoryPath(category)
            : CategoryPath.ROOT;

        StructureDataType struct = new StructureDataType(categoryPath, name, size, dtm);

        if (packed) {
            struct.setPackingEnabled(true);
        }

        DataType addedType = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);

        if (addedType instanceof Structure) {
            Msg.info(this, "Created empty structure: " + name);
            return (Structure) addedType;
        }

        return null;
    }

    private Structure createStructFromCDefinition(DataTypeManager dtm, String cDefinition,
                                                   String category) throws Exception {
        String normalizedDef = cDefinition.trim();
        if (!normalizedDef.endsWith(";")) {
            normalizedDef += ";";
        }

        CParser parser = new CParser(dtm);

        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(
                normalizedDef.getBytes(StandardCharsets.UTF_8));
            parser.parse(inputStream);

            Map<String, DataType> composites = parser.getComposites();

            if (composites.isEmpty()) {
                throw new Exception("No structure definition found in the provided C code. " +
                    "Make sure to use format: 'struct Name { type field; ... };'");
            }

            Structure parsedStruct = selectParsedStructure(composites, null);

            if (category != null && !category.isEmpty()) {
                CategoryPath categoryPath = new CategoryPath(category);
                parsedStruct.setCategoryPath(categoryPath);
            }

            DataType addedType = dtm.addDataType(parsedStruct, DataTypeConflictHandler.REPLACE_HANDLER);

            if (addedType instanceof Structure) {
                Msg.info(this, "Created structure from C definition: " + addedType.getName());
                return (Structure) addedType;
            }

            return null;

        } catch (ghidra.app.util.cparser.C.ParseException pe) {
            throw new Exception("C parse error: " + pe.getMessage() +
                ". Check your struct definition syntax.");
        }
    }

    // ========== MODIFY ACTION ==========

    private McpSchema.CallToolResult executeModify(Map<String, Object> arguments, Program currentProgram) {
        String structureName = (String) arguments.get("structure_name");
        String cDefinition = (String) arguments.get("c_definition");
        String newName = (String) arguments.get("new_name");
        Boolean allowEmpty = (Boolean) arguments.get("allow_empty");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required for modify action")
                .build();
        }

        if (cDefinition == null || cDefinition.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("c_definition parameter is required for modify action")
                .build();
        }

        int txId = currentProgram.startTransaction("Modify Structure");
        boolean committed = false;
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();

            Structure existingStruct = findStructure(dtm, structureName);
            if (existingStruct == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Structure '" + structureName + "' not found. " +
                        "Use action='create' to create a new structure.")
                    .build();
            }

            var categoryPath = existingStruct.getCategoryPath();

            Structure newStruct = parseStructFromCDefinition(dtm, cDefinition, structureName);
            if (newStruct == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to parse C structure definition")
                    .build();
            }

            boolean allowEmptyStruct = allowEmpty != null && allowEmpty;
            Structure result = applyNewDefinition(dtm, existingStruct, newStruct, newName, categoryPath, allowEmptyStruct);

            if (result == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to apply new structure definition")
                    .build();
            }

            committed = true;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully modified structure '" + result.getName() +
                    "': now has " + result.getNumComponents() + " components, size " +
                    result.getLength() + " bytes")
                .build();

        } catch (Exception e) {
            String msg = "Error modifying structure: " + e.getMessage();
            Msg.error(this, msg, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent(msg)
                .build();
        } finally {
            currentProgram.endTransaction(txId, committed);
        }
    }

    // ========== MERGE ACTION ==========

    /**
     * Merge (overlay) a parsed C structure definition onto an existing structure without deleting
     * existing fields first. This is useful for incrementally adding a few fields without rewriting
     * the full definition.
     *
     * Notes:
     * - Only reliable for non-packed structures. For packed structures, use modify or set_field.
     */
    private McpSchema.CallToolResult executeMerge(Map<String, Object> arguments, Program currentProgram) {
        String structureName = (String) arguments.get("structure_name");
        String cDefinition = (String) arguments.get("c_definition");
        Boolean updatePacking = (Boolean) arguments.get("update_packing");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required for merge action")
                .build();
        }
        if (cDefinition == null || cDefinition.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("c_definition parameter is required for merge action")
                .build();
        }

        int txId = currentProgram.startTransaction("Merge Structure Fields");
        boolean committed = false;
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            Structure existingStruct = findStructure(dtm, structureName);
            if (existingStruct == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Structure '" + structureName + "' not found. Use action='create' first.")
                    .build();
            }

            if (existingStruct.isPackingEnabled()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Cannot safely merge into a packed structure ('" + existingStruct.getName() +
                        "'). Use action='modify' or action='set_field' instead.")
                    .build();
            }

            Structure parsedStruct = parseStructFromCDefinition(dtm, cDefinition, structureName);
            if (parsedStruct == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to parse C structure definition")
                    .build();
            }

            StructureSnapshot snapshot = snapshotStructure(parsedStruct);
            boolean shouldUpdatePacking = updatePacking != null && updatePacking;
            if (shouldUpdatePacking) {
                existingStruct.setPackingEnabled(snapshot.packed);
            }

            for (ComponentSnapshot comp : snapshot.components) {
                int offset = comp.offset;
                DataType compType = comp.dataType;
                int compLength = comp.length;
                String fieldName = comp.fieldName;
                String comment = comp.comment;

                if (!existingStruct.isPackingEnabled() && existingStruct.getLength() < offset) {
                    existingStruct.growStructure(offset - existingStruct.getLength());
                }
                try {
                    existingStruct.replaceAtOffset(offset, compType, compLength, fieldName, comment);
                } catch (Exception e) {
                    existingStruct.insertAtOffset(offset, compType, compLength, fieldName, comment);
                }
            }

            committed = true;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully merged fields into structure '" + existingStruct.getName() +
                    "': now has " + existingStruct.getNumComponents() + " components, size " +
                    existingStruct.getLength() + " bytes")
                .build();

        } catch (Exception e) {
            String msg = "Error merging structure fields: " + e.getMessage();
            Msg.error(this, msg, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent(msg)
                .build();
        } finally {
            currentProgram.endTransaction(txId, committed);
        }
    }

    // ========== SET_FIELD ACTION ==========

    private McpSchema.CallToolResult executeSetField(Map<String, Object> arguments, Program currentProgram) {
        String structureName = (String) arguments.get("structure_name");
        Number fieldOffsetNum = (Number) arguments.get("field_offset");
        String dataTypeName = (String) arguments.get("data_type");
        String fieldName = (String) arguments.get("field_name");
        String comment = (String) arguments.get("comment");
        Number pointerLevelNum = (Number) arguments.get("pointer_level");
        Number arrayCountNum = (Number) arguments.get("array_count");
        Number fieldLengthNum = (Number) arguments.get("field_length");
        String op = (String) arguments.get("op");
        Boolean grow = (Boolean) arguments.get("grow");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required for set_field action")
                .build();
        }
        if (fieldOffsetNum == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("field_offset parameter is required for set_field action")
                .build();
        }
        if (dataTypeName == null || dataTypeName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("data_type parameter is required for set_field action")
                .build();
        }

        int fieldOffset = fieldOffsetNum.intValue();
        int pointerLevel = pointerLevelNum != null ? pointerLevelNum.intValue() : 0;
        Integer arrayCount = arrayCountNum != null ? arrayCountNum.intValue() : null;
        Integer explicitLength = fieldLengthNum != null ? fieldLengthNum.intValue() : null;
        String operation = op != null && !op.isBlank() ? op.toLowerCase() : "replace";
        boolean shouldGrow = grow == null || grow;

        if (!operation.equals("replace") && !operation.equals("insert")) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid op for set_field: '" + op + "'. Use 'replace' or 'insert'.")
                .build();
        }
        if (fieldOffset < 0) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("field_offset must be >= 0")
                .build();
        }
        if (pointerLevel < 0) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("pointer_level must be >= 0")
                .build();
        }
        if (arrayCount != null && arrayCount < 1) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("array_count must be >= 1")
                .build();
        }
        if (explicitLength != null && explicitLength < 1) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("field_length must be >= 1")
                .build();
        }

        int txId = currentProgram.startTransaction("Set Structure Field");
        boolean committed = false;
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            Structure struct = findStructure(dtm, structureName);
            if (struct == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Structure '" + structureName + "' not found")
                    .build();
            }

            DataType baseType = resolveDataType(dtm, dataTypeName);
            if (baseType == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Data type not found: " + dataTypeName)
                    .build();
            }

            DataType resolvedType = baseType;
            for (int i = 0; i < pointerLevel; i++) {
                resolvedType = dtm.getPointer(resolvedType);
            }
            if (arrayCount != null) {
                int elemLen = resolvedType.getLength();
                if (elemLen <= 0) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Cannot build array of variable-length type '" + resolvedType.getName() +
                            "'. Provide a fixed-length base type (or avoid array_count).")
                        .build();
                }
                resolvedType = new ArrayDataType(resolvedType, arrayCount, elemLen);
            }

            int length = explicitLength != null ? explicitLength : resolvedType.getLength();
            if (length <= 0) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Resolved data type '" + resolvedType.getName() + "' has variable/unknown length. " +
                        "Provide field_length explicitly.")
                    .build();
            }

            if (shouldGrow && struct.getLength() < fieldOffset + length) {
                int needed = (fieldOffset + length) - struct.getLength();
                if (needed > 0) {
                    struct.growStructure(needed);
                }
            }

            try {
                if (operation.equals("insert")) {
                    struct.insertAtOffset(fieldOffset, resolvedType, length, fieldName, comment);
                } else {
                    struct.replaceAtOffset(fieldOffset, resolvedType, length, fieldName, comment);
                }
            } catch (Exception e) {
                // Fallback: replace might fail if there's no component at offset, and insert might fail due to overlap.
                // Try the other operation before failing.
                try {
                    if (operation.equals("insert")) {
                        struct.replaceAtOffset(fieldOffset, resolvedType, length, fieldName, comment);
                    } else {
                        struct.insertAtOffset(fieldOffset, resolvedType, length, fieldName, comment);
                    }
                } catch (Exception e2) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Failed to apply field at offset 0x" + Integer.toHexString(fieldOffset) +
                            " in structure '" + struct.getName() + "': " + e2.getMessage())
                        .build();
                }
            }

            committed = true;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully set field at +0x" + Integer.toHexString(fieldOffset) +
                    " in structure '" + struct.getName() + "' to type '" + resolvedType.getName() + "'" +
                    (fieldName != null && !fieldName.isBlank() ? " name '" + fieldName + "'" : "") +
                    " (" + length + " bytes)")
                .build();

        } catch (Exception e) {
            String msg = "Error setting structure field: " + e.getMessage();
            Msg.error(this, msg, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent(msg)
                .build();
        } finally {
            currentProgram.endTransaction(txId, committed);
        }
    }

    // ========== NAME_GAP ACTION ==========

    private McpSchema.CallToolResult executeNameGap(Map<String, Object> arguments, Program currentProgram) {
        String structureName = (String) arguments.get("structure_name");
        Number fieldOffsetNum = (Number) arguments.get("field_offset");
        Number fieldLengthNum = (Number) arguments.get("field_length");
        String fieldName = (String) arguments.get("field_name");
        String comment = (String) arguments.get("comment");
        Boolean allowOverwrite = (Boolean) arguments.get("allow_overwrite");
        Boolean grow = (Boolean) arguments.get("grow");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required for name_gap action")
                .build();
        }
        if (fieldOffsetNum == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("field_offset parameter is required for name_gap action")
                .build();
        }
        if (fieldLengthNum == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("field_length parameter is required for name_gap action")
                .build();
        }
        if (fieldName == null || fieldName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("field_name parameter is required for name_gap action")
                .build();
        }

        int fieldOffset = fieldOffsetNum.intValue();
        int fieldLength = fieldLengthNum.intValue();
        if (fieldOffset < 0 || fieldLength < 1) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("field_offset must be >= 0 and field_length must be >= 1")
                .build();
        }

        boolean shouldGrow = grow == null || grow;
        boolean canOverwrite = allowOverwrite != null && allowOverwrite;

        int txId = currentProgram.startTransaction("Name Structure Gap");
        boolean committed = false;
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            Structure struct = findStructure(dtm, structureName);
            if (struct == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Structure '" + structureName + "' not found")
                    .build();
            }

            if (shouldGrow && struct.getLength() < fieldOffset + fieldLength) {
                int needed = (fieldOffset + fieldLength) - struct.getLength();
                if (needed > 0) {
                    struct.growStructure(needed);
                }
            }

            int start = fieldOffset;
            int endExclusive = fieldOffset + fieldLength;

            if (!canOverwrite) {
                for (DataTypeComponent comp : struct.getComponents()) {
                    int compStart = comp.getOffset();
                    int compEndExclusive = comp.getEndOffset() + 1;
                    boolean overlaps = compStart < endExclusive && compEndExclusive > start;
                    if (overlaps && !comp.isUndefined()) {
                        return McpSchema.CallToolResult.builder()
                            .addTextContent("Refusing to overwrite non-undefined component at +0x" +
                                Integer.toHexString(comp.getOffset()) + " (" + comp.getDataType().getName() + "). " +
                                "Pass allow_overwrite=true to force.")
                            .build();
                    }
                }
            }

            DataType gapElem = UnsignedCharDataType.dataType;
            DataType gapArray = new ArrayDataType(gapElem, fieldLength, gapElem.getLength());
            struct.replaceAtOffset(fieldOffset, gapArray, gapArray.getLength(), fieldName, comment);

            committed = true;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully named gap in structure '" + struct.getName() + "' at +0x" +
                    Integer.toHexString(fieldOffset) + " (" + fieldLength + " bytes) as '" + fieldName + "'")
                .build();

        } catch (Exception e) {
            String msg = "Error naming structure gap: " + e.getMessage();
            Msg.error(this, msg, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent(msg)
                .build();
        } finally {
            currentProgram.endTransaction(txId, committed);
        }
    }

    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        if (typeName == null) {
            return null;
        }
        String t = typeName.trim();
        if (t.isEmpty()) {
            return null;
        }

        // Direct path lookup (if caller provides a full path)
        if (t.startsWith("/")) {
            DataType byPath = dtm.getDataType(t);
            if (byPath != null) {
                return byPath;
            }
        }

        // Common lookups
        DataType dt = dtm.getDataType("/" + t);
        if (dt == null) {
            dt = dtm.getDataType(t);
        }

        if (dt != null) {
            return dt;
        }

        // Search all types by name
        List<DataType> allTypes = new ArrayList<>();
        dtm.getAllDataTypes(allTypes);
        for (DataType candidate : allTypes) {
            if (candidate.getName().equals(t)) {
                return candidate;
            }
        }
        return null;
    }

    private Structure findStructure(DataTypeManager dtm, String structureName) {
        String[] searchPaths = {
            "/" + structureName,
            "/auto_structs/" + structureName,
            structureName
        };

        for (String path : searchPaths) {
            DataType dt = dtm.getDataType(path);
            if (dt instanceof Structure) {
                return (Structure) dt;
            }
        }

        List<DataType> allTypes = new ArrayList<>();
        dtm.getAllDataTypes(allTypes);
        for (DataType dt : allTypes) {
            if (dt instanceof Structure && dt.getName().equals(structureName)) {
                return (Structure) dt;
            }
        }

        return null;
    }

    private Structure parseStructFromCDefinition(DataTypeManager dtm, String cDefinition, String expectedStructName) throws Exception {
        String normalizedDef = cDefinition.trim();
        if (!normalizedDef.endsWith(";")) {
            normalizedDef += ";";
        }

        CParser parser = new CParser(dtm);

        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(
                normalizedDef.getBytes(StandardCharsets.UTF_8));
            parser.parse(inputStream);

            Map<String, DataType> composites = parser.getComposites();

            if (composites.isEmpty()) {
                throw new Exception("No structure definition found in the provided C code. " +
                    "Make sure to use format: 'struct Name { type field; ... };'");
            }

            return selectParsedStructure(composites, expectedStructName);

        } catch (ghidra.app.util.cparser.C.ParseException pe) {
            throw new Exception("C parse error: " + pe.getMessage() +
                ". Check your struct definition syntax.");
        }
    }

    private Structure applyNewDefinition(DataTypeManager dtm, Structure existingStruct,
                                         Structure newStruct, String newName,
                                         ghidra.program.model.data.CategoryPath categoryPath,
                                         boolean allowEmptyStruct) throws Exception {
        // IMPORTANT: The C parser may return a Structure object that is the same DataType instance
        // as the struct we're modifying (or otherwise shares backing storage via the DTM).
        // If we delete components before snapshotting, we can accidentally wipe the parsed definition.
        StructureSnapshot snapshot = snapshotStructure(newStruct);

        int existingDefinedCount = existingStruct.getDefinedComponents().length;
        if (!allowEmptyStruct && snapshot.components.isEmpty() && existingDefinedCount > 0) {
            throw new Exception("Parsed structure definition contained no fields; refusing to replace a non-empty " +
                "structure with an empty one. If you really want an empty struct, pass allow_empty=true.");
        }

        existingStruct.deleteAll();

        boolean isPacked = snapshot.packed;
        existingStruct.setPackingEnabled(isPacked);

        for (ComponentSnapshot comp : snapshot.components) {
            DataType compType = comp.dataType;
            int compLength = comp.length;
            String fieldName = comp.fieldName;
            String comment = comp.comment;
            int offset = comp.offset;

            if (!isPacked && existingStruct.getLength() < offset) {
                existingStruct.growStructure(offset - existingStruct.getLength());
            }

            if (isPacked) {
                if (fieldName != null) {
                    existingStruct.add(compType, compLength, fieldName, comment);
                } else {
                    existingStruct.add(compType, compLength, null, comment);
                }
            } else {
                try {
                    existingStruct.replaceAtOffset(offset, compType, compLength, fieldName, comment);
                } catch (Exception e) {
                    existingStruct.insertAtOffset(offset, compType, compLength, fieldName, comment);
                }
            }
        }

        // Preserve original category path (C parser may have placed the parsed struct elsewhere)
        try {
            if (categoryPath != null) {
                existingStruct.setCategoryPath(categoryPath);
            }
        } catch (Exception e) {
            Msg.warn(this, "Could not preserve category path for '" + existingStruct.getName() + "': " + e.getMessage());
        }

        if (newName != null && !newName.isEmpty() && !newName.equals(existingStruct.getName())) {
            try {
                existingStruct.setName(newName);
            } catch (Exception e) {
                Msg.warn(this, "Could not rename structure to '" + newName + "': " + e.getMessage());
            }
        }

        Msg.info(this, "Modified structure: " + existingStruct.getName() +
            " with " + existingStruct.getNumComponents() + " components");

        return existingStruct;
    }

    private StructureSnapshot snapshotStructure(Structure struct) {
        boolean packed = struct.isPackingEnabled();
        DataTypeComponent[] defined = struct.getDefinedComponents();

        List<ComponentSnapshot> snapshots = new ArrayList<>(defined.length);
        for (DataTypeComponent comp : defined) {
            snapshots.add(new ComponentSnapshot(
                comp.getOffset(),
                comp.getDataType(),
                comp.getLength(),
                comp.getFieldName(),
                comp.getComment()
            ));
        }
        return new StructureSnapshot(packed, snapshots);
    }

    private Structure selectParsedStructure(Map<String, DataType> composites, String expectedStructName) throws Exception {
        List<Structure> parsedStructs = new ArrayList<>();
        for (DataType dt : composites.values()) {
            if (dt instanceof Structure) {
                parsedStructs.add((Structure) dt);
            }
        }

        if (parsedStructs.isEmpty()) {
            // Provide better diagnostics than "not a structure" on an arbitrary iterator().next()
            List<String> names = new ArrayList<>();
            for (DataType dt : composites.values()) {
                names.add(dt.getName());
            }
            throw new Exception("Parsed C code did not produce a structure. Parsed composites: " + names);
        }

        if (expectedStructName != null && !expectedStructName.isBlank()) {
            for (Structure s : parsedStructs) {
                if (expectedStructName.equals(s.getName())) {
                    return s;
                }
            }

            if (parsedStructs.size() == 1) {
                // If only one struct was defined, accept it even if the name didn't match
                return parsedStructs.get(0);
            }

            List<String> names = new ArrayList<>();
            for (Structure s : parsedStructs) {
                names.add(s.getName());
            }
            throw new Exception("C code defined multiple structures, but none matched expected name '" +
                expectedStructName + "'. Defined structures: " + names);
        }

        if (parsedStructs.size() > 1) {
            List<String> names = new ArrayList<>();
            for (Structure s : parsedStructs) {
                names.add(s.getName());
            }
            throw new Exception("C code defined multiple structures; please provide only one structure definition. " +
                "Defined structures: " + names);
        }

        return parsedStructs.get(0);
    }

    // ========== AUTO_CREATE ACTION ==========

    private McpSchema.CallToolResult executeAutoCreate(Map<String, Object> arguments, Program currentProgram) {
        String functionIdentifier = (String) arguments.get("function_identifier");
        String variableName = (String) arguments.get("variable_name");

        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("function_identifier parameter is required for auto_create action")
                .build();
        }

        if (variableName == null || variableName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("variable_name parameter is required for auto_create action")
                .build();
        }

        StructureResult result = createAndApplyStructure(currentProgram, functionIdentifier, variableName);

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.success ?
                "Successfully created and applied structure: " + result.message :
                "Failed to create structure: " + result.errorMessage)
            .build();
    }

    private static class StructureResult {
        final boolean success;
        final String message;
        final String errorMessage;

        StructureResult(boolean success, String message, String errorMessage) {
            this.success = success;
            this.message = message;
            this.errorMessage = errorMessage;
        }
    }

    private StructureResult createAndApplyStructure(Program program, String functionIdentifier, String variableName) {
        final StringBuilder errorMessage = new StringBuilder();
        final StringBuilder successMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() ->
                performStructureCreation(program, functionIdentifier, variableName, success, successMessage, errorMessage));
        } catch (Exception e) {
            String msg = "Failed to create structure on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new StructureResult(success.get(), successMessage.toString(), errorMessage.toString());
    }

    private void performStructureCreation(Program program, String functionIdentifier, String variableName,
                                        AtomicBoolean success, StringBuilder successMessage, StringBuilder errorMessage) {
        int txId = program.startTransaction("Auto Create Structure");
        boolean committed = false;

        try {
            Function function = findFunction(program, functionIdentifier);
            if (function == null) {
                errorMessage.append("Could not find function: ").append(functionIdentifier);
                return;
            }

            Msg.info(this, "Creating structure for variable '" + variableName + "' in function " + function.getName());

            try (DecompilerSession session = decompilerService.open(program)) {
                DecompInterface decompiler = session.decompiler();
                DecompileResults results = decompiler.decompileFunction(function,
                    session.options().getDefaultTimeout(), TaskMonitor.DUMMY);

                if (!results.decompileCompleted()) {
                    errorMessage.append("Decompilation failed for function: ").append(function.getName());
                    return;
                }

                HighFunction highFunction = results.getHighFunction();

                HighVariable highVar = findHighVariable(highFunction, variableName);
                if (highVar == null) {
                    errorMessage.append("Could not find variable '").append(variableName).append("' in function");
                    return;
                }

                boolean applied = createAndApplyStructureImpl(program, function, highVar, decompiler, highFunction,
                    successMessage, errorMessage);

                if (applied) {
                    success.set(true);
                    committed = true;
                }

            }

        } catch (Exception e) {
            String msg = "Error during structure creation: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    private boolean createAndApplyStructureImpl(Program program, Function function, HighVariable highVar,
                                             DecompInterface decompiler, HighFunction highFunction,
                                             StringBuilder successMessage, StringBuilder errorMessage) throws Exception {

        Structure structDT = null;
        try {
            Class<?> fillHelperClass = Class.forName("ghidra.app.decompiler.util.FillOutStructureHelper");
            Object fillHelper = fillHelperClass.getConstructor(Program.class, TaskMonitor.class)
                .newInstance(program, TaskMonitor.DUMMY);

            java.lang.reflect.Method processMethod = fillHelperClass.getMethod("processStructure",
                HighVariable.class, Function.class, boolean.class, boolean.class, DecompInterface.class);

            structDT = (Structure) processMethod.invoke(fillHelper, highVar, function, false, true, decompiler);
        } catch (Exception e) {
            errorMessage.append("FillOutStructureHelper not available or failed: ").append(e.getMessage());
            return false;
        }

        if (structDT == null) {
            errorMessage.append("Failed to create structure from variable usage");
            return false;
        }

        DataTypeManager dtm = program.getDataTypeManager();
        structDT = (Structure) dtm.addDataType(structDT, DataTypeConflictHandler.DEFAULT_HANDLER);
        PointerDataType ptrStruct = new PointerDataType(structDT);

        Variable var = findVariableFromDecompiler(function, highFunction, highVar.getSymbol().getName());

        if (var != null && var instanceof ghidra.program.model.listing.AutoParameterImpl) {
            updateFunctionParameter(function, var.getName(), ptrStruct);
            successMessage.append("Updated function parameter '").append(var.getName())
                         .append("' with structure type: ").append(structDT.getName());
        } else {
            HighFunctionDBUtil.updateDBVariable(highVar.getSymbol(), null, ptrStruct, SourceType.USER_DEFINED);
            successMessage.append("Updated local variable '").append(highVar.getSymbol().getName())
                         .append("' with structure type: ").append(structDT.getName());
        }

        Msg.info(this, "Successfully created and applied structure: " + structDT.getName());
        return true;
    }

    private Function findFunction(Program program, String identifier) {
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                return program.getFunctionManager().getFunctionAt(addr);
            }
        } catch (Exception e) {
            // Not an address, try as name
        }

        return FunctionLookup.findByName(program, identifier);
    }

    private HighVariable findHighVariable(HighFunction highFunction, String varName) {
        var symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol sym = symbols.next();
            if (sym.getName().equals(varName)) {
                return sym.getHighVariable();
            }
        }
        return null;
    }

    private void commitLocalNames(Program program, Function function) {
        try {
            program.flushEvents();
            if (function != null) {
                function.getLocalVariables();
                function.getParameters();
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to commit local names for function " + function.getName() + ": " + e.getMessage());
        }
    }

    private Variable findVariableFromDecompiler(Function function, HighFunction highFunction, String varName) {
        commitLocalNames(function.getProgram(), function);

        var symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getName().equals(varName)) {
                HighVariable highVar = symbol.getHighVariable();
                if (highVar != null) {
                    try {
                        var representative = highVar.getRepresentative();
                        if (representative != null) {
                            for (Parameter param : function.getParameters()) {
                                var storage = param.getVariableStorage();
                                if (storage != null && storage.getVarnodes().length > 0) {
                                    var paramVarnode = storage.getVarnodes()[0];
                                    if (paramVarnode.getAddress().equals(representative.getAddress())) {
                                        return param;
                                    }
                                }
                            }

                            for (Variable localVar : function.getLocalVariables()) {
                                var storage = localVar.getVariableStorage();
                                if (storage != null && storage.getVarnodes().length > 0) {
                                    var localVarnode = storage.getVarnodes()[0];
                                    if (localVarnode.getAddress().equals(representative.getAddress())) {
                                        return localVar;
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        // Continue if storage comparison fails
                    }
                }
            }
        }

        return null;
    }

    private void updateFunctionParameter(Function function, String paramName,
                                       DataType newType) throws InvalidInputException, DuplicateNameException {

        Parameter[] parameters = function.getParameters();
        Parameter[] newParams = new Parameter[parameters.length];

        for (int i = 0; i < parameters.length; i++) {
            if (parameters[i].getName().equals(paramName)) {
                newParams[i] = new ParameterImpl(
                    parameters[i].getName(),
                    newType,
                    parameters[i].getVariableStorage(),
                    function.getProgram(),
                    SourceType.USER_DEFINED
                );
            } else {
                newParams[i] = parameters[i];
            }
        }

        function.updateFunction(
            function.getCallingConventionName(),
            null,
            FunctionUpdateType.CUSTOM_STORAGE,
            true,
            SourceType.USER_DEFINED,
            newParams
        );
    }

    // ========== RENAME_FIELD ACTION ==========

    private McpSchema.CallToolResult executeRenameField(Map<String, Object> arguments, Program currentProgram) {
        String structureName = (String) arguments.get("structure_name");
        String newFieldName = (String) arguments.get("new_field_name");
        String oldFieldName = (String) arguments.get("old_field_name");
        Number offsetNum = (Number) arguments.get("offset");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required for rename_field action")
                .build();
        }

        if (newFieldName == null || newFieldName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("new_field_name parameter is required for rename_field action")
                .build();
        }

        if (oldFieldName == null && offsetNum == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either old_field_name or offset must be provided to identify the field")
                .build();
        }

        int txId = currentProgram.startTransaction("Rename Structure Field");
        boolean committed = false;
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            DataType dataType = dtm.getDataType("/" + structureName);
            if (dataType == null) {
                dataType = dtm.getDataType("/auto_structs/" + structureName);
            }

            if (dataType == null) {
                // Search all data types
                List<DataType> allTypes = new ArrayList<>();
                dtm.getAllDataTypes(allTypes);
                for (DataType dt : allTypes) {
                    if (dt instanceof Structure && dt.getName().equals(structureName)) {
                        dataType = dt;
                        break;
                    }
                }
            }

            if (dataType == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Structure '" + structureName + "' not found")
                    .build();
            } else if (!(dataType instanceof Structure)) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Data type '" + structureName + "' found but is not a structure")
                    .build();
            }

            Structure structure = (Structure) dataType;
            DataTypeComponent component = null;
            if (offsetNum != null) {
                int offset = offsetNum.intValue();
                if (offset < 0 || offset >= structure.getLength()) {
                     return McpSchema.CallToolResult.builder()
                        .addTextContent("Offset " + offset + " is out of bounds for structure '" + structureName + "' (length " + structure.getLength() + ")")
                        .build();
                }
                component = structure.getComponentAt(offset);
                if (component == null) {
                     return McpSchema.CallToolResult.builder()
                        .addTextContent("No component found at offset " + offset + " in structure '" + structureName + "'")
                        .build();
                }
            } else {
                DataTypeComponent[] components = structure.getComponents();
                for (DataTypeComponent c : components) {
                    String name = c.getFieldName();
                    if (name != null && name.equals(oldFieldName)) {
                        component = c;
                        break;
                    }
                }
                if (component == null) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Field '" + oldFieldName + "' not found in structure '" + structureName + "'")
                        .build();
                }
            }

            String previousName = component.getFieldName();
            try {
                component.setFieldName(newFieldName);
            } catch (Exception e) {
                 return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to set field name: " + e.getMessage())
                    .build();
            }

            committed = true;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Successfully renamed field in structure '" + structure.getName() + "': " +
                                (previousName != null ? previousName : ("offset " + component.getOffset())) +
                                " -> " + newFieldName)
                .build();

        } catch (Exception e) {
            String msg = "Error renaming structure field: " + e.getMessage();
            Msg.error(this, msg, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent(msg)
                .build();
        } finally {
            currentProgram.endTransaction(txId, committed);
        }
    }

    // ========== FIELD_XREFS ACTION ==========

    private McpSchema.CallToolResult executeFieldXrefs(Map<String, Object> arguments, Program currentProgram) {
        // Parse required parameters
        String structName = (String) arguments.get("structure_name");
        if (structName == null || structName.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required for field_xrefs action")
                .build();
        }

        // Parse optional field identifiers
        String fieldName = (String) arguments.get("field_name");
        Integer fieldOffset = null;
        if (arguments.get("field_offset") instanceof Number) {
            fieldOffset = ((Number) arguments.get("field_offset")).intValue();
        }

        if ((fieldName == null || fieldName.trim().isEmpty()) && fieldOffset == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either field_name or field_offset parameter is required for field_xrefs action")
                .build();
        }

        // Parse optional instance address
        String instanceAddressStr = (String) arguments.get("instance_address");
        Address instanceAddress = null;
        if (instanceAddressStr != null && !instanceAddressStr.trim().isEmpty()) {
            try {
                instanceAddress = currentProgram.getAddressFactory().getAddress(instanceAddressStr);
            } catch (Exception e) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid instance_address format: " + instanceAddressStr)
                    .build();
            }
        }

        // Parse pagination
        int offset = 0;
        int limit = 100;
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }

        // Resolve structure
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Structure struct = resolveStructureForXrefs(dtm, structName);
        if (struct == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Structure not found: " + structName)
                .build();
        }

        // Resolve field
        DataTypeComponent fieldComponent = resolveFieldForXrefs(struct, fieldName, fieldOffset);
        if (fieldComponent == null) {
            String fieldDesc = fieldName != null ? "field_name: " + fieldName : "field_offset: " + fieldOffset;
            return McpSchema.CallToolResult.builder()
                .addTextContent("Field not found in structure " + struct.getName() + " with " + fieldDesc)
                .build();
        }

        int resolvedFieldOffset = fieldComponent.getOffset();
        int fieldSize = fieldComponent.getLength();
        String resolvedFieldName = fieldComponent.getFieldName() != null ?
            fieldComponent.getFieldName() : "(offset_" + resolvedFieldOffset + ")";

        // Build result
        StringBuilder result = new StringBuilder();
        result.append("Struct Field Cross-References for ")
              .append(struct.getName()).append(".").append(resolvedFieldName)
              .append(" (offset +0x").append(String.format("%X", resolvedFieldOffset))
              .append(", ").append(fieldSize).append(" bytes):\n\n");

        List<FieldReference> allReferences = new ArrayList<>();

        // Run type-based query (decompiler analysis)
        List<FieldReference> typeBasedRefs = findTypeBasedReferences(
            currentProgram, struct, resolvedFieldName, resolvedFieldOffset);

        if (!typeBasedRefs.isEmpty()) {
            result.append("=== Type-Based References ===\n");
            allReferences.addAll(typeBasedRefs);
        }

        // Run instance-based query if address provided
        if (instanceAddress != null) {
            List<FieldReference> instanceRefs = findInstanceBasedReferences(
                currentProgram, instanceAddress, resolvedFieldOffset, fieldSize);

            if (!instanceRefs.isEmpty()) {
                result.append("\n=== Instance-Based References (at ")
                      .append(instanceAddress).append(") ===\n");
                allReferences.addAll(instanceRefs);
            }
        }

        // Format and paginate results
        if (allReferences.isEmpty()) {
            result.append("No references found.\n");
        } else {
            String currentFunction = null;
            int displayCount = 0;
            int totalCount = allReferences.size();

            for (int i = 0; i < allReferences.size(); i++) {
                if (i < offset) continue;
                if (displayCount >= limit) break;

                FieldReference ref = allReferences.get(i);

                // Print function header for new functions
                if (ref.source.equals("DECOMPILER") &&
                    (currentFunction == null || !currentFunction.equals(ref.functionName))) {
                    currentFunction = ref.functionName;
                    result.append("\nFunction: ").append(ref.functionName);
                    if (ref.functionAddress != null) {
                        result.append(" (").append(ref.functionAddress).append(")");
                    }
                    result.append("\n");
                }

                result.append("  ").append(ref.toString()).append("\n");
                displayCount++;
            }

            result.append("\nShowing ").append(displayCount).append(" of ")
                  .append(totalCount).append(" references");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
            result.append("\n");
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Resolve a structure by name from the DataTypeManager for field_xrefs.
     */
    private Structure resolveStructureForXrefs(DataTypeManager dtm, String structName) {
        // Try direct lookup
        DataType dt = dtm.getDataType("/" + structName);
        if (dt instanceof Structure) {
            return (Structure) dt;
        }

        // Try without leading slash
        dt = dtm.getDataType(structName);
        if (dt instanceof Structure) {
            return (Structure) dt;
        }

        // Search all data types
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();

            // Unwrap TypeDef
            DataType baseType = dataType;
            while (baseType instanceof TypeDef) {
                baseType = ((TypeDef) baseType).getBaseDataType();
            }

            if (baseType instanceof Structure) {
                Structure s = (Structure) baseType;
                if (s.getName().equals(structName)) {
                    return s;
                }
            }
        }

        // Try case-insensitive search
        iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();
            DataType baseType = dataType;
            while (baseType instanceof TypeDef) {
                baseType = ((TypeDef) baseType).getBaseDataType();
            }

            if (baseType instanceof Structure) {
                Structure s = (Structure) baseType;
                if (s.getName().equalsIgnoreCase(structName)) {
                    return s;
                }
            }
        }

        return null;
    }

    /**
     * Resolve a field within a structure by name or offset for field_xrefs.
     */
    private DataTypeComponent resolveFieldForXrefs(Structure struct, String fieldName, Integer fieldOffset) {
        DataTypeComponent[] components = struct.getComponents();

        // If offset is provided, use it directly
        if (fieldOffset != null) {
            DataTypeComponent comp = struct.getComponentAt(fieldOffset);
            if (comp != null) {
                return comp;
            }
            // Try exact offset match in components
            for (DataTypeComponent comp2 : components) {
                if (comp2.getOffset() == fieldOffset) {
                    return comp2;
                }
            }
            return null;
        }

        // Search by field name
        if (fieldName != null) {
            // Exact match first
            for (DataTypeComponent comp : components) {
                String compName = comp.getFieldName();
                if (compName != null && compName.equals(fieldName)) {
                    return comp;
                }
            }

            // Case-insensitive match
            for (DataTypeComponent comp : components) {
                String compName = comp.getFieldName();
                if (compName != null && compName.equalsIgnoreCase(fieldName)) {
                    return comp;
                }
            }
        }

        return null;
    }

    /**
     * Find type-based references using decompiler analysis.
     */
    private List<FieldReference> findTypeBasedReferences(
            Program program,
            Structure targetStruct,
            String targetFieldName,
            int targetFieldOffset) {

        List<FieldReference> references = new ArrayList<>();

        try (DecompilerSession session = decompilerService.open(program)) {
            DecompInterface decompiler = session.decompiler();

            // Iterate all functions
            FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext()) {
                Function function = funcIter.next();

                // Skip external/thunk functions
                if (function.isExternal() || function.isThunk()) {
                    continue;
                }

                try {
                    // Decompile with timeout
                    DecompileResults results = decompiler.decompileFunction(
                        function, session.options().getDefaultTimeout(), TaskMonitor.DUMMY);

                    if (!results.decompileCompleted()) {
                        continue;
                    }

                    ClangTokenGroup tokenGroup = results.getCCodeMarkup();
                    if (tokenGroup == null) {
                        continue;
                    }

                    // Walk token tree looking for field accesses
                    walkClangTokens(tokenGroup, targetStruct, targetFieldOffset,
                        function.getName(), function.getEntryPoint(), references);

                } catch (Exception e) {
                    // Skip functions that fail to decompile
                    continue;
                }
            }
        }

        return references;
    }

    /**
     * Recursively walk the Clang token tree looking for ClangFieldToken nodes.
     */
    private void walkClangTokens(
            ClangNode node,
            Structure targetStruct,
            int targetFieldOffset,
            String functionName,
            Address functionAddress,
            List<FieldReference> results) {

        if (node instanceof ClangFieldToken) {
            ClangFieldToken fieldToken = (ClangFieldToken) node;

            // Get the data type this field belongs to
            DataType parentType = fieldToken.getDataType();
            int fieldOffset = fieldToken.getOffset();

            // Check if this matches our target
            if (isMatchingStructType(parentType, targetStruct) &&
                fieldOffset == targetFieldOffset) {

                // Determine access type from context
                String accessType = determineAccessType(fieldToken);

                // Get the address where this access occurs
                Address minAddress = fieldToken.getMinAddress();

                // Get context (the field access text)
                String context = fieldToken.toString();

                results.add(new FieldReference(
                    minAddress,
                    functionName,
                    functionAddress,
                    accessType,
                    context,
                    "DECOMPILER"
                ));
            }
        }

        // Recursively process children
        int numChildren = node.numChildren();
        for (int i = 0; i < numChildren; i++) {
            walkClangTokens(node.Child(i), targetStruct, targetFieldOffset,
                functionName, functionAddress, results);
        }
    }

    /**
     * Check if a data type matches the target structure.
     */
    private boolean isMatchingStructType(DataType type, Structure targetStruct) {
        if (type == null) {
            return false;
        }

        // Unwrap TypeDef
        while (type instanceof TypeDef) {
            type = ((TypeDef) type).getBaseDataType();
        }

        // Check direct match
        if (type instanceof Structure) {
            Structure s = (Structure) type;
            return s.getName().equals(targetStruct.getName());
        }

        return false;
    }

    /**
     * Try to determine if a field access is a read or write.
     */
    private String determineAccessType(ClangFieldToken fieldToken) {
        ClangNode parent = fieldToken.Parent();

        if (parent != null) {
            String parentText = parent.toString();
            if (parentText.contains("=") && !parentText.contains("==")) {
                String fieldText = fieldToken.toString();
                int equalPos = parentText.indexOf('=');
                int fieldPos = parentText.indexOf(fieldText);
                if (fieldPos >= 0 && fieldPos < equalPos) {
                    return "WRITE";
                }
            }
        }

        return "READ";
    }

    /**
     * Find instance-based references using ReferenceManager.
     */
    private List<FieldReference> findInstanceBasedReferences(
            Program program,
            Address baseAddress,
            int fieldOffset,
            int fieldSize) {

        List<FieldReference> references = new ArrayList<>();

        // Calculate field address
        Address fieldAddress = baseAddress.add(fieldOffset);

        // Get references to the field address (and adjacent bytes for multi-byte fields)
        for (int byteOffset = 0; byteOffset < fieldSize; byteOffset++) {
            Address targetAddr = fieldAddress.add(byteOffset);
            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(targetAddr);

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                // Determine access type
                String accessType = classifyReferenceType(refType);

                // Get containing function
                Function containingFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcName = containingFunc != null ? containingFunc.getName() : "(unknown)";
                Address funcAddr = containingFunc != null ? containingFunc.getEntryPoint() : null;

                // Get instruction/data at reference
                String context = refType.toString() + " at " + fromAddr;

                // Avoid duplicate entries for multi-byte fields
                boolean isDuplicate = references.stream()
                    .anyMatch(r -> r.address.equals(fromAddr) && r.source.equals("ADDRESS"));

                if (!isDuplicate) {
                    references.add(new FieldReference(
                        fromAddr,
                        funcName,
                        funcAddr,
                        accessType,
                        context,
                        "ADDRESS"
                    ));
                }
            }
        }

        return references;
    }

    /**
     * Classify a reference type as READ, WRITE, or UNKNOWN.
     */
    private String classifyReferenceType(RefType refType) {
        if (refType.isRead()) {
            return "READ";
        } else if (refType.isWrite()) {
            return "WRITE";
        } else if (refType.isData()) {
            return "DATA";
        } else if (refType.isCall()) {
            return "CALL";
        }
        return "UNKNOWN";
    }
}

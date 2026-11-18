/*
 * Consolidated MCP tool for data type operations.
 * Replaces GetDataTypeTool, SetDataTypeTool, DeleteDataTypeTool, ListDataTypesTool.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

public class TypesTool implements McpTool {

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isIdempotent() { return true; }

    @Override
    public String getName() { return "types"; }

    @Override
    public String getDescription() {
        return "Data type operations: list, get, set, create_struct, create_enum, create_typedef, or delete";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Operation to perform",
                    "enum", List.of("list", "get", "set", "create_struct", "create_enum", "create_typedef", "delete")
                )),
                Map.entry("name", Map.of("type", "string", "description", "Type name (for get/create/delete)")),
                Map.entry("category", Map.of("type", "string", "description", "Category path (optional)")),
                Map.entry("filter", Map.of("type", "string", "description", "Name filter (for list)")),
                Map.entry("offset", Map.of("type", "integer", "description", "Pagination offset (for list)")),
                Map.entry("limit", Map.of("type", "integer", "description", "Pagination limit (for list, default 100)")),
                Map.entry("address", Map.of("type", "string", "description", "Address (for set action)")),
                Map.entry("data_type", Map.of("type", "string", "description", "Data type name (for set action). Supports array suffix syntax like 'int[16]'.")),
                Map.entry("array_count", Map.of("type", "integer", "description", "For set action: wraps data_type in an array of this many elements")),
                Map.entry("size", Map.of("type", "integer", "description", "Size in bytes (for create_struct/create_enum)")),
                Map.entry("packed", Map.of("type", "boolean", "description", "Enable packing (for create_struct)")),
                Map.entry("values", Map.of("type", "object", "description", "Enum values as name:value pairs (for create_enum)")),
                Map.entry("base_type", Map.of("type", "string", "description", "Base type name (for create_typedef)"))
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) return result("No program currently loaded");
        String action = (String) arguments.get("action");
        if (action == null) return result("action is required");

        switch (action.toLowerCase()) {
            case "list": return executeList(arguments, currentProgram);
            case "get": return executeGet(arguments, currentProgram);
            case "set": return executeSet(arguments, currentProgram);
            case "create_struct": return executeCreateStruct(arguments, currentProgram);
            case "create_enum": return executeCreateEnum(arguments, currentProgram);
            case "create_typedef": return executeCreateTypedef(arguments, currentProgram);
            case "delete": return executeDelete(arguments, currentProgram);
            default: return result("Invalid action: " + action);
        }
    }

    private McpSchema.CallToolResult executeList(Map<String, Object> arguments, Program program) {
        String filter = (String) arguments.get("filter");
        String category = (String) arguments.get("category");
        int offset = arguments.get("offset") instanceof Number ? ((Number) arguments.get("offset")).intValue() : 0;
        int limit = arguments.get("limit") instanceof Number ? ((Number) arguments.get("limit")).intValue() : 100;

        DataTypeManager dtm = program.getDataTypeManager();
        List<DataType> dataTypes = new ArrayList<>();
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (filter != null && !dt.getName().toLowerCase().contains(filter.toLowerCase())) continue;
            if (category != null && !dt.getCategoryPath().getPath().toLowerCase().contains(category.toLowerCase())) continue;
            dataTypes.add(dt);
        }

        Collections.sort(dataTypes, (a, b) -> {
            int c = a.getCategoryPath().getPath().compareTo(b.getCategoryPath().getPath());
            return c != 0 ? c : a.getName().compareTo(b.getName());
        });

        StringBuilder sb = new StringBuilder("Data Types");
        if (filter != null || category != null) {
            sb.append(" (filtered)");
        }
        sb.append(":\n\n");

        int count = 0;
        for (int i = offset; i < dataTypes.size() && count < limit; i++) {
            DataType dt = dataTypes.get(i);
            sb.append("- ").append(dt.getName()).append(" [").append(dt.getCategoryPath().getPath()).append("]");
            int size = dt.getLength();
            if (size > 0) sb.append(" (").append(size).append(" bytes)");
            sb.append("\n");
            count++;
        }
        sb.append("\nShowing ").append(count).append(" of ").append(dataTypes.size());
        return result(sb.toString());
    }

    private McpSchema.CallToolResult executeGet(Map<String, Object> arguments, Program program) {
        String name = (String) arguments.get("name");
        if (name == null) return result("name is required for get");
        String category = (String) arguments.get("category");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = null;
        if (category != null) dt = dtm.getDataType(new CategoryPath(category), name);
        if (dt == null) dt = dtm.getDataType(name);
        if (dt == null) {
            Iterator<DataType> iter = dtm.getAllDataTypes();
            while (iter.hasNext()) {
                DataType d = iter.next();
                if (d.getName().equals(name)) { dt = d; break; }
            }
        }
        if (dt == null) return result("Data type not found: " + name);

        StringBuilder sb = new StringBuilder();
        sb.append("Data Type: ").append(dt.getName()).append("\n");
        sb.append("Category: ").append(dt.getCategoryPath().getPath()).append("\n");
        int size = dt.getLength();
        if (size > 0) sb.append("Size: ").append(size).append(" bytes\n");
        sb.append("\n");

        if (dt instanceof Structure) {
            Structure struct = (Structure) dt;
            sb.append("Type: Structure\n\nFields:\n");
            for (DataTypeComponent comp : struct.getComponents()) {
                String dtName = comp.getDataType().getName();
                if (dtName.equalsIgnoreCase("undefined")) continue;
                sb.append(String.format("  +0x%04x [%3d] %-20s %s\n",
                    comp.getOffset(), comp.getLength(), dtName,
                    comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)"));
            }
        } else if (dt instanceof Enum) {
            Enum enumType = (Enum) dt;
            sb.append("Type: Enum\n\nValues:\n");
            for (String n : enumType.getNames()) {
                sb.append(String.format("  %-30s = 0x%x\n", n, enumType.getValue(n)));
            }
        } else if (dt instanceof TypeDef) {
            sb.append("Type: Typedef\nUnderlying: ").append(((TypeDef) dt).getDataType().getName()).append("\n");
        } else if (dt instanceof Union) {
            Union u = (Union) dt;
            sb.append("Type: Union\n\nFields:\n");
            for (DataTypeComponent comp : u.getComponents()) {
                sb.append(String.format("  [%3d] %-20s %s\n", comp.getLength(),
                    comp.getDataType().getName(),
                    comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)"));
            }
        } else {
            sb.append("Type Kind: ").append(dt.getClass().getSimpleName()).append("\n");
        }

        return result(sb.toString());
    }

    private McpSchema.CallToolResult executeSet(Map<String, Object> arguments, Program program) {
        String addressStr = (String) arguments.get("address");
        String dataTypeName = (String) arguments.get("data_type");
        if (addressStr == null || dataTypeName == null) return result("address and data_type required for set");

        Address address;
        try { address = program.getAddressFactory().getAddress(addressStr); }
        catch (Exception e) { return result("Invalid address: " + addressStr); }

        DataTypeResolver.Result resolvedType =
            DataTypeResolver.resolve(program.getDataTypeManager(), dataTypeName, arguments.get("array_count"));
        if (resolvedType.isError()) return result(resolvedType.errorMessage);
        DataType dataType = resolvedType.dataType;

        int txId = program.startTransaction("Set Data Type");
        try {
            if (dataType.getLength() > 0) {
                program.getListing().clearCodeUnits(address, address.add(dataType.getLength() - 1), false);
            } else {
                program.getListing().clearCodeUnits(address, address, false);
            }
            program.getListing().createData(address, dataType);
            program.endTransaction(txId, true);
            return result("Set data type at " + addressStr + " to " + dataType.getName());
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return result("Error: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult executeCreateStruct(Map<String, Object> arguments, Program program) {
        String name = (String) arguments.get("name");
        if (name == null) return result("name is required for create_struct");
        int size = arguments.get("size") instanceof Number ? ((Number) arguments.get("size")).intValue() : 0;
        boolean packed = Boolean.TRUE.equals(arguments.get("packed"));
        String category = (String) arguments.get("category");
        CategoryPath catPath = category != null ? new CategoryPath(category) : CategoryPath.ROOT;

        int txId = program.startTransaction("Create Structure");
        try {
            StructureDataType struct = new StructureDataType(catPath, name, size);
            if (packed) struct.setPackingEnabled(true);
            DataType resolved = program.getDataTypeManager().addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
            program.endTransaction(txId, true);
            return result("Created structure '" + resolved.getName() + "' (" + resolved.getLength() + " bytes)");
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return result("Error: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private McpSchema.CallToolResult executeCreateEnum(Map<String, Object> arguments, Program program) {
        String name = (String) arguments.get("name");
        if (name == null) return result("name is required for create_enum");
        int size = arguments.get("size") instanceof Number ? ((Number) arguments.get("size")).intValue() : 4;
        Object valuesObj = arguments.get("values");
        if (!(valuesObj instanceof Map)) return result("values (object of name:value pairs) required for create_enum");
        Map<String, Object> values = (Map<String, Object>) valuesObj;
        String category = (String) arguments.get("category");
        CategoryPath catPath = category != null ? new CategoryPath(category) : CategoryPath.ROOT;

        int txId = program.startTransaction("Create Enum");
        try {
            EnumDataType enumDt = new EnumDataType(catPath, name, size);
            for (Map.Entry<String, Object> entry : values.entrySet()) {
                long val = entry.getValue() instanceof Number ? ((Number) entry.getValue()).longValue() : 0;
                enumDt.add(entry.getKey(), val);
            }
            DataType resolved = program.getDataTypeManager().addDataType(enumDt, DataTypeConflictHandler.REPLACE_HANDLER);
            program.endTransaction(txId, true);
            return result("Created enum '" + resolved.getName() + "' with " + values.size() + " values");
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return result("Error: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult executeCreateTypedef(Map<String, Object> arguments, Program program) {
        String name = (String) arguments.get("name");
        String baseTypeName = (String) arguments.get("base_type");
        if (name == null || baseTypeName == null) return result("name and base_type required for create_typedef");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType baseType = dtm.getDataType("/" + baseTypeName);
        if (baseType == null) baseType = dtm.getDataType(baseTypeName);
        if (baseType == null) return result("Base type not found: " + baseTypeName);

        int txId = program.startTransaction("Create Typedef");
        try {
            TypedefDataType td = new TypedefDataType(name, baseType);
            DataType resolved = dtm.addDataType(td, DataTypeConflictHandler.REPLACE_HANDLER);
            program.endTransaction(txId, true);
            return result("Created typedef '" + resolved.getName() + "' -> " + baseType.getName());
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return result("Error: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult executeDelete(Map<String, Object> arguments, Program program) {
        String name = (String) arguments.get("name");
        if (name == null) return result("name is required for delete");
        String category = (String) arguments.get("category");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = null;
        if (category != null) dt = dtm.getDataType(new CategoryPath(category), name);
        if (dt == null && name.startsWith("/")) dt = dtm.getDataType(name);
        if (dt == null) {
            Iterator<DataType> iter = dtm.getAllDataTypes();
            while (iter.hasNext()) {
                DataType d = iter.next();
                if (name.equals(d.getName())) { dt = d; break; }
            }
        }
        if (dt == null) return result("Data type not found: " + name);

        if (dt.getDataTypeManager() != dtm) {
            return result("Cannot delete: type is not owned by this program's DataTypeManager");
        }

        int txId = program.startTransaction("Delete Data Type");
        try {
            boolean removed = dtm.remove(dt);
            program.endTransaction(txId, removed);
            return result(removed ? "Deleted data type: " + name : "Failed to delete: " + name);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return result("Error: " + e.getMessage());
        }
    }

    private static McpSchema.CallToolResult result(String text) {
        return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder(text).build()).build();
    }
}

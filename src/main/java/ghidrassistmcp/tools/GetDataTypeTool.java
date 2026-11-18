/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that retrieves detailed information about a specific data type,
 * including structure definitions with field layouts.
 */
public class GetDataTypeTool implements McpTool {

    @Override
    public String getName() {
        return "get_data_type";
    }

    @Override
    public String getDescription() {
        return "Get detailed information about a specific data type, including structure/union field layouts, " +
               "enum values, typedef definitions, and type properties. " +
               "Examples: " +
               "1) Get a structure: {\"name\": \"mystruct\"} " +
               "2) Get built-in type: {\"name\": \"int\"} " +
               "3) Get with category: {\"name\": \"IMAGE_DOS_HEADER\", \"category\": \"/winnt.h\"}";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "name", new JsonSchema("string", null, null, null, null, null),
                "category", new JsonSchema("string", null, null, null, null, null)
            ),
            List.of("name"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }

        String name = (String) arguments.get("name");
        if (name == null || name.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("name parameter is required").build())
                .build();
        }

        String category = (String) arguments.get("category");

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType dataType = null;

        // If category is specified, try to find exact match
        if (category != null && !category.trim().isEmpty()) {
            CategoryPath categoryPath = new CategoryPath(category);
            dataType = dtm.getDataType(categoryPath, name);
        }

        // If not found or no category specified, search all data types
        if (dataType == null) {
            dataType = dtm.getDataType(name);
        }

        // If still not found, try searching by name
        if (dataType == null) {
            java.util.Iterator<DataType> iter = dtm.getAllDataTypes();
            while (iter.hasNext()) {
                DataType dt = iter.next();
                if (dt.getName().equals(name)) {
                    dataType = dt;
                    break;
                }
            }
        }

        if (dataType == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Data type not found: " + name +
                    (category != null ? " in category: " + category : "")).build())
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Data Type: ").append(dataType.getName()).append("\n");
        result.append("Category: ").append(dataType.getCategoryPath().getPath()).append("\n");

        int size = dataType.getLength();
        if (size > 0) {
            result.append("Size: ").append(size).append(" bytes\n");
        } else if (size == -1) {
            result.append("Size: Variable\n");
        }

        String description = dataType.getDescription();
        if (description != null && !description.isEmpty()) {
            result.append("Description: ").append(description).append("\n");
        }

        result.append("\n");

        // Handle different data type kinds
        if (dataType instanceof Structure) {
            formatStructure((Structure) dataType, result);
        } else if (dataType instanceof Union) {
            formatUnion((Union) dataType, result);
        } else if (dataType instanceof Enum) {
            formatEnum((Enum) dataType, result);
        } else if (dataType instanceof TypeDef) {
            formatTypeDef((TypeDef) dataType, result);
        } else if (dataType instanceof Pointer) {
            formatPointer((Pointer) dataType, result);
        } else if (dataType instanceof Array) {
            formatArray((Array) dataType, result);
        } else if (dataType instanceof FunctionDefinition) {
            formatFunctionDefinition((FunctionDefinition) dataType, result);
        } else {
            result.append("Type Kind: ").append(dataType.getClass().getSimpleName()).append("\n");
            result.append("Display Name: ").append(dataType.getDisplayName()).append("\n");
        }

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }

    private void formatStructure(Structure struct, StringBuilder result) {
        result.append("Type: Structure");
        if (struct.isPackingEnabled()) {
            result.append(" (packed)");
        }
        result.append("\n\n");

        DataTypeComponent[] components = struct.getComponents();
        if (components.length == 0) {
            result.append("(Empty structure)\n");
            return;
        }

        result.append("Fields:\n");
        
        // Track consecutive undefined bytes for consolidation
        Integer undefinedStartOffset = null;
        int undefinedByteCount = 0;
        
        for (DataTypeComponent comp : components) {
            String dataTypeName = comp.getDataType().getName();
            boolean isUndefined = dataTypeName.equalsIgnoreCase("undefined");
            
            if (isUndefined) {
                // Accumulate undefined bytes
                if (undefinedStartOffset == null) {
                    undefinedStartOffset = comp.getOffset();
                }
                undefinedByteCount += comp.getLength();
            } else {
                // Flush any accumulated undefined bytes before processing this component
                if (undefinedStartOffset != null) {
                    result.append(String.format("  -- %d undefined bytes at 0x%04x --\n",
                        undefinedByteCount, undefinedStartOffset));
                    undefinedStartOffset = null;
                    undefinedByteCount = 0;
                }
                
                // Output the non-undefined component
                result.append(String.format("  +0x%04x [%3d] %-20s %s",
                    comp.getOffset(),
                    comp.getLength(),
                    dataTypeName,
                    comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)"));

                if (comp instanceof BitFieldDataType) {
                    BitFieldDataType bf = (BitFieldDataType) comp;
                    result.append(" : ").append(bf.getBitSize());
                }

                String comment = comp.getComment();
                if (comment != null && !comment.isEmpty()) {
                    result.append("  // ").append(comment);
                }

                result.append("\n");
            }
        }
        
        // Flush any remaining undefined bytes at the end
        if (undefinedStartOffset != null) {
            result.append(String.format("  -- %d undefined bytes at 0x%04x --\n",
                undefinedByteCount, undefinedStartOffset));
        }
    }

    private void formatUnion(Union union, StringBuilder result) {
        result.append("Type: Union\n\n");

        DataTypeComponent[] components = union.getComponents();
        if (components.length == 0) {
            result.append("(Empty union)\n");
            return;
        }

        result.append("Fields:\n");
        for (DataTypeComponent comp : components) {
            result.append(String.format("  [%3d] %-20s %s",
                comp.getLength(),
                comp.getDataType().getName(),
                comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)"));

            String comment = comp.getComment();
            if (comment != null && !comment.isEmpty()) {
                result.append("  // ").append(comment);
            }

            result.append("\n");
        }
    }

    private void formatEnum(Enum enumType, StringBuilder result) {
        result.append("Type: Enum\n\n");

        String[] names = enumType.getNames();
        if (names.length == 0) {
            result.append("(Empty enum)\n");
            return;
        }

        result.append("Values:\n");
        for (String name : names) {
            long value = enumType.getValue(name);
            result.append(String.format("  %-30s = 0x%x (%d)\n", name, value, value));
        }
    }

    private void formatTypeDef(TypeDef typeDef, StringBuilder result) {
        result.append("Type: Typedef\n");
        result.append("Underlying Type: ").append(typeDef.getDataType().getName()).append("\n");
        result.append("Underlying Category: ").append(typeDef.getDataType().getCategoryPath().getPath()).append("\n");
    }

    private void formatPointer(Pointer pointer, StringBuilder result) {
        result.append("Type: Pointer\n");
        result.append("Points To: ").append(pointer.getDataType().getName()).append("\n");
        result.append("Pointer Size: ").append(pointer.getLength()).append(" bytes\n");
    }

    private void formatArray(Array array, StringBuilder result) {
        result.append("Type: Array\n");
        result.append("Element Type: ").append(array.getDataType().getName()).append("\n");
        result.append("Element Count: ").append(array.getNumElements()).append("\n");
        result.append("Element Size: ").append(array.getElementLength()).append(" bytes\n");
    }

    private void formatFunctionDefinition(FunctionDefinition funcDef, StringBuilder result) {
        result.append("Type: Function Definition\n\n");
        result.append("Signature: ").append(funcDef.getPrototypeString()).append("\n");
    }
}

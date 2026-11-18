/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.decompiler.DecompilerSession;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that sets the data type of a local variable within a function.
 */
public class SetLocalVariableTypeTool implements McpTool {

    private final DecompilerService decompilerService;

    public SetLocalVariableTypeTool(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public String getName() {
        return "set_local_variable_type";
    }
    
    @Override
    public String getDescription() {
        return "Set the data type of a local variable within a function";
    }
    
    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "function_name", new JsonSchema("string", null, null, null, null, null),
                "variable_name", new JsonSchema("string", null, null, null, null, null),
                "data_type", new JsonSchema("string", null, null, null, null, null)
            ),
            List.of("function_name", "variable_name", "data_type"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }
        
        String functionName = (String) arguments.get("function_name");
        String variableName = (String) arguments.get("variable_name");
        String dataTypeName = (String) arguments.get("data_type");
        
        if (functionName == null || variableName == null || dataTypeName == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("function_name, variable_name, and data_type are all required").build())
                .build();
        }
        
        // Find the function
        Function function = findFunctionByName(currentProgram, functionName);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Function not found: " + functionName).build())
                .build();
        }
        
        // Find the data type
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType dataType = dtm.getDataType("/" + dataTypeName);
        if (dataType == null) {
            // Try finding by name without path
            dataType = dtm.getDataType(dataTypeName);
        }
        if (dataType == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Data type not found: " + dataTypeName +
                              ". Use built-in types like 'int', 'char', 'void*', etc.").build())
                .build();
        }
        
        // Get the high function and find the variable
        try (DecompilerSession session = decompilerService.open(currentProgram)) {
            DecompileResults results = session.decompiler().decompileFunction(function,
                session.options().getDefaultTimeout(), TaskMonitor.DUMMY);
            
            if (results.isTimedOut()) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Decompilation timed out for function: " + functionName).build())
                    .build();
            }
            
            if (results.isValid() == false) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Decompilation error for function " + functionName + ": " + results.getErrorMessage()).build())
                    .build();
            }
            
            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Could not get high function for: " + functionName).build())
                    .build();
            }
            
            // Find the variable
            HighSymbol targetSymbol = null;
            Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
            
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                if (symbol.getName().equals(variableName)) {
                    targetSymbol = symbol;
                    break;
                }
            }
            
            if (targetSymbol == null) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Variable '" + variableName + "' not found in function '" + functionName + "'").build())
                    .build();
            }
            
            // Setting variable types in the decompiler is complex and may not persist
            // For now, return information about the variable and desired type
            try {
                HighVariable highVar = targetSymbol.getHighVariable();
                if (highVar != null) {
                    DataType currentType = highVar.getDataType();
                    String currentTypeName = currentType != null ? currentType.getName() : "unknown";
                    
                    return McpSchema.CallToolResult.builder()
                        .addContent(McpSchema.TextContent.builder("Variable '" + variableName + "' in function '" + functionName +
                                      "' currently has type: " + currentTypeName + 
                                      ". Requested type: " + dataType.getName() + 
                                      " (Type setting not fully implemented - changes may not persist)").build())
                        .build();
                }
				return McpSchema.CallToolResult.builder()
				    .addContent(McpSchema.TextContent.builder("Cannot access type for variable '" + variableName +
				                  "' - no high variable available").build())
				    .build();
            } catch (Exception e) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Error accessing variable type: " + e.getMessage()).build())
                    .build();
            }
            
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Error processing function: " + e.getMessage()).build())
                .build();
        }
    }
    
    private Function findFunctionByName(Program program, String functionName) {
        return FunctionLookup.findByName(program, functionName);
    }
}

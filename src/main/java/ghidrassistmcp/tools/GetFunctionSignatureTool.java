package ghidrassistmcp.tools;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;

import java.util.List;
import java.util.Map;
import ghidrassistmcp.protocol.JsonSchema;

public class GetFunctionSignatureTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_function_signature";
    }

    @Override
    public String getDescription() {
        return "Get the native GhidrAssist byte signature for a function";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema(
            "object",
            Map.of(
                "function_name_or_address",
                Map.of("type", "string", "description", "Function name, qualified name, or address")
            ),
            List.of("function_name_or_address"),
            null,
            null,
            null
        );
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }

        String identifier = (String) arguments.get("function_name_or_address");
        if (identifier == null || identifier.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("function_name_or_address is required").build())
                .build();
        }

        Function function = findFunction(currentProgram, identifier);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Function not found: " + identifier).build())
                .build();
        }

        NativeFunctionSignatureGenerator generator =
            new NativeFunctionSignatureGenerator(currentProgram, TaskMonitor.DUMMY);

        JsonObject result = new JsonObject();
        result.addProperty("name", function.getName(true));
        result.addProperty("address", function.getEntryPoint().toString());
        String signature = generator.generate(function);
        if (signature == null) {
            result.add("signature", JsonNull.INSTANCE);
        } else {
            result.addProperty("signature", signature);
        }

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }

    private Function findFunction(Program program, String identifier) {
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func != null) {
                    return func;
                }

                func = program.getFunctionManager().getFunctionContaining(addr);
                if (func != null) {
                    return func;
                }
            }
        } catch (Exception e) {
            // Not an address, continue to name lookup.
        }

        return FunctionLookup.findByQualifiedName(program, identifier);
    }
}

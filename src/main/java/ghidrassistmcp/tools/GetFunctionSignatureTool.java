package ghidrassistmcp.tools;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.List;
import java.util.Map;

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
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema(
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
                .addTextContent("No program currently loaded")
                .build();
        }

        String identifier = (String) arguments.get("function_name_or_address");
        if (identifier == null || identifier.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("function_name_or_address is required")
                .build();
        }

        Function function = findFunction(currentProgram, identifier);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + identifier)
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
            .addTextContent(result.toString())
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

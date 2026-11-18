/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that sets a function's prototype/signature.
 */
public class SetFunctionPrototypeTool implements McpTool {

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
        return "set_function_prototype";
    }
    
    @Override
    public String getDescription() {
        return "Set a function's prototype/signature";
    }
    
    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "function_address", new JsonSchema("string", null, null, null, null, null),
                "prototype", new JsonSchema("string", null, null, null, null, null)
            ),
            List.of("function_address", "prototype"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        // Fallback for when backend reference is not available
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }

        String functionAddrStr = (String) arguments.get("function_address");
        String prototype = (String) arguments.get("prototype");

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("function_address parameter is required").build())
                .build();
        }

        if (prototype == null || prototype.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("prototype parameter is required").build())
                .build();
        }

        // Use proper prototype setting with transaction handling
        PrototypeResult result = setFunctionPrototype(currentProgram, functionAddrStr, prototype);

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.success ?
                "Successfully set function prototype: " + prototype :
                "Failed to set function prototype: " + result.errorMessage).build())
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        // This tool doesn't need UI context, so just delegate to the base implementation
        return execute(arguments, currentProgram);
    }
    
    /**
     * Result class for prototype operations
     */
    private static class PrototypeResult {
        final boolean success;
        final String errorMessage;
        
        PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }
    }
    
    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(Program program, String functionAddrStr, String prototype) {
        // Input validation
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (Exception e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            if (addr == null) {
                String msg = "Invalid address format: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }
            
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use proper function signature parsing and application
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }
    
    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Create function signature parser
            // Note: Since we don't have access to the tool here, we'll create parser without DataTypeManagerService
            FunctionSignatureParser parser = new FunctionSignatureParser(dtm, null);

            // Parse the prototype into a function signature
            FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype: " + prototype;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }
    
    /**
     * Add prototype as a comment for reference
     */
    private void addPrototypeComment(Program program, Function function, String prototype) {
        int transactionId = program.startTransaction("Add prototype comment");
        boolean committed = false;
        try {
            String currentComment = function.getComment();
            String newComment = "Applied prototype: " + prototype;
            if (currentComment != null && !currentComment.isEmpty()) {
                newComment = currentComment + "\n" + newComment;
            }
            function.setComment(newComment);
            committed = true;
        } catch (Exception e) {
            Msg.warn(this, "Could not add prototype comment: " + e.getMessage());
        } finally {
            program.endTransaction(transactionId, committed);
        }
    }
    
}
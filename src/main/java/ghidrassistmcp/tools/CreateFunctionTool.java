/*
 * MCP tool to create (define) a function at a given address in the current program.
 * Optionally accepts a name for the new function.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;
public class CreateFunctionTool implements McpTool {

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isIdempotent() { return true; }

    @Override
    public String getName() { return "create_function"; }

    @Override
    public String getDescription() {
        return "Create (define) a function at a specific address. "
             + "Ghidra will auto-detect the function body via flow analysis. "
             + "Optionally clear existing code/data units first and provide a name for the function.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("address", Map.of("type", "string",
                    "description", "Entry point address for the function (e.g. '0xC121' or 'C121')")),
                Map.entry("name", Map.of("type", "string",
                    "description", "Optional name for the function (default: auto-generated FUN_xxxx)")),
                Map.entry("clear_existing", Map.of(
                    "type", "boolean",
                    "description", "Clear existing instructions/data before creating the function. Default: false.",
                    "default", false)),
                Map.entry("clear_length", Map.of(
                    "type", "integer",
                    "description", "When clear_existing=true, bytes to clear from the entry address. " +
                        "If omitted, clears only the code/data unit containing the entry.",
                    "minimum", 1))
            ),
            List.of("address"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded").build();
        }

        String addressStr = (String) arguments.get("address");
        String name = (String) arguments.get("name");
        boolean clearExisting = Boolean.TRUE.equals(arguments.get("clear_existing"));
        int clearLength = numberArg(arguments.get("clear_length"), 0);

        Address entryPoint;
        try {
            entryPoint = currentProgram.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address: " + addressStr).build();
        }

        if (entryPoint == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Could not parse address: " + addressStr).build();
        }

        // Check if a function already exists at this address
        Function existing = currentProgram.getFunctionManager().getFunctionAt(entryPoint);
        if (existing != null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function already exists at " + addressStr + ": "
                    + existing.getName() + " (" + existing.getBody().getNumAddresses() + " bytes)")
                .build();
        }

        ClearResult clearResult = ClearResult.none();
        if (clearExisting) {
            try {
                clearResult = clearExistingCodeUnits(currentProgram, entryPoint, clearLength);
            } catch (Exception e) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to clear existing code/data units at " + addressStr +
                        ": " + e.getMessage())
                    .build();
            }
        }

        // Use CreateFunctionCmd which performs flow-based body detection
        CreateFunctionCmd cmd = new CreateFunctionCmd(entryPoint);
        boolean success = cmd.applyTo(currentProgram);

        if (!success) {
            // Fallback: try to disassemble first, then create function
            int txId = currentProgram.startTransaction("Disassemble for function creation");
            boolean txClosed = false;
            try {
                AddressSet disassembleRange =
                    clearResult.endAddress() != null ? new AddressSet(entryPoint, clearResult.endAddress()) : null;
                DisassembleCommand disCmd = new DisassembleCommand(entryPoint, disassembleRange, true);
                boolean disassembled = disCmd.applyTo(currentProgram);
                currentProgram.endTransaction(txId, disassembled);
                txClosed = true;

                if (!disassembled) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Failed to disassemble at " + addressStr +
                            ". Try clear_existing=true with an explicit clear_length if the region is data.")
                        .build();
                }

                // Retry function creation after disassembly
                cmd = new CreateFunctionCmd(entryPoint);
                success = cmd.applyTo(currentProgram);
            } catch (Exception e) {
                if (!txClosed) {
                    currentProgram.endTransaction(txId, false);
                }
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to disassemble at " + addressStr + ": " + e.getMessage())
                    .build();
            }
        }

        if (!success) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to create function at " + addressStr
                    + ". The address may not contain valid code or may overlap an existing function.")
                .build();
        }

        // Get the created function
        Function func = currentProgram.getFunctionManager().getFunctionAt(entryPoint);
        if (func == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function creation reported success but function not found at " + addressStr)
                .build();
        }

        // Rename if a name was provided
        if (name != null && !name.isEmpty()) {
            int txId = currentProgram.startTransaction("Rename function");
            try {
                func.setName(name, SourceType.USER_DEFINED);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Function created at " + addressStr
                        + " but rename failed: " + e.getMessage())
                    .build();
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Function created successfully:\n");
        sb.append("  Name: ").append(func.getName(true)).append("\n");
        sb.append("  Entry: ").append(func.getEntryPoint()).append("\n");
        sb.append("  Body size: ").append(func.getBody().getNumAddresses()).append(" bytes\n");
        sb.append("  Range: ").append(func.getBody().getMinAddress())
          .append(" - ").append(func.getBody().getMaxAddress()).append("\n");
        sb.append("  Cleared existing code/data units: ").append(clearResult.description());

        return McpSchema.CallToolResult.builder()
            .addTextContent(sb.toString()).build();
    }

    @Override
    public boolean isDestructive() { return true; }

    private ClearResult clearExistingCodeUnits(Program program, Address entryPoint, int clearLength)
            throws Exception {
        Listing listing = program.getListing();
        Address clearStart = entryPoint;
        Address clearEnd;

        if (clearLength > 0) {
            clearEnd = entryPoint.add(clearLength - 1);
        } else {
            CodeUnit codeUnit = listing.getCodeUnitContaining(entryPoint);
            if (codeUnit != null) {
                clearStart = codeUnit.getMinAddress();
                clearEnd = codeUnit.getMaxAddress();
            } else {
                clearEnd = entryPoint;
            }
        }

        int txId = program.startTransaction("Clear existing code/data before function creation");
        boolean committed = false;
        try {
            listing.clearCodeUnits(clearStart, clearEnd, false);
            committed = true;
        } finally {
            program.endTransaction(txId, committed);
        }

        String description = clearStart + " - " + clearEnd;
        return new ClearResult(clearEnd, description);
    }

    private int numberArg(Object value, int defaultValue) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        return defaultValue;
    }

    private record ClearResult(Address endAddress, String description) {
        static ClearResult none() {
            return new ClearResult(null, "false");
        }
    }
}

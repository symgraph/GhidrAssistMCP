/*
 * MCP tool to create (define) a function at a given address in the current program.
 * Optionally accepts a name for the new function.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.cmd.Command;
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
    private final CreateCommandFactory createCommandFactory;
    private final DisassembleCommandFactory disassembleCommandFactory;

    public CreateFunctionTool() {
        this(CreateFunctionCmd::new,
            (entry, range) -> new DisassembleCommand(entry, range, true));
    }

    CreateFunctionTool(CreateCommandFactory createCommandFactory,
            DisassembleCommandFactory disassembleCommandFactory) {
        this.createCommandFactory = createCommandFactory;
        this.disassembleCommandFactory = disassembleCommandFactory;
    }

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
            return error("No program currently loaded");
        }

        String addressStr = (String) arguments.get("address");
        String name = (String) arguments.get("name");
        boolean clearExisting = Boolean.TRUE.equals(arguments.get("clear_existing"));
        int clearLength = numberArg(arguments.get("clear_length"), 0);

        Address entryPoint;
        try {
            entryPoint = currentProgram.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return error("Invalid address: " + addressStr);
        }

        if (entryPoint == null) {
            return error("Could not parse address: " + addressStr);
        }

        // Check if a function already exists at this address
        Function existing = currentProgram.getFunctionManager().getFunctionAt(entryPoint);
        if (existing != null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function already exists at " + addressStr + ": "
                    + existing.getName() + " (" + existing.getBody().getNumAddresses() + " bytes)")
                .build();
        }

        AttemptResult attempt = null;
        if (!clearExisting) {
            attempt = createAttempt(currentProgram, entryPoint, name, false, 0, false);
            if (!attempt.success() && !attempt.retryable()) {
                return error("Failed to create function at " + addressStr + ": " + attempt.detail());
            }
        }

        if (attempt == null || !attempt.success()) {
            String initialFailure = attempt == null ? null : attempt.detail();
            attempt = createAttempt(currentProgram, entryPoint, name, clearExisting, clearLength, true);
            if (!attempt.success()) {
                String detail = initialFailure == null ? attempt.detail()
                    : "initial attempt: " + initialFailure + "; retry: " + attempt.detail();
                return error("Failed to create function at " + addressStr + ": " + detail);
            }
        }

        Function func = attempt.function();
        ClearResult clearResult = attempt.clearResult();

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

    private AttemptResult createAttempt(Program program, Address entryPoint, String name,
            boolean clearExisting, int clearLength, boolean disassemble) {
        int txId = program.startTransaction("Create function");
        boolean committed = false;
        String stage = "function creation";
        try {
            ClearResult clearResult = ClearResult.none();
            if (clearExisting) {
                stage = "clearing existing code/data units";
                clearResult = clearExistingCodeUnits(program, entryPoint, clearLength);
            }
            if (disassemble) {
                stage = "disassembly";
                AddressSet range = clearResult.endAddress() == null ? null
                    : new AddressSet(entryPoint, clearResult.endAddress());
                Command<Program> command = disassembleCommandFactory.create(entryPoint, range);
                if (!command.applyTo(program)) {
                    return AttemptResult.failure("disassembly failed: " + commandStatus(command), false);
                }
            }

            stage = "function creation";
            Command<Program> command = createCommandFactory.create(entryPoint);
            if (!command.applyTo(program)) {
                return AttemptResult.failure("function creation failed: " + commandStatus(command), true);
            }

            Function function = program.getFunctionManager().getFunctionAt(entryPoint);
            if (function == null) {
                return AttemptResult.failure("creation reported success but no function exists at the entry", false);
            }
            if (name != null && !name.isEmpty()) {
                stage = "rename";
                function.setName(name, SourceType.USER_DEFINED);
            }
            committed = true;
            return new AttemptResult(function, clearResult, null, false);
        } catch (Exception e) {
            return AttemptResult.failure(stage + " failed: " + exceptionMessage(e), false);
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    private static String commandStatus(Command<Program> command) {
        String status = command.getStatusMsg();
        return status == null || status.isBlank() ? "Ghidra returned no status message" : status;
    }

    private static String exceptionMessage(Exception e) {
        return e.getMessage() == null ? e.toString() : e.getMessage();
    }

    private static McpSchema.CallToolResult error(String message) {
        return McpSchema.CallToolResult.builder().addTextContent(message).isError(true).build();
    }

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

        // The creation attempt owns the transaction, including clearing and disassembly.
        listing.clearCodeUnits(clearStart, clearEnd, false);

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

    private record AttemptResult(Function function, ClearResult clearResult, String detail,
            boolean retryable) {
        boolean success() { return function != null; }

        static AttemptResult failure(String detail, boolean retryable) {
            return new AttemptResult(null, ClearResult.none(), detail, retryable);
        }
    }

    @FunctionalInterface
    interface CreateCommandFactory {
        Command<Program> create(Address entry);
    }

    @FunctionalInterface
    interface DisassembleCommandFactory {
        Command<Program> create(Address entry, AddressSet range);
    }
}

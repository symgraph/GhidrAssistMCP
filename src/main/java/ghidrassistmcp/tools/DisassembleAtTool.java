/*
 * MCP tool to disassemble bytes at a given address, even if no function is defined there.
 * Useful for inspecting code regions that haven't been auto-analyzed.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;
public class DisassembleAtTool implements McpTool {

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isIdempotent() { return true; }

    @Override
    public String getName() { return "disassemble_at"; }

    @Override
    public String getDescription() {
        return "Disassemble code at a specific address, even if no function is defined. "
             + "Converts undefined bytes into instructions and returns the disassembly listing.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", Map.of("type", "string",
                    "description", "Start address to disassemble (e.g. '0xC121' or 'C121')"),
                "length", Map.of("type", "integer",
                    "description", "Maximum number of bytes to disassemble (default: 128)")
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
        int length = 128;
        Object lengthObj = arguments.get("length");
        if (lengthObj instanceof Number) {
            length = ((Number) lengthObj).intValue();
        }

        // Cap at a reasonable maximum
        if (length > 4096) length = 4096;
        if (length < 1) length = 128;

        Address startAddr;
        try {
            startAddr = currentProgram.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address: " + addressStr).build();
        }

        if (startAddr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Could not parse address: " + addressStr).build();
        }

        Address endAddr = startAddr.add(length - 1);
        AddressSet range = new AddressSet(startAddr, endAddr);

        // Disassemble the region (this is a write operation - converts bytes to instructions)
        int txId = currentProgram.startTransaction("Disassemble at " + addressStr);
        try {
            DisassembleCommand cmd = new DisassembleCommand(startAddr, range, true);
            cmd.applyTo(currentProgram);
            currentProgram.endTransaction(txId, true);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Disassembly failed at " + addressStr + ": " + e.getMessage())
                .build();
        }

        // Now read back the disassembled instructions
        Listing listing = currentProgram.getListing();
        StringBuilder sb = new StringBuilder();
        sb.append("Disassembly at ").append(startAddr).append(":\n\n");

        int instrCount = 0;
        InstructionIterator iter = listing.getInstructions(startAddr, true);
        while (iter.hasNext()) {
            Instruction instr = iter.next();
            if (instr.getAddress().compareTo(endAddr) > 0) break;

            sb.append(String.format("%s: %s\n", instr.getAddress(), instr.toString()));
            instrCount++;

            // Safety limit
            if (instrCount > 500) {
                sb.append("... (truncated at 500 instructions)\n");
                break;
            }
        }

        sb.append("\nTotal instructions: ").append(instrCount);

        return McpSchema.CallToolResult.builder()
            .addTextContent(sb.toString()).build();
    }
}

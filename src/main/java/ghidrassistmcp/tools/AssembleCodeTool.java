/*
 * MCP tool to assemble code at a specific address and optionally patch it.
 */
package ghidrassistmcp.tools;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Uses Ghidra's assembler to convert assembly text to bytes and optionally patch the program.
 */
public class AssembleCodeTool implements McpTool {

    @Override
    public String getName() {
        return "assemble_code";
    }

    @Override
    public String getDescription() {
        return "Assemble instruction text at an address and optionally patch it into program memory. " +
            "Example: {\"address\":\"0x401000\",\"code\":\"NOP\",\"patch\":true}";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return true;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", Map.of(
                    "type", "string",
                    "description", "Address where the assembly should be encoded (e.g. '0x401000' or '401000')"),
                "code", Map.of(
                    "type", "string",
                    "description", "Assembly instruction text. May be a single instruction or newline-separated block."),
                "patch", Map.of(
                    "type", "boolean",
                    "description", "If true, patch assembled bytes into the program. If false, only return bytes. Default: true"),
                "clear_code_units", Map.of(
                    "type", "boolean",
                    "description", "When patching, clear existing instructions/data across the assembled range first. Default: true")
            ),
            List.of("address", "code"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return textResult("No program currently loaded");
        }

        Object addressObj = arguments.get("address");
        Object codeObj = arguments.get("code");
        boolean patch = !Boolean.FALSE.equals(arguments.get("patch"));
        boolean clearCodeUnits = !Boolean.FALSE.equals(arguments.get("clear_code_units"));

        if (!(addressObj instanceof String) || ((String) addressObj).isBlank()) {
            return textResult("address is required");
        }
        if (!(codeObj instanceof String) || ((String) codeObj).isBlank()) {
            return textResult("code is required");
        }

        String addressStr = (String) addressObj;
        Address address = parseAddress(currentProgram, addressStr);
        if (address == null) {
            return textResult("Could not parse address: " + addressStr);
        }

        String[] lines = parseLines((String) codeObj);
        if (lines.length == 0) {
            return textResult("No assembly instructions provided");
        }

        Assembler assembler;
        try {
            assembler = Assemblers.getAssembler(currentProgram);
        } catch (Exception e) {
            return textResult("Failed creating assembler: " + e.getMessage());
        }

        AssembledBlock assembled;
        try {
            assembled = assembleBytes(assembler, address, lines);
        } catch (AssemblySyntaxException e) {
            return textResult("Assembly syntax error: " + e.getMessage());
        } catch (AssemblySemanticException e) {
            return textResult("Assembly semantic error: " + e.getMessage());
        } catch (AddressOverflowException e) {
            return textResult("Assembly range overflows address space: " + e.getMessage());
        }

        if (assembled.bytes.length == 0) {
            return textResult("Assembler produced no bytes");
        }

        Memory memory = currentProgram.getMemory();
        if (!memory.contains(address) || !memory.contains(assembled.endAddress)) {
            return textResult("Assembly range is outside mapped memory: " + address + " - " + assembled.endAddress);
        }

        if (!patch) {
            return textResult(buildResult("Assembled", address, assembled.endAddress, assembled.bytes, null, false, lines));
        }

        byte[] oldBytes = new byte[assembled.bytes.length];
        try {
            memory.getBytes(address, oldBytes);
        } catch (MemoryAccessException e) {
            return textResult("Failed reading original bytes: " + e.getMessage());
        }

        int txId = currentProgram.startTransaction("MCP Assemble Code at " + address);
        try {
            if (clearCodeUnits) {
                currentProgram.getListing().clearCodeUnits(address, assembled.endAddress, false);
            }

            assembler.assemble(address, lines);
            currentProgram.endTransaction(txId, true);
        } catch (AssemblySyntaxException e) {
            currentProgram.endTransaction(txId, false);
            return textResult("Assembly syntax error: " + e.getMessage());
        } catch (AssemblySemanticException e) {
            currentProgram.endTransaction(txId, false);
            return textResult("Assembly semantic error: " + e.getMessage());
        } catch (MemoryAccessException e) {
            currentProgram.endTransaction(txId, false);
            return textResult("Patch failed reading/writing memory: " + e.getMessage());
        } catch (AddressOverflowException e) {
            currentProgram.endTransaction(txId, false);
            return textResult("Assembly range overflows address space: " + e.getMessage());
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            return textResult("Patch failed: " + e.getMessage());
        }

        return textResult(buildResult("Assembled and patched", address, assembled.endAddress,
            assembled.bytes, oldBytes, clearCodeUnits, lines));
    }

    private static String[] parseLines(String code) {
        List<String> lines = new ArrayList<>();
        for (String line : code.split("\\R")) {
            String trimmed = line.strip();
            if (!trimmed.isEmpty()) {
                lines.add(trimmed);
            }
        }
        return lines.toArray(new String[0]);
    }

    private static AssembledBlock assembleBytes(Assembler assembler, Address address, String[] lines)
            throws AssemblySyntaxException, AssemblySemanticException, AddressOverflowException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Address nextAddress = address;

        for (String line : lines) {
            byte[] lineBytes = assembler.assembleLine(nextAddress, line);
            out.write(lineBytes, 0, lineBytes.length);
            if (lineBytes.length > 0) {
                nextAddress = nextAddress.addNoWrap(lineBytes.length);
            }
        }

        byte[] bytes = out.toByteArray();
        if (bytes.length == 0) {
            return new AssembledBlock(bytes, address);
        }
        Address endAddress = address.addNoWrap(bytes.length - 1L);
        return new AssembledBlock(bytes, endAddress);
    }

    private static String buildResult(String action, Address startAddress, Address endAddress,
            byte[] newBytes, byte[] oldBytes, boolean clearCodeUnits, String[] lines) {
        StringBuilder sb = new StringBuilder();
        sb.append(action).append(' ').append(lines.length).append(" instruction line(s) at ").append(startAddress).append("\n");
        sb.append("Range: ").append(startAddress).append(" - ").append(endAddress).append("\n");
        sb.append("Bytes: ").append(toHex(newBytes));
        if (oldBytes != null) {
            sb.append("\nBefore: ").append(toHex(oldBytes));
            sb.append("\nAfter:  ").append(toHex(newBytes));
            if (clearCodeUnits) {
                sb.append("\nCode units cleared in patched range: yes");
            }
        }
        return sb.toString();
    }

    private static Address parseAddress(Program program, String addressStr) {
        try {
            Address parsed = program.getAddressFactory().getAddress(addressStr);
            if (parsed != null) {
                return parsed;
            }
        } catch (Exception ignored) {
            // Fall through to numeric parse
        }

        try {
            String clean = addressStr.strip();
            if (clean.startsWith("0x") || clean.startsWith("0X")) {
                clean = clean.substring(2);
            }
            long value = Long.parseUnsignedLong(clean, 16);
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", bytes[i] & 0xff));
        }
        return sb.toString();
    }

    private static McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }

    private static class AssembledBlock {
        private final byte[] bytes;
        private final Address endAddress;

        private AssembledBlock(byte[] bytes, Address endAddress) {
            this.bytes = bytes;
            this.endAddress = endAddress;
        }
    }
}

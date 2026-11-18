package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.Map;
import org.junit.jupiter.api.Test;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import io.modelcontextprotocol.modern.McpSchema;

class GetHexdumpToolTest {
    @Test void unreadableMemoryIsDistinguishedFromZeroBytes() {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address entry = space.getAddress(0x1000);
        AddressFactory factory = fake(AddressFactory.class, (method, args) -> entry);
        Memory memory = fake(Memory.class, (method, args) -> {
            long offset = ((Address) args[0]).getOffset();
            if (offset == 0x1001) throw new MemoryAccessException("unmapped");
            return (byte) (offset == 0x1000 ? 0 : 'A');
        });
        Program program = fake(Program.class, (method, args) -> switch (method) {
            case "getAddressFactory" -> factory;
            case "getMemory" -> memory;
            default -> throw new UnsupportedOperationException(method);
        });
        var result = new GetHexdumpTool().execute(Map.of("address", "0x1000", "len", 3), program);
        String text = ((McpSchema.TextContent) result.content().get(0)).text();
        assertTrue(text.contains("00 ?? 41"), text);
        assertTrue(text.contains("|.?A|"), text);
        assertTrue(text.contains("Unreadable bytes: 1"), text);
    }
    private interface Answer { Object invoke(String method, Object[] args) throws Throwable; }
    private static <T> T fake(Class<T> type, Answer answer) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type },
            (proxy, method, args) -> answer.invoke(method.getName(), args)));
    }
}

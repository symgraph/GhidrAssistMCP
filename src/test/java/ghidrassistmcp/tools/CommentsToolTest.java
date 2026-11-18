package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.Map;
import org.junit.jupiter.api.Test;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.modern.McpSchema;

class CommentsToolTest {
    @Test void invalidCommentAddressReturnsTypedError() {
        var result = new CommentsTool().execute(Map.of("action", "get", "address", "0x1000"), program(null));
        assertTrue(result.isError());
    }
    @Test void errorLikeCommentContentRemainsSuccessfulData() {
        CodeUnit unit = fake(CodeUnit.class, (method, args) -> "Error: text stored by the analyst");
        var result = new CommentsTool().execute(Map.of("action", "get", "address", "0x1000"), program(unit));
        assertFalse(Boolean.TRUE.equals(result.isError()));
        assertEquals("Error: text stored by the analyst", ((McpSchema.TextContent) result.content().get(0)).text());
    }
    private static Program program(CodeUnit codeUnit) {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address entry = space.getAddress(0x1000);
        AddressFactory factory = fake(AddressFactory.class, (method, args) -> entry);
        Listing listing = fake(Listing.class, (method, args) -> codeUnit);
        return fake(Program.class, (method, args) -> switch (method) {
            case "getAddressFactory" -> factory;
            case "getListing" -> listing;
            default -> throw new UnsupportedOperationException(method);
        });
    }
    private interface Answer { Object invoke(String method, Object[] args) throws Throwable; }
    private static <T> T fake(Class<T> type, Answer answer) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type },
            (proxy, method, args) -> answer.invoke(method.getName(), args)));
    }
}

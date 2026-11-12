package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.spec.McpSchema;

class RenameSymbolToolTest {
    @Test
    void unqualifiedRenameMovesNestedFunctionToGlobal() {
        TestProgram fixture = new TestProgram();
        Namespace outer = fixture.namespace("Outer", fixture.global);
        Namespace owner = fixture.namespace("Owner", outer);
        FunctionState target = fixture.function("oldName", 0x200, owner);

        var result = fixture.rename("0x200", "newName");

        assertTrue(result.success, result.message);
        assertSame(fixture.global, target.namespace);
        assertEquals("newName", target.name);
        assertTrue(result.message.endsWith("to 'newName'"), result.message);
        assertEquals(List.of(true), fixture.commits);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Widget", "~Widget", "render"})
    void acceptsDuplicateQualifiedFunctionNamesAtTheAddressedTarget(String name) {
        TestProgram fixture = new TestProgram();
        Namespace owner = fixture.namespace("Widget", fixture.global);
        FunctionState earlier = fixture.function(name, 0x100, owner);
        FunctionState target = fixture.function("oldName", 0x200, fixture.global);

        var result = fixture.rename("0x200", "Widget::" + name);

        assertTrue(result.success, result.message);
        assertEquals(name, earlier.name);
        assertEquals(name, target.name);
        assertSame(owner, target.namespace);
        assertEquals(0, earlier.renameCalls);
        assertEquals(1, target.renameCalls);
        assertTrue(result.message.endsWith("to 'Widget::" + name + "'"), result.message);
        assertEquals(List.of(true), fixture.commits);
    }

    @Test
    void acceptsDuplicateGlobalNameAndContainingAddressSelector() {
        TestProgram fixture = new TestProgram();
        Namespace owner = fixture.namespace("OldOwner", fixture.global);
        FunctionState earlier = fixture.function("process", 0x100, fixture.global);
        FunctionState target = fixture.function("oldName", 0x200, owner);

        var result = fixture.rename("0x204", "process");

        assertTrue(result.success, result.message);
        assertEquals("process", earlier.name);
        assertEquals(0, earlier.renameCalls);
        assertEquals("process", target.name);
        assertSame(fixture.global, target.namespace);
        assertEquals(List.of(true), fixture.commits);
    }

    @Test
    void nativeInvalidNameRollsBackNamespaceCreationAndReturnsTypedError() {
        TestProgram fixture = new TestProgram();
        Namespace owner = fixture.namespace("OldOwner", fixture.global);
        FunctionState target = fixture.function("oldName", 0x200, owner);
        target.renameFailure = new InvalidInputException("native invalid name");

        var result = new RenameSymbolTool(null).execute(
            request("0x200", "NewOwner::invalid"), fixture.program);

        assertTrue(result.isError());
        assertTrue(text(result).contains("native invalid name"), text(result));
        assertEquals("oldName", target.name);
        assertSame(owner, target.namespace);
        assertFalse(fixture.namespaces.containsKey("NewOwner"));
        assertEquals(List.of(false), fixture.commits);
    }

    @Test
    void nativeDuplicateRejectionStillFailsAndRollsBack() {
        TestProgram fixture = new TestProgram();
        Namespace owner = fixture.namespace("OldOwner", fixture.global);
        FunctionState target = fixture.function("oldName", 0x200, owner);
        target.renameFailure = new DuplicateNameException("native namespace conflict");

        var result = fixture.rename("0x200", "newName");

        assertFalse(result.success);
        assertTrue(result.message.contains("native namespace conflict"), result.message);
        assertEquals("oldName", target.name);
        assertSame(owner, target.namespace);
        assertEquals(List.of(false), fixture.commits);
    }

    @Test
    void batchCommitsGlobalAndDuplicateRenamesButRollsBackInvalidItem() throws Exception {
        TestProgram fixture = new TestProgram();
        Namespace owner = fixture.namespace("Owner", fixture.global);
        FunctionState globalTarget = fixture.function("nested", 0x100, owner);
        FunctionState existing = fixture.function("method", 0x200, owner);
        FunctionState duplicateTarget = fixture.function("unknown", 0x300, fixture.global);
        FunctionState invalidTarget = fixture.function("unchanged", 0x400, owner);
        invalidTarget.renameFailure = new InvalidInputException("native invalid name");

        var result = new RenameSymbolBatchTool(null).execute(Map.of("renames", List.of(
            request("0x100", "globalName"),
            request("0x300", "Owner::method"),
            request("0x400", "Temporary::invalid"))), fixture.program);
        var report = new ObjectMapper().readTree(text(result));

        assertEquals(2, report.get("succeeded").asInt());
        assertEquals(1, report.get("failed").asInt());
        assertTrue(report.get("results").get(0).get("success").asBoolean());
        assertTrue(report.get("results").get(1).get("success").asBoolean());
        assertFalse(report.get("results").get(2).get("success").asBoolean());
        assertSame(fixture.global, globalTarget.namespace);
        assertEquals("globalName", globalTarget.name);
        assertSame(owner, duplicateTarget.namespace);
        assertEquals("method", duplicateTarget.name);
        assertEquals(0, existing.renameCalls);
        assertEquals("unchanged", invalidTarget.name);
        assertSame(owner, invalidTarget.namespace);
        assertFalse(fixture.namespaces.containsKey("Temporary"));
        assertEquals(List.of(true, true, false), fixture.commits);
    }

    private static Map<String, Object> request(String identifier, String newName) {
        return Map.of("target_type", "function", "identifier", identifier, "new_name", newName);
    }

    private static String text(McpSchema.CallToolResult result) {
        return ((McpSchema.TextContent) result.content().get(0)).text();
    }

    private static final class FunctionState {
        private final Address address;
        private final Function function;
        private String name;
        private Namespace namespace;
        private Exception renameFailure;
        private int renameCalls;

        private FunctionState(String name, Address address, Namespace namespace) {
            this.name = name;
            this.address = address;
            this.namespace = namespace;
            function = fake(Function.class, (method, args) -> switch (method.getName()) {
                case "getName" -> args.length > 0 && Boolean.TRUE.equals(args[0])
                    && !this.namespace.isGlobal()
                    ? this.namespace.getName(true) + "::" + this.name : this.name;
                case "getEntryPoint" -> this.address;
                case "getParentNamespace" -> this.namespace;
                case "isExternal" -> false;
                case "getFunctionThunkAddresses" -> null;
                case "setParentNamespace" -> {
                    assertTrue(SwingUtilities.isEventDispatchThread());
                    this.namespace = (Namespace) args[0];
                    yield null;
                }
                case "setName" -> {
                    assertTrue(SwingUtilities.isEventDispatchThread());
                    assertEquals(SourceType.USER_DEFINED, args[1]);
                    renameCalls++;
                    if (renameFailure != null) throw renameFailure;
                    this.name = (String) args[0];
                    yield null;
                }
                default -> unsupported(method);
            });
        }
    }

    private static final class TestProgram {
        private final AddressSpace space = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
        private final Map<Address, FunctionState> functions = new LinkedHashMap<>();
        private final Map<String, Namespace> namespaces = new HashMap<>();
        private final List<Boolean> commits = new ArrayList<>();
        private Map<FunctionState, List<Object>> beforeFunctions;
        private Map<String, Namespace> beforeNamespaces;
        private final Namespace global = fake(Namespace.class, (method, args) -> switch (method.getName()) {
            case "getName" -> "Global";
            case "getParentNamespace" -> null;
            case "isGlobal" -> true;
            default -> unsupported(method);
        });
        private final AddressFactory addresses = fake(AddressFactory.class, (method, args) ->
            switch (method.getName()) {
                case "getAddress" -> ((String) args[0]).startsWith("0x")
                    ? space.getAddress(Long.parseLong(((String) args[0]).substring(2), 16)) : null;
                case "getDefaultAddressSpace" -> space;
                case "getAddressSpace" -> null;
                default -> unsupported(method);
            });
        private final FunctionManager functionManager = fake(FunctionManager.class, (method, args) ->
            switch (method.getName()) {
                case "getFunctionAt" -> functions.containsKey(args[0])
                    ? functions.get(args[0]).function : null;
                case "getFunctionContaining" -> functions.values().stream()
                    .filter(f -> ((Address) args[0]).getOffset() >= f.address.getOffset()
                        && ((Address) args[0]).getOffset() < f.address.getOffset() + 0x10)
                    .map(f -> f.function).findFirst().orElse(null);
                default -> unsupported(method);
            });
        private final SymbolTable symbols = fake(SymbolTable.class, (method, args) ->
            switch (method.getName()) {
                case "getSymbols" -> iterator(functions.values().stream()
                    .filter(f -> f.name.equals(args[0])).map(f -> symbol(f.function)).toList());
                case "getNamespace" -> namespaces.get(namespaceKey((String) args[0], (Namespace) args[1]));
                case "createClass", "createNameSpace" -> namespace((String) args[1], (Namespace) args[0]);
                default -> unsupported(method);
            });
        private final Program program = fake(Program.class, (method, args) ->
            switch (method.getName()) {
                case "getName" -> "TestProgram";
                case "getAddressFactory" -> addresses;
                case "getFunctionManager" -> functionManager;
                case "getSymbolTable" -> symbols;
                case "getGlobalNamespace" -> global;
                case "startTransaction" -> {
                    assertTrue(SwingUtilities.isEventDispatchThread());
                    beforeFunctions = new HashMap<>();
                    functions.values().forEach(f -> beforeFunctions.put(f, List.of(f.name, f.namespace)));
                    beforeNamespaces = new HashMap<>(namespaces);
                    yield 1;
                }
                case "endTransaction" -> {
                    assertTrue(SwingUtilities.isEventDispatchThread());
                    boolean commit = (Boolean) args[1];
                    commits.add(commit);
                    if (!commit) {
                        beforeFunctions.forEach((f, state) -> {
                            f.name = (String) state.get(0);
                            f.namespace = (Namespace) state.get(1);
                        });
                        namespaces.clear();
                        namespaces.putAll(beforeNamespaces);
                    }
                    yield commit;
                }
                default -> unsupported(method);
            });

        private RenameSymbolCore.RenameResult rename(String identifier, String newName) {
            return RenameSymbolCore.renameOne(request(identifier, newName), program, null);
        }

        private FunctionState function(String name, long offset, Namespace parent) {
            FunctionState state = new FunctionState(name, space.getAddress(offset), parent);
            functions.put(state.address, state);
            return state;
        }

        private Namespace namespace(String name, Namespace parent) {
            String qualified = namespaceKey(name, parent);
            Namespace namespace = fake(Namespace.class, (method, args) ->
                switch (method.getName()) {
                    case "getName" -> args.length > 0 && Boolean.TRUE.equals(args[0]) ? qualified : name;
                    case "getParentNamespace" -> parent;
                    case "isGlobal" -> false;
                    default -> unsupported(method);
                });
            namespaces.put(qualified, namespace);
            return namespace;
        }

        private String namespaceKey(String name, Namespace parent) {
            return parent.isGlobal() ? name : parent.getName(true) + "::" + name;
        }
    }

    private static Symbol symbol(Function function) {
        return fake(Symbol.class, (method, args) -> switch (method.getName()) {
            case "getObject" -> function;
            case "getSymbolType" -> SymbolType.FUNCTION;
            default -> unsupported(method);
        });
    }

    private static SymbolIterator iterator(List<Symbol> symbols) {
        Iterator<Symbol> delegate = symbols.iterator();
        return new SymbolIterator() {
            @Override public boolean hasNext() { return delegate.hasNext(); }
            @Override public Symbol next() { return delegate.next(); }
            @Override public Iterator<Symbol> iterator() { return this; }
        };
    }

    private static Object unsupported(Method method) {
        throw new UnsupportedOperationException("Unexpected call: " + method);
    }

    @SuppressWarnings("unchecked")
    private static <T> T fake(Class<T> type, FakeMethodHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type },
            (proxy, method, args) -> {
                if (method.getDeclaringClass() == Object.class) {
                    return switch (method.getName()) {
                        case "equals" -> proxy == args[0];
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "toString" -> "Fake" + type.getSimpleName();
                        default -> unsupported(method);
                    };
                }
                return handler.invoke(method, args == null ? new Object[0] : args);
            });
    }

    @FunctionalInterface
    private interface FakeMethodHandler {
        Object invoke(Method method, Object[] args) throws Throwable;
    }
}

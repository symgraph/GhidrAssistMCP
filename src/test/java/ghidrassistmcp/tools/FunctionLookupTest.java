package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.assertSame;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

class FunctionLookupTest {

    @Test
    void returnsLowestAddressForDuplicateIndexedNames() {
        TestProgram testProgram = new TestProgram();
        Function higher = testProgram.function("duplicate", 0x200, false, null);
        Function lower = testProgram.function("duplicate", 0x100, false, null);
        testProgram.index("duplicate", higher, lower);

        assertSame(lower, FunctionLookup.findByName(testProgram.program, "duplicate"));
    }

    @Test
    void findsDefaultThunkOfExternalFunction() {
        TestProgram testProgram = new TestProgram();
        Function thunk = testProgram.function("memcpy", 0x100, false, null);
        Function external = testProgram.function("memcpy", 0x900, true, null, 0x100);
        testProgram.index("memcpy", external);

        assertSame(thunk, FunctionLookup.findByName(testProgram.program, "memcpy"));
    }

    @Test
    void findsDefaultThunkOfDefaultNamedFunction() {
        TestProgram testProgram = new TestProgram();
        Function thunk = testProgram.function("thunk_FUN_00001000", 0x200, false, null);
        testProgram.function("FUN_00001000", 0x1000, false, null, 0x200);

        assertSame(thunk,
            FunctionLookup.findByName(testProgram.program, "thunk_FUN_00001000"));
    }

    @Test
    void qualifiedLookupFiltersDefaultThunksByInheritedNamespace() {
        TestProgram testProgram = new TestProgram();
        Namespace global = testProgram.namespace("Global", null, true);
        Namespace libc = testProgram.namespace("libc", global, false);
        Namespace other = testProgram.namespace("other", global, false);
        Function matchingThunk = testProgram.function("memcpy", 0x200, false, libc);
        testProgram.function("memcpy", 0x100, false, other);
        Function external = testProgram.function("memcpy", 0x900, true, libc, 0x100, 0x200);
        testProgram.index("memcpy", external);

        assertSame(matchingThunk,
            FunctionLookup.findByQualifiedName(testProgram.program, "libc::memcpy"));
    }

    @Test
    void includesDynamicFunctionHiddenByStoredNameCollision() {
        TestProgram testProgram = new TestProgram();
        Function dynamic = testProgram.function("FUN_00001000", 0x1000, false, null);
        Function stored = testProgram.function("FUN_00001000", 0x2000, false, null);
        testProgram.index("FUN_00001000", stored);

        assertSame(dynamic, FunctionLookup.findByName(testProgram.program, "FUN_00001000"));
    }

    private static final class TestProgram {
        private final AddressSpace addressSpace =
            new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
        private final Map<String, List<Symbol>> indexedSymbols = new HashMap<>();
        private final Map<Address, Function> functionsByAddress = new HashMap<>();
        private final FunctionManager functionManager = fake(FunctionManager.class,
            (method, args) -> switch (method.getName()) {
                case "getFunctionAt" -> functionsByAddress.get(args[0]);
                default -> unsupported(method);
            });
        private final SymbolTable symbolTable = fake(SymbolTable.class,
            (method, args) -> switch (method.getName()) {
                case "getSymbols" -> iterator(indexedSymbols.getOrDefault(args[0], List.of()));
                default -> unsupported(method);
            });
        private final AddressFactory addressFactory = fake(AddressFactory.class,
            (method, args) -> switch (method.getName()) {
                case "getAddressSpace" -> null;
                case "getDefaultAddressSpace" -> addressSpace;
                default -> unsupported(method);
            });
        private final Program program = fake(Program.class,
            (method, args) -> switch (method.getName()) {
                case "getFunctionManager" -> functionManager;
                case "getSymbolTable" -> symbolTable;
                case "getAddressFactory" -> addressFactory;
                default -> unsupported(method);
            });

        private Function function(String name, long offset, boolean external,
                Namespace namespace, long... thunkOffsets) {
            Address entryPoint = addressSpace.getAddress(offset);
            Address[] thunkAddresses = new Address[thunkOffsets.length];
            for (int i = 0; i < thunkOffsets.length; i++) {
                thunkAddresses[i] = addressSpace.getAddress(thunkOffsets[i]);
            }
            Function function = fake(Function.class,
                (method, args) -> switch (method.getName()) {
                    case "getName" -> name;
                    case "getEntryPoint" -> entryPoint;
                    case "getFunctionThunkAddresses" ->
                        thunkAddresses.length == 0 ? null : thunkAddresses;
                    case "getParentNamespace" -> namespace;
                    case "isExternal" -> external;
                    default -> unsupported(method);
                });
            functionsByAddress.put(entryPoint, function);
            return function;
        }

        private void index(String name, Function... functions) {
            indexedSymbols.put(name, java.util.Arrays.stream(functions)
                .map(this::symbol)
                .toList());
        }

        private Symbol symbol(Function function) {
            return fake(Symbol.class, (method, args) -> switch (method.getName()) {
                case "getObject" -> function;
                case "getSymbolType" -> SymbolType.FUNCTION;
                default -> unsupported(method);
            });
        }

        private Namespace namespace(String name, Namespace parent, boolean global) {
            return fake(Namespace.class, (method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "getParentNamespace" -> parent;
                case "isGlobal" -> global;
                default -> unsupported(method);
            });
        }
    }

    private static SymbolIterator iterator(List<Symbol> symbols) {
        Iterator<Symbol> delegate = symbols.iterator();
        return new SymbolIterator() {
            @Override
            public boolean hasNext() {
                return delegate.hasNext();
            }

            @Override
            public Symbol next() {
                return delegate.next();
            }

            @Override
            public Iterator<Symbol> iterator() {
                return this;
            }
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
        Object invoke(Method method, Object[] args);
    }
}

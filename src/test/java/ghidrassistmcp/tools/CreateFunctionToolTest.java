package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.spec.McpSchema;

class CreateFunctionToolTest {
    @Test
    void nativeCreateCommandSucceedsWithoutAnOuterTransaction() {
        Fixture fixture = new Fixture();
        assertFalse(fixture.active);

        var result = new CreateFunctionTool().execute(
            Map.of("address", "0x1000", "name", "render"), fixture.program);

        assertFalse(Boolean.TRUE.equals(result.isError()), text(result));
        assertTrue(text(result).contains("Name: render"), text(result));
        assertTrue(fixture.functionPresent);
        assertEquals("render", fixture.name);
        assertEquals(List.of(true), fixture.commits);
        assertFalse(fixture.active);
        assertEquals(List.of("previous analysis"), fixture.changes);
    }

    @Test
    void failedInitialAttemptRollsBackBeforeFallbackAndFallbackCommitsTogether() {
        Fixture fixture = new Fixture();
        AtomicInteger attempts = new AtomicInteger();
        CreateFunctionTool tool = new CreateFunctionTool(entry -> command("native first failure", () -> {
            fixture.requireTransaction();
            if (attempts.getAndIncrement() == 0) {
                fixture.changes.add("partial first attempt");
                return false;
            }
            assertEquals(List.of("previous analysis", "disassembled"), fixture.changes);
            fixture.defineFunction("FUN_1000", new AddressSet(entry, entry.add(7)));
            return true;
        }), (entry, range) -> command(null, () -> {
            fixture.requireTransaction();
            assertEquals(List.of("previous analysis"), fixture.changes);
            assertNull(range);
            fixture.changes.add("disassembled");
            return true;
        }));

        var result = tool.execute(Map.of("address", "0x1000"), fixture.program);

        assertFalse(Boolean.TRUE.equals(result.isError()), text(result));
        assertEquals(2, attempts.get());
        assertEquals(List.of(false, true), fixture.commits);
        assertEquals(List.of("previous analysis", "disassembled"), fixture.changes);
        assertTrue(fixture.functionPresent);
        assertFalse(fixture.active);
    }

    @Test
    void failedRetryPreservesBothNativeStatusesAndRollsBackDisassembly() {
        Fixture fixture = new Fixture();
        AtomicInteger attempts = new AtomicInteger();
        CreateFunctionTool tool = new CreateFunctionTool(entry -> {
            String status = attempts.getAndIncrement() == 0 ? "native initial status" : "native retry status";
            return command(status, () -> {
                fixture.requireTransaction();
                fixture.changes.add("partial creation");
                return false;
            });
        }, (entry, range) -> command(null, () -> {
            fixture.requireTransaction();
            fixture.changes.add("disassembled");
            return true;
        }));

        var result = tool.execute(Map.of("address", "0x1000"), fixture.program);

        assertTrue(result.isError());
        assertTrue(text(result).contains("native initial status"), text(result));
        assertTrue(text(result).contains("native retry status"), text(result));
        assertEquals(List.of(false, false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void disassemblyFailureRetainsItsStatusAndDoesNotRetryCreation() {
        Fixture fixture = new Fixture();
        AtomicInteger attempts = new AtomicInteger();
        CreateFunctionTool tool = new CreateFunctionTool(entry -> {
            attempts.incrementAndGet();
            return command("native create status", () -> false);
        }, (entry, range) -> command("native disassembly status", () -> {
            fixture.requireTransaction();
            fixture.changes.add("partial disassembly");
            return false;
        }));

        var result = tool.execute(Map.of("address", "0x1000"), fixture.program);

        assertTrue(result.isError());
        assertTrue(text(result).contains("native create status"), text(result));
        assertTrue(text(result).contains("disassembly failed: native disassembly status"), text(result));
        assertEquals(1, attempts.get());
        assertEquals(List.of(false, false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void clearDisassembleAndFailedCreationRollBackAsOneAttempt() {
        Fixture fixture = new Fixture();
        CreateFunctionTool tool = new CreateFunctionTool(entry -> command("body overlaps", () -> {
            fixture.requireTransaction();
            assertTrue(fixture.cleared);
            fixture.changes.add("partial creation");
            return false;
        }), (entry, range) -> command(null, () -> {
            fixture.requireTransaction();
            assertTrue(fixture.cleared);
            assertEquals(new AddressSet(entry, entry.add(15)), range);
            fixture.changes.add("disassembled");
            return true;
        }));

        var result = tool.execute(Map.of("address", "0x1000", "clear_existing", true,
            "clear_length", 16), fixture.program);

        assertTrue(result.isError());
        assertTrue(text(result).contains("body overlaps"), text(result));
        assertEquals(List.of(false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void renameFailureRollsBackCreationClearingAndDisassembly() {
        Fixture fixture = new Fixture();
        fixture.renameFailure = new InvalidInputException("invalid function name");
        CreateFunctionTool tool = new CreateFunctionTool(entry -> command(null, () -> {
            fixture.requireTransaction();
            fixture.defineFunction("FUN_1000", new AddressSet(entry, entry.add(7)));
            return true;
        }), (entry, range) -> command(null, () -> {
            fixture.requireTransaction();
            fixture.changes.add("disassembled");
            return true;
        }));

        var result = tool.execute(Map.of("address", "0x1000", "clear_existing", true,
            "clear_length", 8, "name", "bad name"), fixture.program);

        assertTrue(result.isError());
        assertTrue(text(result).contains("rename failed: invalid function name"), text(result));
        assertFalse(text(result).contains("Function created"), text(result));
        assertEquals(List.of(false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void thrownCreationErrorRollsBackAndReportsCorrectStage() {
        Fixture fixture = new Fixture();
        CreateFunctionTool tool = new CreateFunctionTool(entry -> command(null, () -> {
            fixture.requireTransaction();
            fixture.changes.add("partial creation");
            throw new IllegalStateException("native creation exception");
        }), (entry, range) -> { throw new AssertionError("Unexpected fallback"); });

        var result = tool.execute(Map.of("address", "0x1000"), fixture.program);

        assertTrue(result.isError());
        assertTrue(text(result).contains("function creation failed: native creation exception"), text(result));
        assertEquals(List.of(false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void commandSuccessWithoutExactEntryFunctionIsAnErrorAndRollsBack() {
        Fixture fixture = new Fixture();
        CreateFunctionTool tool = new CreateFunctionTool(entry -> command(null, () -> {
            fixture.requireTransaction();
            fixture.changes.add("unverified creation");
            return true;
        }), (entry, range) -> { throw new AssertionError("Unexpected fallback"); });

        var result = tool.execute(Map.of("address", "0x1000"), fixture.program);

        assertTrue(result.isError());
        assertTrue(text(result).contains("no function exists at the entry"), text(result));
        assertEquals(List.of(false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void existingFunctionIsRetainedWithoutTransactionsOrCommands() {
        Fixture fixture = new Fixture();
        fixture.functionPresent = true;
        fixture.name = "existing";
        CreateFunctionTool tool = new CreateFunctionTool(entry -> { throw new AssertionError(); },
            (entry, range) -> { throw new AssertionError(); });

        var result = tool.execute(Map.of("address", "0x1000", "name", "other",
            "clear_existing", true), fixture.program);

        assertFalse(Boolean.TRUE.equals(result.isError()), text(result));
        assertTrue(text(result).contains("already exists"), text(result));
        assertEquals("existing", fixture.name);
        assertEquals(List.of(), fixture.commits);
        assertFalse(fixture.cleared);
    }

    private static Command<Program> command(String status, Action action) {
        return new Command<>() {
            @Override public String getName() { return "Test command"; }
            @Override public String getStatusMsg() { return status; }
            @Override public boolean applyTo(Program program) { return action.apply(); }
        };
    }

    @FunctionalInterface
    private interface Action { boolean apply(); }

    private static String text(McpSchema.CallToolResult result) {
        return ((McpSchema.TextContent) result.content().get(0)).text();
    }

    private static final class Fixture {
        private final AddressSpace space = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
        private final Address entry = space.getAddress(0x1000);
        private final List<Boolean> commits = new ArrayList<>();
        private final List<String> changes = new ArrayList<>(List.of("previous analysis"));
        private boolean active;
        private boolean functionPresent;
        private boolean cleared;
        private String name = "FUN_1000";
        private AddressSetView body = new AddressSet(entry, entry.add(7));
        private Exception renameFailure;
        private Snapshot before;

        private final Function function = fake(Function.class, (method, args) -> switch (method.getName()) {
            case "getName" -> name;
            case "getEntryPoint" -> entry;
            case "getBody" -> body;
            case "setName" -> {
                requireTransaction();
                assertEquals(SourceType.USER_DEFINED, args[1]);
                if (renameFailure != null) throw renameFailure;
                name = (String) args[0];
                yield null;
            }
            default -> unsupported(method);
        });
        private final Namespace global = fake(Namespace.class, (method, args) -> switch (method.getName()) {
            case "isGlobal" -> true;
            default -> unsupported(method);
        });
        private final CodeUnit codeUnit = fake(CodeUnit.class, (method, args) -> switch (method.getName()) {
            case "getMinAddress" -> entry;
            case "getMaxAddress" -> entry.add(7);
            default -> unsupported(method);
        });
        private final AddressFactory addresses = fake(AddressFactory.class, (method, args) -> switch (method.getName()) {
            case "getAddress" -> space.getAddress(Long.decode((String) args[0]));
            default -> unsupported(method);
        });
        private final FunctionManager functions = fake(FunctionManager.class, (method, args) -> switch (method.getName()) {
            case "getFunctionAt" -> functionPresent && entry.equals(args[0]) ? function : null;
            case "getFunctionsOverlapping" -> List.<Function>of().iterator();
            default -> unsupported(method);
        });
        private final SymbolTable symbols = fake(SymbolTable.class, (method, args) -> switch (method.getName()) {
            case "getPrimarySymbol" -> null;
            default -> unsupported(method);
        });
        private final Memory memory = fake(Memory.class, (method, args) -> switch (method.getName()) {
            case "isExternalBlockAddress" -> false;
            default -> unsupported(method);
        });
        private final Listing listing = fake(Listing.class, (method, args) -> switch (method.getName()) {
            case "getInstructionAt" -> null;
            case "getCodeUnitAt", "getCodeUnitContaining" -> codeUnit;
            case "createFunction" -> {
                requireTransaction();
                defineFunction((String) args[0], (AddressSetView) args[3]);
                yield function;
            }
            case "clearCodeUnits" -> {
                requireTransaction();
                cleared = true;
                changes.add("cleared");
                yield null;
            }
            default -> unsupported(method);
        });
        private final Program program = fake(Program.class, (method, args) -> switch (method.getName()) {
            case "getAddressFactory" -> addresses;
            case "getFunctionManager" -> functions;
            case "getGlobalNamespace" -> global;
            case "getSymbolTable" -> symbols;
            case "getMemory" -> memory;
            case "getListing" -> listing;
            case "startTransaction" -> {
                assertFalse(active, "Tool must own and close each transaction before retrying");
                before = new Snapshot(functionPresent, cleared, name, body, List.copyOf(changes));
                active = true;
                yield commits.size() + 1;
            }
            case "endTransaction" -> {
                requireTransaction();
                assertEquals(commits.size() + 1, args[0]);
                boolean commit = (Boolean) args[1];
                commits.add(commit);
                if (!commit) {
                    functionPresent = before.functionPresent();
                    cleared = before.cleared();
                    name = before.name();
                    body = before.body();
                    changes.clear();
                    changes.addAll(before.changes());
                }
                active = false;
                yield commit;
            }
            default -> unsupported(method);
        });

        private void requireTransaction() { assertTrue(active, "Mutation requires an owned transaction"); }

        private void defineFunction(String functionName, AddressSetView functionBody) {
            requireTransaction();
            functionPresent = true;
            name = functionName;
            body = functionBody;
        }

        private void assertOriginalState() {
            assertFalse(active);
            assertFalse(functionPresent);
            assertFalse(cleared);
            assertEquals(List.of("previous analysis"), changes);
        }
    }

    private record Snapshot(boolean functionPresent, boolean cleared, String name,
            AddressSetView body, List<String> changes) {}

    private static Object unsupported(Method method) {
        throw new UnsupportedOperationException("Unexpected call: " + method);
    }

    @SuppressWarnings("unchecked")
    private static <T> T fake(Class<T> type, Handler handler) {
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
    private interface Handler { Object invoke(Method method, Object[] args) throws Throwable; }
}

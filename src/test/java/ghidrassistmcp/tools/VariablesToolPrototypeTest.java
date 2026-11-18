package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ghidra.app.util.cparser.C.ParseException;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

class VariablesToolPrototypeTest {
    @Test
    void omittedConventionPreservesValidExistingConvention() {
        Fixture fixture = new Fixture();
        fixture.convention = "__thiscall";

        var result = fixture.apply("void saveConfiguration(void* self, void* store)");

        assertFalse(Boolean.TRUE.equals(result.isError()), text(result));
        assertEquals("__thiscall", fixture.appliedConvention);
        assertEquals("__thiscall", fixture.convention);
        assertEquals(List.of(true), fixture.commits);
        assertEquals("Existing reviewer comment", fixture.comment);
    }

    @Test
    void omittedUnknownConventionUsesSelectedCompilerNativeDefault() {
        Fixture fixture = new Fixture();
        fixture.convention = CompilerSpec.CALLING_CONVENTION_unknown;

        var result = fixture.apply("void saveConfiguration(void* self)");

        assertFalse(Boolean.TRUE.equals(result.isError()), text(result));
        assertEquals("__aapcs64", fixture.appliedConvention);
        assertEquals("__aapcs64", fixture.convention);
        assertEquals(List.of(true), fixture.commits);
    }

    @Test
    void omittedConventionPreservesValidDefaultAlias() {
        Fixture fixture = new Fixture();
        fixture.convention = CompilerSpec.CALLING_CONVENTION_default;

        var result = fixture.apply("void saveConfiguration(void)");

        assertFalse(Boolean.TRUE.equals(result.isError()), text(result));
        assertEquals(CompilerSpec.CALLING_CONVENTION_default, fixture.appliedConvention);
    }

    @Test
    void omittedStaleUnsupportedConventionFallsBackToNativeDefault() {
        Fixture fixture = new Fixture();
        fixture.convention = "removed_compiler_model";

        var result = fixture.apply("void saveConfiguration(void)");

        assertFalse(Boolean.TRUE.equals(result.isError()), text(result));
        assertEquals("__aapcs64", fixture.appliedConvention);
    }

    @Test
    void explicitSupportedConventionOverridesCurrentAndIsRemovedOnlyForParser() {
        Fixture fixture = new Fixture();
        fixture.convention = "__thiscall";

        var result = fixture.apply("void __stdcall saveConfiguration(void* self)");

        assertFalse(Boolean.TRUE.equals(result.isError()), text(result));
        assertEquals("__stdcall", fixture.appliedConvention);
        assertEquals(List.of("void  saveConfiguration(void* self)"), fixture.parsedTexts);
        assertTrue(text(result).contains("void __stdcall saveConfiguration"), text(result));
    }

    @Test
    void explicitSelectedCompilerCustomConventionIsSupported() {
        Fixture fixture = new Fixture();
        fixture.convention = "__cdecl";

        var result = fixture.apply("void __aapcs64 saveConfiguration(void)");

        assertFalse(Boolean.TRUE.equals(result.isError()), text(result));
        assertEquals("__aapcs64", fixture.appliedConvention);
        assertEquals(List.of("void  saveConfiguration(void)"), fixture.parsedTexts);
    }

    @Test
    void multipleConventionTokensAreRejectedBeforeParsingOrApplying() {
        Fixture fixture = new Fixture();

        var result = fixture.apply("void __cdecl __stdcall saveConfiguration(void)");

        assertTrue(result.isError());
        assertTrue(text(result).contains("Multiple calling convention tokens"), text(result));
        assertEquals(List.of(), fixture.parsedTexts);
        assertEquals(0, fixture.commandCalls);
        assertEquals(List.of(false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void parserFailureDoesNotChangeSignatureConventionStorageOrComment() {
        Fixture fixture = new Fixture();
        fixture.parseFailure = new ParseException("native parser rejected declaration");

        var result = fixture.apply("void saveConfiguration(void);");

        assertTrue(result.isError());
        assertTrue(text(result).contains("native parser rejected declaration"), text(result));
        assertEquals(List.of("void saveConfiguration(void);"), fixture.parsedTexts);
        assertEquals(0, fixture.commandCalls);
        assertEquals(List.of(false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void commandFailureRollsBackPartialSignatureConventionAndStorageChanges() {
        Fixture fixture = new Fixture();
        fixture.commandSuccess = false;

        var result = fixture.apply("void __stdcall saveConfiguration(void* self)");

        assertTrue(result.isError());
        assertTrue(text(result).contains("native signature application failure"), text(result));
        assertEquals("__stdcall", fixture.appliedConvention);
        assertEquals(1, fixture.commandCalls);
        assertEquals(List.of(false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void thrownCommandErrorRollsBackPartialSignatureConventionStorageAndCommentChanges() {
        Fixture fixture = new Fixture();
        fixture.commandFailure = new IllegalStateException("native signature application exception");
        String requested = "void __stdcall saveConfiguration(void* self)";

        var result = fixture.apply(requested);

        assertTrue(result.isError());
        assertTrue(text(result).contains("native signature application exception"), text(result));
        assertEquals(new Snapshot("__stdcall", requested, "Partial command comment", false),
            fixture.beforeThrow);
        assertEquals(1, fixture.commandCalls);
        assertEquals(List.of(false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void missingNativeDefaultFailsWithoutApplyingOrChangingExistingState() {
        Fixture fixture = new Fixture();
        fixture.defaultConvention = null;

        var result = fixture.apply("void saveConfiguration(void)");

        assertTrue(result.isError());
        assertTrue(text(result).contains("no valid default calling convention"), text(result));
        assertEquals(0, fixture.commandCalls);
        assertEquals(List.of(false), fixture.commits);
        fixture.assertOriginalState();
    }

    @Test
    void extractionLeavesOtherGrammarAndArgumentTextUntouched() throws Exception {
        Fixture fixture = new Fixture();
        for (String declaration : List.of(
                "const unsigned char* saveConfiguration(void* self);",
                "void saveConfiguration(void* __stdcall)",
                "void __cdecl(void)",
                "void saveConfiguration__stdcall(void)",
                "void __unsupported saveConfiguration(void)",
                "void __stdcall* saveConfiguration(void)")) {
            var extracted = PrototypeCallingConvention.extract(fixture.compiler, declaration);
            assertEquals(declaration, extracted.prototype());
            assertNull(extracted.callingConvention());
        }
    }

    @Test
    void unsupportedConventionRemainsForNativeParserRejection() {
        Fixture fixture = new Fixture();
        fixture.parseFailure = new ParseException("Can't resolve return type: void __unsupported");

        var result = fixture.apply("void __unsupported saveConfiguration(void)");

        assertTrue(result.isError());
        assertEquals(List.of("void __unsupported saveConfiguration(void)"), fixture.parsedTexts);
        assertEquals(0, fixture.commandCalls);
        fixture.assertOriginalState();
    }

    private static String text(McpSchema.CallToolResult result) {
        return ((McpSchema.TextContent) result.content().get(0)).text();
    }

    private static final class Fixture {
        private final Address entry = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0)
            .getAddress(0x1000);
        private final Map<String, PrototypeModel> models = new LinkedHashMap<>();
        private final List<Boolean> commits = new ArrayList<>();
        private final List<String> parsedTexts = new ArrayList<>();
        private String defaultConvention = "__aapcs64";
        private String convention = CompilerSpec.CALLING_CONVENTION_unknown;
        private String signature = "void original(void)";
        private String comment = "Existing reviewer comment";
        private boolean customStorage = true;
        private boolean active;
        private Snapshot before;
        private Exception parseFailure;
        private boolean commandSuccess = true;
        private RuntimeException commandFailure;
        private Snapshot beforeThrow;
        private int commandCalls;
        private String appliedConvention;

        Fixture() {
            for (String name : List.of("__aapcs64", "__cdecl", "__stdcall", "__thiscall")) {
                models.put(name, new PrototypeModel(name, new PrototypeModel()));
            }
        }

        private final CompilerSpec compiler = fake(CompilerSpec.class, (method, args) -> switch (method.getName()) {
            case "getCallingConventions" -> models.values().toArray(PrototypeModel[]::new);
            case "getCallingConvention" -> CompilerSpec.CALLING_CONVENTION_default.equals(args[0])
                ? models.get(defaultConvention) : models.get(args[0]);
            case "getDefaultCallingConvention" -> models.get(defaultConvention);
            default -> unsupported(method);
        });
        private final DataTypeManager dataTypes = fake(DataTypeManager.class, (method, args) -> switch (method.getName()) {
            case "getKnownCallingConventionNames" -> List.copyOf(models.keySet());
            default -> unsupported(method);
        });
        private final Function function = fake(Function.class, (method, args) -> switch (method.getName()) {
            case "getName" -> "saveConfiguration";
            case "getCallingConventionName" -> convention;
            default -> unsupported(method);
        });
        private final FunctionManager functions = fake(FunctionManager.class, (method, args) -> switch (method.getName()) {
            case "getFunctionAt" -> entry.equals(args[0]) ? function : null;
            default -> unsupported(method);
        });
        private final AddressFactory addresses = fake(AddressFactory.class, (method, args) -> switch (method.getName()) {
            case "getAddress" -> "0x1000".equals(args[0]) ? entry : null;
            default -> unsupported(method);
        });
        private final Program program = fake(Program.class, (method, args) -> switch (method.getName()) {
            case "getAddressFactory" -> addresses;
            case "getFunctionManager" -> functions;
            case "getCompilerSpec" -> compiler;
            case "getDataTypeManager" -> dataTypes;
            case "startTransaction" -> {
                assertTrue(SwingUtilities.isEventDispatchThread());
                assertFalse(active);
                before = new Snapshot(convention, signature, comment, customStorage);
                active = true;
                yield 1;
            }
            case "endTransaction" -> {
                requireTransaction();
                assertEquals(1, args[0]);
                boolean commit = (Boolean) args[1];
                commits.add(commit);
                if (!commit) {
                    convention = before.convention();
                    signature = before.signature();
                    comment = before.comment();
                    customStorage = before.customStorage();
                }
                active = false;
                yield commit;
            }
            default -> unsupported(method);
        });

        private McpSchema.CallToolResult apply(String prototype) {
            VariablesTool tool = new VariablesTool(null, (selectedProgram, parsedPrototype) -> {
                requireTransaction();
                assertSame(program, selectedProgram);
                parsedTexts.add(parsedPrototype);
                if (parseFailure != null) throw parseFailure;
                return new FunctionDefinitionDataType("saveConfiguration", dataTypes);
            }, (address, parsed) -> new BackgroundCommand<Program>() {
                @Override public boolean applyTo(Program selectedProgram, TaskMonitor monitor) {
                    requireTransaction();
                    assertSame(program, selectedProgram);
                    assertEquals(entry, address);
                    commandCalls++;
                    appliedConvention = parsed.getCallingConventionName();
                    convention = appliedConvention;
                    signature = prototype;
                    customStorage = false; // Actual signature requests may change formal parameter storage.
                    if (commandFailure != null) {
                        comment = "Partial command comment";
                        beforeThrow = new Snapshot(convention, signature, comment, customStorage);
                        throw commandFailure;
                    }
                    setStatusMsg("native signature application failure");
                    return commandSuccess;
                }
            });
            return tool.execute(Map.of("action", "set_prototype", "function_address", "0x1000",
                "prototype", prototype), program);
        }

        private void requireTransaction() {
            assertTrue(SwingUtilities.isEventDispatchThread());
            assertTrue(active);
        }

        private void assertOriginalState() {
            assertFalse(active);
            assertEquals(CompilerSpec.CALLING_CONVENTION_unknown, convention);
            assertEquals("void original(void)", signature);
            assertEquals("Existing reviewer comment", comment);
            assertTrue(customStorage);
        }
    }

    private record Snapshot(String convention, String signature, String comment, boolean customStorage) {}

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

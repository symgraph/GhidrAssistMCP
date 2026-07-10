package ghidrassistmcp.decompiler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import docking.options.OptionsService;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;

class DecompilerServiceTest {

    @Test
    void resolvesOptionsAndSetsThemBeforeOpeningProgram() {
        Program program = program("test", false);
        ServiceProvider provider = serviceProvider(null);
        DecompileOptions options = new DecompileOptions();
        FakeDecompiler decompiler = new FakeDecompiler(true);
        AtomicReference<ServiceProvider> resolvedProvider = new AtomicReference<>();
        AtomicReference<Program> resolvedProgram = new AtomicReference<>();

        DecompilerService service = new DecompilerService(
            requestedProgram -> {
                assertSame(program, requestedProgram);
                return provider;
            },
            (actualProvider, actualProgram) -> {
                resolvedProvider.set(actualProvider);
                resolvedProgram.set(actualProgram);
                return options;
            },
            () -> decompiler);

        try (DecompilerSession session = service.open(program)) {
            assertSame(decompiler, session.decompiler());
            assertSame(options, session.options());
            assertEquals(List.of("setOptions", "openProgram"), decompiler.events);
            assertFalse(decompiler.disposed);
        }

        assertSame(provider, resolvedProvider.get());
        assertSame(program, resolvedProgram.get());
        assertTrue(decompiler.disposed);
    }

    @Test
    void supportsHeadlessModeWithoutAServiceProvider() {
        Program program = program("headless", false);
        AtomicReference<ServiceProvider> resolvedProvider = new AtomicReference<>();
        FakeDecompiler decompiler = new FakeDecompiler(true);
        DecompilerService service = new DecompilerService(
            requestedProgram -> null,
            (provider, requestedProgram) -> {
                resolvedProvider.set(provider);
                return new DecompileOptions();
            },
            () -> decompiler);

        try (DecompilerSession ignored = service.open(program)) {
            assertEquals(List.of("setOptions", "openProgram"), decompiler.events);
        }
        assertNull(resolvedProvider.get());
    }

    @Test
    void disposesWithoutOpeningWhenOptionsAreRejected() {
        Program program = program("test", false);
        FakeDecompiler decompiler = new FakeDecompiler(false, true);
        DecompilerService service = new DecompilerService(
            requestedProgram -> null,
            (provider, requestedProgram) -> new DecompileOptions(),
            () -> decompiler);

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> service.open(program));

        assertTrue(error.getMessage().contains("rejected its options"));
        assertEquals(List.of("setOptions"), decompiler.events);
        assertTrue(decompiler.disposed);
    }

    @Test
    void disposesAndReportsNativeMessageWhenOpenFails() {
        Program program = program("broken", false);
        FakeDecompiler decompiler = new FakeDecompiler(false);
        decompiler.lastMessage = "native startup failed";
        DecompilerService service = new DecompilerService(
            requestedProgram -> null,
            (provider, requestedProgram) -> new DecompileOptions(),
            () -> decompiler);

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> service.open(program));

        assertTrue(error.getMessage().contains("broken"));
        assertTrue(error.getMessage().contains("native startup failed"));
        assertTrue(decompiler.disposed);
    }

    @Test
    void sessionCloseIsIdempotent() {
        FakeDecompiler decompiler = new FakeDecompiler(true);
        DecompilerSession session = new DecompilerSession(decompiler, new DecompileOptions());

        session.close();
        session.close();

        assertEquals(1, decompiler.disposeCount);
    }

    @Test
    void fingerprintChangesWhenGuiDecompilerOptionsChange() {
        ToolOptions decompilerOptions = new ToolOptions("Decompiler");
        ToolOptions browserOptions = new ToolOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
        decompilerOptions.setBoolean("Display.Casts", true);
        OptionsService optionsService = optionsService(decompilerOptions, browserOptions);
        DecompilerService service = new DecompilerService(
            requestedProgram -> serviceProvider(optionsService));
        Program program = program("test", false);

        String before = service.getOptionsFingerprint(program);
        decompilerOptions.setBoolean("Display.Casts", false);
        String after = service.getOptionsFingerprint(program);

        assertNotEquals(before, after);
        assertEquals(after, service.getOptionsFingerprint(program));
    }

    @Test
    void rejectsClosedProgramsBeforeAllocatingDecompiler() {
        Program program = program("closed", true);
        DecompilerService service = new DecompilerService(requestedProgram -> null,
            (provider, requestedProgram) -> new DecompileOptions(),
            () -> {
                throw new AssertionError("Decompiler must not be allocated");
            });

        assertThrows(IllegalStateException.class, () -> service.open(program));
    }

    private static Program program(String name, boolean closed) {
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "isClosed" -> closed;
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> "FakeProgram[" + name + "]";
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }

    private static ServiceProvider serviceProvider(OptionsService optionsService) {
        return (ServiceProvider) Proxy.newProxyInstance(ServiceProvider.class.getClassLoader(),
            new Class<?>[] { ServiceProvider.class }, (proxy, method, args) -> {
                if (method.getName().equals("getService") && args[0] == OptionsService.class) {
                    return optionsService;
                }
                return null;
            });
    }

    private static OptionsService optionsService(ToolOptions decompilerOptions,
            ToolOptions browserOptions) {
        return (OptionsService) Proxy.newProxyInstance(OptionsService.class.getClassLoader(),
            new Class<?>[] { OptionsService.class }, (proxy, method, args) -> {
                if (!method.getName().equals("getOptions")) {
                    return null;
                }
                return "Decompiler".equals(args[0]) ? decompilerOptions : browserOptions;
            });
    }

    private static final class FakeDecompiler extends DecompInterface {
        private final List<String> events = new ArrayList<>();
        private final boolean setOptionsResult;
        private final boolean openResult;
        private boolean disposed;
        private int disposeCount;
        private String lastMessage = "";

        FakeDecompiler(boolean openResult) {
            this(true, openResult);
        }

        FakeDecompiler(boolean setOptionsResult, boolean openResult) {
            this.setOptionsResult = setOptionsResult;
            this.openResult = openResult;
        }

        @Override
        public synchronized boolean setOptions(DecompileOptions options) {
            events.add("setOptions");
            return setOptionsResult;
        }

        @Override
        public synchronized boolean openProgram(Program program) {
            events.add("openProgram");
            return openResult;
        }

        @Override
        public String getLastMessage() {
            return lastMessage;
        }

        @Override
        public synchronized void dispose() {
            disposed = true;
            disposeCount++;
        }
    }
}

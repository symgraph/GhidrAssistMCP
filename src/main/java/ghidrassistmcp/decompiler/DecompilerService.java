package ghidrassistmcp.decompiler;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

import docking.options.OptionsService;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;

/** Creates isolated decompiler sessions using the options of the owning CodeBrowser. */
public final class DecompilerService {
    private final Function<Program, ServiceProvider> serviceProviderResolver;
    private final BiFunction<ServiceProvider, Program, DecompileOptions> optionsResolver;
    private final Supplier<DecompInterface> decompilerFactory;

    public DecompilerService(Function<Program, ServiceProvider> serviceProviderResolver) {
        this(serviceProviderResolver, DecompilerUtils::getDecompileOptions, DecompInterface::new);
    }

    DecompilerService(Function<Program, ServiceProvider> serviceProviderResolver,
            BiFunction<ServiceProvider, Program, DecompileOptions> optionsResolver,
            Supplier<DecompInterface> decompilerFactory) {
        this.serviceProviderResolver = Objects.requireNonNull(serviceProviderResolver);
        this.optionsResolver = Objects.requireNonNull(optionsResolver);
        this.decompilerFactory = Objects.requireNonNull(decompilerFactory);
    }

    public DecompilerSession open(Program program) {
        if (program == null) {
            throw new IllegalArgumentException("Cannot initialize a decompiler without a program");
        }
        if (program.isClosed()) {
            throw new IllegalStateException(
                "Cannot initialize a decompiler for closed program: " + program.getName());
        }

        ServiceProvider serviceProvider = serviceProviderResolver.apply(program);
        DecompileOptions options = optionsResolver.apply(serviceProvider, program);
        DecompInterface decompiler = decompilerFactory.get();
        boolean opened = false;
        try {
            if (!decompiler.setOptions(options)) {
                throw initializationFailure(program, decompiler, "Decompiler rejected its options");
            }
            if (!decompiler.openProgram(program)) {
                throw initializationFailure(program, decompiler, "Unable to open program");
            }
            opened = true;
            return new DecompilerSession(decompiler, options);
        }
        finally {
            if (!opened) {
                decompiler.dispose();
            }
        }
    }

    /** Fingerprint GUI options so cached output changes immediately when those options change. */
    public String getOptionsFingerprint(Program program) {
        ServiceProvider serviceProvider = serviceProviderResolver.apply(program);
        OptionsService optionsService = serviceProvider != null
                ? serviceProvider.getService(OptionsService.class)
                : null;
        if (optionsService == null) {
            return "program-defaults";
        }

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 is required by the Java runtime", e);
        }

        updateDigest(digest, optionsService.getOptions("Decompiler"));
        updateDigest(digest, optionsService.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS));
        return java.util.HexFormat.of().formatHex(digest.digest());
    }

    private static void updateDigest(MessageDigest digest, ToolOptions options) {
        List<String> names = new ArrayList<>(options.getOptionNames());
        names.sort(String::compareTo);
        for (String name : names) {
            updateDigest(digest, name);
            updateDigest(digest, options.getValueAsString(name));
        }
    }

    private static void updateDigest(MessageDigest digest, String value) {
        if (value != null) {
            digest.update(value.getBytes(StandardCharsets.UTF_8));
        }
        digest.update((byte) 0);
    }

    private static IllegalStateException initializationFailure(Program program,
            DecompInterface decompiler, String summary) {
        String detail = decompiler.getLastMessage();
        String message = summary + " for " + program.getName();
        if (detail != null && !detail.isBlank()) {
            message += ": " + detail.trim();
        }
        return new IllegalStateException(message);
    }
}

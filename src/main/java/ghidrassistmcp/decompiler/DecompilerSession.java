package ghidrassistmcp.decompiler;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;

/** Owns a configured decompiler interface and guarantees native resource cleanup. */
public final class DecompilerSession implements AutoCloseable {
    private final DecompInterface decompiler;
    private final DecompileOptions options;
    private boolean closed;

    DecompilerSession(DecompInterface decompiler, DecompileOptions options) {
        this.decompiler = decompiler;
        this.options = options;
    }

    public DecompInterface decompiler() {
        return decompiler;
    }

    public DecompileOptions options() {
        return options;
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            decompiler.dispose();
        }
    }
}

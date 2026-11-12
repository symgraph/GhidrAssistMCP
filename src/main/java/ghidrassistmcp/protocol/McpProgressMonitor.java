package ghidrassistmcp.protocol;

import java.math.BigInteger;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitorAdapter;
import io.modelcontextprotocol.spec.McpSchema;

/** Sends optional SDK progress for one in-flight request without changing its execution. */
public final class McpProgressMonitor extends TaskMonitorAdapter implements AutoCloseable {
    private static final long UPDATE_INTERVAL_NANOS = TimeUnit.MILLISECONDS.toNanos(100);

    private final Object token;
    private final Consumer<McpSchema.ProgressNotification> sender;
    private final LongSupplier nanoClock;
    private long maximum = -1;
    private long progress;
    private String message = "";
    private boolean indeterminate = true;
    private boolean closed;
    private boolean notificationFailed;
    private boolean sent;
    private double lastProgress;
    private long lastSentNanos;

    public McpProgressMonitor(Object token, Consumer<McpSchema.ProgressNotification> sender) {
        this(token, sender, System::nanoTime);
    }

    McpProgressMonitor(Object token, Consumer<McpSchema.ProgressNotification> sender,
            LongSupplier nanoClock) {
        if (!supportsToken(token)) throw new IllegalArgumentException("Progress token must be a string or integer");
        this.token = token;
        this.sender = Objects.requireNonNull(sender, "sender");
        this.nanoClock = Objects.requireNonNull(nanoClock, "nanoClock");
    }

    /** Matches the native scalar types used for integer JSON tokens, preserving their values. */
    public static boolean supportsToken(Object token) {
        return token instanceof String || token instanceof Byte || token instanceof Short ||
            token instanceof Integer || token instanceof Long || token instanceof BigInteger;
    }

    @Override public synchronized void initialize(long total) {
        maximum = total < 0 ? -1 : total;
        progress = 0;
        indeterminate = total < 0;
        publish();
    }

    @Override public synchronized void setMaximum(long total) {
        maximum = total < 0 ? -1 : total;
        indeterminate = total < 0;
        if (maximum >= 0) progress = Math.min(progress, maximum);
    }

    @Override public synchronized long getMaximum() { return maximum; }

    @Override public synchronized void setProgress(long value) {
        long bounded = Math.max(0, maximum >= 0 ? Math.min(value, maximum) : value);
        progress = Math.max(progress, bounded);
        publish();
    }

    @Override public synchronized long getProgress() { return progress; }

    @Override public synchronized void incrementProgress(long amount) {
        setProgress(amount > 0 && progress > Long.MAX_VALUE - amount
            ? Long.MAX_VALUE : progress + amount);
    }

    @Override public synchronized void setMessage(String value) { message = value == null ? "" : value; }
    @Override public synchronized String getMessage() { return message; }
    @Override public synchronized void setIndeterminate(boolean value) { indeterminate = value; }
    @Override public synchronized boolean isIndeterminate() { return indeterminate; }

    private void publish() {
        if (closed || notificationFailed) return;
        double value = progress;
        if (sent && value <= lastProgress) return;
        long now = nanoClock.getAsLong();
        boolean finished = maximum >= 0 && progress == maximum;
        if (sent && !finished && now - lastSentNanos < UPDATE_INTERVAL_NANOS) return;
        sent = true;
        lastProgress = value;
        lastSentNanos = now;
        try {
            sender.accept(new McpSchema.ProgressNotification(token, value,
                maximum >= 0 ? (double) maximum : null, message.isBlank() ? null : message, null));
        } catch (RuntimeException error) {
            // Progress is optional: an unavailable notification channel must not fail the tool.
            notificationFailed = true;
            Msg.warn(this, "Unable to send MCP progress: " + error.getMessage());
        }
    }

    /** Serialize with delivery so the SDK callback cannot run after close has returned. */
    @Override public synchronized void close() { closed = true; }
}

package ghidrassistmcp.tools;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Counts requested items while isolating native decompiler progress and cancellation listeners. */
final class BatchProgressMonitor implements AutoCloseable {
    private final TaskMonitor parent;
    private final int total;
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final CancelledListener parentCancelled = this::cancelActiveItem;
    private volatile ItemMonitor active;
    private int completed;

    BatchProgressMonitor(TaskMonitor parent, int total) {
        this.parent = Objects.requireNonNull(parent);
        if (total < 1) throw new IllegalArgumentException("Batch must contain an item");
        this.total = total;
        parent.initialize(total);
        parent.setIndeterminate(false);
        parent.setProgress(0);
        parent.addCancelledListener(parentCancelled);
        // Cancellation can happen immediately before or during listener registration.
        isCancelled();
    }

    TaskMonitor beginItem(int index, String identifier) {
        if (closed.get()) throw new IllegalStateException("Batch monitor is closed");
        ItemMonitor previous = active;
        if (previous != null) previous.close();
        ItemMonitor next = new ItemMonitor("Decompiling " + (index + 1) + "/" + total + ": " + identifier);
        active = next;
        if (isCancelled()) next.cancelFromParent();
        parent.setMessage(next.label);
        return next;
    }

    void completeItem() {
        ItemMonitor item = active;
        active = null;
        if (item != null) item.close();
        parent.setProgress(++completed);
    }

    boolean isCancelled() {
        if (parent.isCancelled() || Thread.currentThread().isInterrupted()) cancelActiveItem();
        return cancelled.get();
    }

    private void cancelActiveItem() {
        cancelled.set(true);
        ItemMonitor item = active;
        if (item != null) item.cancelFromParent();
    }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        parent.removeCancelledListener(parentCancelled);
        ItemMonitor item = active;
        active = null;
        if (item != null) item.close();
    }

    // Numeric progress and messages deliberately retain TaskMonitorAdapter's local no-op
    // behavior: native initialize/setProgress calls cannot overwrite the batch's i/N count.
    private final class ItemMonitor extends TaskMonitorAdapter implements AutoCloseable {
        private final String label;
        private final Set<CancelledListener> listeners = new LinkedHashSet<>();
        private boolean itemCancelled;
        private boolean disposed;

        ItemMonitor(String label) { this.label = label; }

        @Override public String getMessage() { return label; }
        @Override public boolean isCancelled() { return BatchProgressMonitor.this.isCancelled(); }
        @Override public void checkCancelled() throws CancelledException {
            if (isCancelled()) throw new CancelledException();
        }
        @Override public void cancel() { cancelActiveItem(); }
        @Override public void clearCancelled() { /* Batch cancellation is sticky. */ }
        @Override public void setCancelEnabled(boolean enabled) { /* Native code cannot disable batch cancellation. */ }
        @Override public boolean isCancelEnabled() { return true; }

        @Override public void addCancelledListener(CancelledListener listener) {
            if (listener == null) return;
            boolean notify;
            synchronized (this) {
                if (disposed || !listeners.add(listener)) return;
                notify = itemCancelled;
            }
            if (notify) notifyListener(listener);
        }

        @Override public synchronized void removeCancelledListener(CancelledListener listener) {
            listeners.remove(listener);
        }

        void cancelFromParent() {
            List<CancelledListener> notify;
            synchronized (this) {
                if (disposed || itemCancelled) return;
                itemCancelled = true;
                notify = List.copyOf(listeners);
            }
            // The decompiler registers its stopProcess callback here. Do not dispose the
            // shared session in this callback; its worker closes it in finally.
            for (CancelledListener listener : notify) notifyListener(listener);
        }

        private void notifyListener(CancelledListener listener) {
            try { listener.cancelled(); }
            catch (RuntimeException error) { Msg.warn(this, "Decompiler cancellation listener failed", error); }
        }

        @Override public synchronized void close() {
            disposed = true;
            listeners.clear();
        }
    }
}

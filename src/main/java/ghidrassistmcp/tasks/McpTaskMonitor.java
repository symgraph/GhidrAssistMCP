package ghidrassistmcp.tasks;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

public class McpTaskMonitor implements TaskMonitor {

    private final McpTask task;
    private final int minPercent;
    private final int maxPercent;
    private final String prefix;
    private final List<CancelledListener> listeners = new CopyOnWriteArrayList<>();

    private volatile boolean cancelled;
    private volatile boolean cancelEnabled = true;
    private volatile boolean indeterminate = true;
    private volatile boolean showProgressValue = true;
    private volatile long maximum = NO_PROGRESS_VALUE;
    private volatile long progress;
    private volatile String message = "";

    public McpTaskMonitor(McpTask task, int minPercent, int maxPercent, String prefix) {
        this.task = task;
        this.minPercent = Math.max(0, Math.min(100, minPercent));
        this.maxPercent = Math.max(this.minPercent, Math.min(100, maxPercent));
        this.prefix = prefix != null ? prefix : "";
        publish();
    }

    @Override
    public boolean isCancelled() {
        return cancelled || task.getStatus() == McpTask.Status.CANCELLED ||
            Thread.currentThread().isInterrupted();
    }

    @Override
    public void setShowProgressValue(boolean showProgressValue) {
        this.showProgressValue = showProgressValue;
    }

    @Override
    public void setMessage(String message) {
        this.message = message != null ? message : "";
        publish();
    }

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public void setProgress(long value) {
        progress = Math.max(0, value);
        publish();
    }

    @Override
    public void initialize(long max) {
        maximum = max;
        progress = 0;
        indeterminate = max <= 0;
        publish();
    }

    @Override
    public void setMaximum(long max) {
        maximum = max;
        indeterminate = max <= 0;
        publish();
    }

    @Override
    public long getMaximum() {
        return maximum;
    }

    @Override
    public void setIndeterminate(boolean indeterminate) {
        this.indeterminate = indeterminate;
        publish();
    }

    @Override
    public boolean isIndeterminate() {
        return indeterminate;
    }

    @Override
    public void checkCanceled() throws CancelledException {
        if (isCancelled()) {
            throw new CancelledException();
        }
    }

    @Override
    public void incrementProgress(long incrementAmount) {
        setProgress(progress + incrementAmount);
    }

    @Override
    public long getProgress() {
        return progress;
    }

    @Override
    public void cancel() {
        if (!cancelEnabled || cancelled) {
            return;
        }
        cancelled = true;
        for (CancelledListener listener : listeners) {
            listener.cancelled();
        }
        publish();
    }

    @Override
    public void addCancelledListener(CancelledListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    @Override
    public void removeCancelledListener(CancelledListener listener) {
        listeners.remove(listener);
    }

    @Override
    public void setCancelEnabled(boolean enable) {
        cancelEnabled = enable;
    }

    @Override
    public boolean isCancelEnabled() {
        return cancelEnabled;
    }

    @Override
    public void clearCanceled() {
        cancelled = false;
        publish();
    }

    private void publish() {
        task.updateProgress(mappedPercent(), displayMessage());
    }

    private int mappedPercent() {
        if (indeterminate || maximum <= 0) {
            return minPercent;
        }
        long boundedProgress = Math.max(0, Math.min(progress, maximum));
        double fraction = maximum == 0 ? 0.0 : (double) boundedProgress / (double) maximum;
        return minPercent + (int) Math.round((maxPercent - minPercent) * fraction);
    }

    private String displayMessage() {
        String suffix = message.isBlank() ? "" : " - " + message;
        if (!showProgressValue || indeterminate || maximum <= 0) {
            return prefix + suffix;
        }
        long boundedProgress = Math.max(0, Math.min(progress, maximum));
        return prefix + suffix + " (" + boundedProgress + "/" + maximum + ")";
    }
}

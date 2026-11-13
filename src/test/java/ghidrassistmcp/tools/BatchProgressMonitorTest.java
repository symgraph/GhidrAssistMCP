package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

class BatchProgressMonitorTest {
    @Test void nativeProgressAndMessagesCannotReplaceAggregateCounts() {
        RecordingMonitor parent = new RecordingMonitor();
        try (BatchProgressMonitor batch = new BatchProgressMonitor(parent, 3)) {
            TaskMonitor nativeMonitor = batch.beginItem(0, "first");
            nativeMonitor.initialize(999);
            nativeMonitor.setMaximum(500);
            nativeMonitor.setProgress(450);
            nativeMonitor.incrementProgress(50);
            nativeMonitor.setIndeterminate(true);
            nativeMonitor.setMessage("native phase");
            assertEquals(3, parent.maximum);
            assertEquals(0, parent.progress);
            assertEquals("Decompiling 1/3: first", parent.message);
            batch.completeItem();
            batch.beginItem(1, "alias");
            batch.completeItem();
            batch.beginItem(2, "missing");
            batch.completeItem();
            assertEquals(List.of(3L), parent.initializations);
            assertEquals(List.of(0L, 1L, 2L, 3L), parent.values);
        }
        assertEquals(0, parent.listeners.size());
    }

    @Test void parentCancellationImmediatelyNotifiesNativeAndLateListenersAndStaysSticky() {
        RecordingMonitor parent = new RecordingMonitor();
        try (BatchProgressMonitor batch = new BatchProgressMonitor(parent, 2)) {
            TaskMonitor nativeMonitor = batch.beginItem(0, "first");
            AtomicInteger early = new AtomicInteger();
            AtomicInteger late = new AtomicInteger();
            nativeMonitor.addCancelledListener(early::incrementAndGet);
            nativeMonitor.setCancelEnabled(false);
            parent.cancel();
            assertEquals(1, early.get(), "Cancellation must not wait for a native polling call");
            nativeMonitor.clearCancelled();
            assertTrue(nativeMonitor.isCancelled());
            CancelledListener listener = late::incrementAndGet;
            nativeMonitor.addCancelledListener(listener);
            nativeMonitor.addCancelledListener(listener);
            parent.cancel();
            assertEquals(1, early.get());
            assertEquals(1, late.get());
            assertTrue(batch.isCancelled());
        }
    }

    @Test void cancellationDuringParentRegistrationIsObservedAndCloseUnregistersOnce() {
        RecordingMonitor parent = new RecordingMonitor();
        parent.cancelDuringRegistration = true;
        BatchProgressMonitor batch = new BatchProgressMonitor(parent, 1);
        TaskMonitor child = batch.beginItem(0, "first");
        AtomicInteger calls = new AtomicInteger();
        child.addCancelledListener(calls::incrementAndGet);
        assertEquals(1, calls.get());
        assertTrue(child.isCancelled());
        batch.close();
        batch.close();
        assertEquals(1, parent.removals);
        assertEquals(0, parent.listeners.size());
        parent.cancel();
        assertEquals(1, calls.get());
    }

    @Test void listenerAddedWhileCancellationIsBeingDeliveredIsNotMissedOrDuplicated() throws Exception {
        RecordingMonitor parent = new RecordingMonitor();
        try (BatchProgressMonitor batch = new BatchProgressMonitor(parent, 1);
                var executor = Executors.newSingleThreadExecutor()) {
            TaskMonitor child = batch.beginItem(0, "first");
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            AtomicInteger first = new AtomicInteger();
            AtomicInteger late = new AtomicInteger();
            child.addCancelledListener(() -> {
                first.incrementAndGet();
                entered.countDown();
                try { assertTrue(release.await(5, TimeUnit.SECONDS)); }
                catch (InterruptedException e) { throw new AssertionError(e); }
            });
            var cancellation = executor.submit(parent::cancel);
            try {
                assertTrue(entered.await(2, TimeUnit.SECONDS));
                child.addCancelledListener(late::incrementAndGet);
                assertEquals(1, late.get());
            } finally { release.countDown(); }
            cancellation.get(2, TimeUnit.SECONDS);
            assertEquals(1, first.get());
            assertEquals(1, late.get());
        }
    }

    private static final class RecordingMonitor extends TaskMonitorAdapter {
        final List<CancelledListener> listeners = new CopyOnWriteArrayList<>();
        final List<Long> initializations = new ArrayList<>();
        final List<Long> values = new ArrayList<>();
        volatile boolean cancelled;
        boolean cancelDuringRegistration;
        long maximum;
        long progress;
        String message;
        int removals;
        @Override public void initialize(long max) { maximum = max; initializations.add(max); }
        @Override public void setProgress(long value) { progress = value; values.add(value); }
        @Override public void setMessage(String value) { message = value; }
        @Override public boolean isCancelled() { return cancelled; }
        @Override public void addCancelledListener(CancelledListener listener) {
            listeners.add(listener);
            if (cancelDuringRegistration) cancelled = true;
        }
        @Override public void removeCancelledListener(CancelledListener listener) { listeners.remove(listener); removals++; }
        @Override public void cancel() { cancelled = true; listeners.forEach(CancelledListener::cancelled); }
    }
}

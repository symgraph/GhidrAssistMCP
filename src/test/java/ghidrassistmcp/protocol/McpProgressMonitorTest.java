package ghidrassistmcp.protocol;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import io.modelcontextprotocol.spec.McpSchema;

class McpProgressMonitorTest {
    @Test void acceptsNativeStringAndIntegerTokensWithoutConvertingThem() {
        for (Object token : new Object[] {"", "correlation", (byte) 1, (short) 2, 3, 4L,
                new BigInteger("123456789012345678901234567890")}) {
            List<McpSchema.ProgressNotification> updates = new ArrayList<>();
            assertTrue(McpProgressMonitor.supportsToken(token));
            try (McpProgressMonitor monitor = new McpProgressMonitor(token, updates::add)) {
                monitor.initialize(1);
                monitor.setProgress(1);
            }
            assertEquals(2, updates.size());
            assertSame(token, updates.getFirst().progressToken());
            assertSame(token, updates.getLast().progressToken());
        }
    }

    @Test void rejectsMissingAndUnsupportedTokensAndMissingSender() {
        for (Object token : new Object[] {null, true, 1.5, Double.NaN, new BigDecimal("1.5"),
                List.of("token"), Map.of("token", "value")}) {
            assertFalse(McpProgressMonitor.supportsToken(token));
            assertThrows(IllegalArgumentException.class, () -> new McpProgressMonitor(token, ignored -> { }));
        }
        assertThrows(NullPointerException.class, () -> new McpProgressMonitor("token", null));
    }

    @Test void sendsInitialZeroCoalescesIntermediateUpdatesAndAlwaysSendsFinalTotal() {
        List<McpSchema.ProgressNotification> updates = new ArrayList<>();
        AtomicLong now = new AtomicLong();
        try (McpProgressMonitor monitor = new McpProgressMonitor("token", updates::add, now::get)) {
            monitor.initialize(5);
            monitor.setProgress(1);
            now.set(99_999_999);
            monitor.setProgress(2);
            assertEquals(List.of(0.0), values(updates));
            now.set(100_000_000);
            monitor.setMessage("Third function");
            monitor.setProgress(3);
            monitor.setProgress(4);
            monitor.setProgress(5);
            assertEquals(List.of(0.0, 3.0, 5.0), values(updates));
            assertEquals("Third function", updates.get(1).message());
            assertTrue(updates.stream().allMatch(update -> Double.valueOf(5).equals(update.total())));
        }
    }

    @Test void suppressesSameRegressiveAndMessageOnlyUpdatesAndClampsAtTotal() {
        List<McpSchema.ProgressNotification> updates = new ArrayList<>();
        AtomicLong now = new AtomicLong();
        try (McpProgressMonitor monitor = new McpProgressMonitor(7, updates::add, now::get)) {
            monitor.initialize(3);
            now.set(100_000_000);
            monitor.setProgress(2);
            monitor.setMessage("Only a message change");
            monitor.setProgress(2);
            monitor.setProgress(1);
            monitor.setProgress(-10);
            monitor.initialize(3);
            monitor.setProgress(9);
            monitor.setProgress(20);
            assertEquals(List.of(0.0, 2.0, 3.0), values(updates));
            assertEquals(3, monitor.getProgress());
            assertEquals("Only a message change", updates.getLast().message());
        }
    }

    @Test void closePreventsAllLaterNotificationsWithoutInventingCompletion() {
        List<McpSchema.ProgressNotification> updates = new ArrayList<>();
        AtomicLong now = new AtomicLong();
        McpProgressMonitor monitor = new McpProgressMonitor("token", updates::add, now::get);
        monitor.initialize(4);
        now.set(100_000_000);
        monitor.incrementProgress(1);
        monitor.close();
        monitor.close();
        monitor.setMessage("After close");
        monitor.setProgress(4);
        monitor.initialize(10);
        monitor.setProgress(10);
        assertEquals(List.of(0.0, 1.0), values(updates));
    }

    @Test void notificationFailureDoesNotFailOrCancelComputationAndStopsRetryFloods() {
        AtomicInteger attempts = new AtomicInteger();
        try (McpProgressMonitor monitor = new McpProgressMonitor("token", update -> {
            attempts.incrementAndGet();
            throw new IllegalStateException("Channel closed");
        })) {
            assertDoesNotThrow(() -> monitor.initialize(2));
            assertDoesNotThrow(() -> monitor.setProgress(1));
            assertDoesNotThrow(() -> monitor.setProgress(2));
            assertFalse(monitor.isCancelled());
            assertEquals(2, monitor.getProgress());
            assertEquals(1, attempts.get());
        }
    }

    @Test void indeterminateProgressOmitsTotalAndSaturatesIncrementOverflow() {
        List<McpSchema.ProgressNotification> updates = new ArrayList<>();
        AtomicLong now = new AtomicLong();
        try (McpProgressMonitor monitor = new McpProgressMonitor("token", updates::add, now::get)) {
            monitor.initialize(-1);
            assertTrue(monitor.isIndeterminate());
            now.set(100_000_000);
            monitor.setProgress(Long.MAX_VALUE - 1);
            now.set(200_000_000);
            monitor.incrementProgress(10);
            assertEquals(Long.MAX_VALUE, monitor.getProgress());
            assertTrue(updates.stream().allMatch(update -> update.total() == null));
            assertTrue(updates.getLast().progress() > updates.getFirst().progress());
        }
    }

    @Test void emptyWorkHasOneZeroNotificationAndNoFabricatedAdditionalProgress() {
        List<McpSchema.ProgressNotification> updates = new ArrayList<>();
        try (McpProgressMonitor monitor = new McpProgressMonitor("token", updates::add)) {
            monitor.initialize(0);
            monitor.setProgress(4);
            assertEquals(List.of(0.0), values(updates));
            assertEquals(0.0, updates.getFirst().total());
            assertFalse(monitor.isIndeterminate());
        }
    }

    private static List<Double> values(List<McpSchema.ProgressNotification> updates) {
        return updates.stream().map(McpSchema.ProgressNotification::progress).toList();
    }
}

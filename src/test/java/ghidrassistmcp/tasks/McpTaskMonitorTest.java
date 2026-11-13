package ghidrassistmcp.tasks;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;

import org.junit.jupiter.api.Test;

class McpTaskMonitorTest {
    @Test
    void unfinishedWorkCannotRoundUpToTheTerminalPercentage() {
        McpTask task = runningTask();
        McpTaskMonitor monitor = new McpTaskMonitor(task, 0, 100, "Items");
        monitor.initialize(200);
        monitor.setProgress(199);
        assertEquals(99, task.getProgressPercent());
        monitor.setProgress(200);
        assertEquals(100, task.getProgressPercent());
    }

    @Test
    void roundedIntermediateValuesAndSubrangeEndpointsArePreserved() {
        McpTask task = runningTask();
        McpTaskMonitor monitor = new McpTaskMonitor(task, 0, 100, "Items");
        monitor.initialize(3);
        monitor.setProgress(1);
        assertEquals(33, task.getProgressPercent());
        monitor.setProgress(2);
        assertEquals(67, task.getProgressPercent());

        monitor = new McpTaskMonitor(task, 20, 40, "Phase");
        monitor.initialize(200);
        monitor.setProgress(199);
        assertEquals(39, task.getProgressPercent());
        monitor.setProgress(200);
        assertEquals(40, task.getProgressPercent());

        monitor = new McpTaskMonitor(task, 33, 33, "Zero-width phase");
        monitor.initialize(200);
        monitor.setProgress(199);
        assertEquals(33, task.getProgressPercent());
    }

    @Test
    void floatingPointPrecisionCannotCompleteAnUnfinishedLongCounter() {
        McpTask task = runningTask();
        McpTaskMonitor monitor = new McpTaskMonitor(task, 0, 100, "Large items");
        monitor.initialize(Long.MAX_VALUE);
        monitor.setProgress(Long.MAX_VALUE - 1);
        assertEquals(99, task.getProgressPercent());
        monitor.setProgress(Long.MAX_VALUE);
        assertEquals(100, task.getProgressPercent());
    }

    private static McpTask runningTask() {
        McpTask task = new McpTask("monitor-test", Map.of());
        task.markStarted();
        return task;
    }
}

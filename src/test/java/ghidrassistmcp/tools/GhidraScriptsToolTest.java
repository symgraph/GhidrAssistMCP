package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

class GhidraScriptsToolTest {
    @Test void distinctScriptLoadersCannotOverlap() throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(2);
        CountDownLatch firstLoading = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch secondAttempted = new CountDownLatch(1);
        CountDownLatch secondLoading = new CountDownLatch(1);
        try {
            Future<?> first = workers.submit(() -> GhidraScriptsTool.loadScriptInstance(() -> {
                firstLoading.countDown();
                await(releaseFirst);
                return null;
            }));
            await(firstLoading);
            Future<?> second = workers.submit(() -> {
                secondAttempted.countDown();
                return GhidraScriptsTool.loadScriptInstance(() -> {
                    secondLoading.countDown();
                    return null;
                });
            });
            await(secondAttempted);
            assertFalse(secondLoading.await(100, TimeUnit.MILLISECONDS),
                "Different script names still share Ghidra's compilation bundle");
            releaseFirst.countDown();
            first.get(2, TimeUnit.SECONDS);
            second.get(2, TimeUnit.SECONDS);
            assertEquals(0, secondLoading.getCount());
        } finally {
            releaseFirst.countDown();
            stop(workers);
        }
    }

    @Test void scriptWorkAfterLoadingDoesNotBlockAnotherLoad() throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(2);
        CountDownLatch firstExecuting = new CountDownLatch(1);
        CountDownLatch releaseExecution = new CountDownLatch(1);
        try {
            Future<?> first = workers.submit(() -> {
                GhidraScriptsTool.loadScriptInstance(() -> null);
                // Model a long-running script after getScriptInstance has returned.
                firstExecuting.countDown();
                await(releaseExecution);
                return null;
            });
            await(firstExecuting);
            Future<?> second = workers.submit(() -> GhidraScriptsTool.loadScriptInstance(() -> null));
            second.get(2, TimeUnit.SECONDS);
            assertFalse(first.isDone(), "Actual script execution must remain concurrent");
            releaseExecution.countDown();
            first.get(2, TimeUnit.SECONDS);
        } finally {
            releaseExecution.countDown();
            stop(workers);
        }
    }

    @Test void loaderFailureIsPreservedAndReleasesTheGate() throws Exception {
        Exception failure = new Exception("compile failed");
        assertSame(failure, assertThrows(Exception.class,
            () -> GhidraScriptsTool.loadScriptInstance(() -> { throw failure; })));
        assertAnotherThreadCanLoad();

        AssertionError error = new AssertionError("provider error");
        assertSame(error, assertThrows(AssertionError.class,
            () -> GhidraScriptsTool.loadScriptInstance(() -> { throw error; })));
        assertAnotherThreadCanLoad();
    }

    @Test void cancelledWaiterNeverInvokesItsLoaderOrUnlocksTheActiveLoad() throws Exception {
        ExecutorService workers = Executors.newSingleThreadExecutor();
        CountDownLatch firstLoading = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch waiterAttempted = new CountDownLatch(1);
        AtomicBoolean invoked = new AtomicBoolean();
        AtomicReference<Throwable> waitFailure = new AtomicReference<>();
        Thread waiter = new Thread(() -> {
            waiterAttempted.countDown();
            try {
                GhidraScriptsTool.loadScriptInstance(() -> {
                    invoked.set(true);
                    return null;
                });
            } catch (Throwable failure) {
                waitFailure.set(failure);
            }
        }, "cancelled-script-loader-test");
        try {
            Future<?> first = workers.submit(() -> GhidraScriptsTool.loadScriptInstance(() -> {
                firstLoading.countDown();
                await(releaseFirst);
                return null;
            }));
            await(firstLoading);
            waiter.start();
            await(waiterAttempted);
            waiter.interrupt();
            waiter.join(2000);
            assertFalse(waiter.isAlive(), "Cancellation must not wait for compilation to finish");
            assertInstanceOf(InterruptedException.class, waitFailure.get());
            assertFalse(invoked.get());
            assertFalse(first.isDone());
            releaseFirst.countDown();
            first.get(2, TimeUnit.SECONDS);
            assertAnotherThreadCanLoad();
        } finally {
            releaseFirst.countDown();
            waiter.interrupt();
            waiter.join(2000);
            stop(workers);
        }
    }

    @Test void alreadyInterruptedCallerDoesNotEnterEvenAnAvailableGate() throws Exception {
        AtomicBoolean invoked = new AtomicBoolean();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread caller = new Thread(() -> {
            Thread.currentThread().interrupt();
            try {
                GhidraScriptsTool.loadScriptInstance(() -> {
                    invoked.set(true);
                    return null;
                });
            } catch (Throwable caught) {
                failure.set(caught);
            }
        }, "interrupted-script-loader-test");
        caller.start();
        caller.join(2000);
        assertFalse(caller.isAlive());
        assertInstanceOf(InterruptedException.class, failure.get());
        assertFalse(invoked.get());
        assertAnotherThreadCanLoad();
    }

    private static void assertAnotherThreadCanLoad() throws Exception {
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            worker.submit(() -> GhidraScriptsTool.loadScriptInstance(() -> null))
                .get(2, TimeUnit.SECONDS);
        } finally {
            stop(worker);
        }
    }

    private static void await(CountDownLatch latch) throws InterruptedException {
        assertTrue(latch.await(5, TimeUnit.SECONDS), "Timed out waiting for test coordination");
    }

    private static void stop(ExecutorService workers) throws InterruptedException {
        workers.shutdownNow();
        assertTrue(workers.awaitTermination(2, TimeUnit.SECONDS), "Script test worker did not stop");
    }
}

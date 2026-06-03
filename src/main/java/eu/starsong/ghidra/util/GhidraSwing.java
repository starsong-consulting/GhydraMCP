package eu.starsong.ghidra.util;

import ghidra.util.Swing;
import ghidra.util.exception.UnableToSwingException;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Marshals read-only program-database access onto the Swing/EDT thread.
 *
 * <p>Ghidra's database is single-threaded by convention: writes go through the EDT
 * (see {@link TransactionHelper}) and the UI reads/renders on the EDT. Individual DB
 * calls self-lock via the internal {@code ghidra.util.Lock}, but compound reads -
 * iterating {@code getFunctions(true)}, walking the listing, scanning symbols/xrefs -
 * release that lock between records. A pool-thread iteration interleaving with EDT
 * activity leaves buffer nodes checked out and throws {@code IOException: Locked buffer}.
 *
 * <p>Running the traversal on the EDT via {@link Swing#runNow} removes the interleaving.
 * {@code runNow} executes inline when already on the EDT, so this helper is reentrant and
 * safe to nest. Long, self-managed operations (the decompiler's {@code DecompInterface},
 * {@code AutoAnalysisManager}) handle their own program access and must NOT be wrapped -
 * doing so would freeze the UI for their full duration.
 */
public final class GhidraSwing {

    private static final long READ_TIMEOUT_SECONDS = Long.getLong("ghidra.mcp.read.timeout", 900);

    private GhidraSwing() {
    }

    @FunctionalInterface
    public interface ReadOperation<T> {
        T get() throws Exception;
    }

    /**
     * Runs a read-only operation on the Swing thread and returns its result.
     *
     * @throws ReadException if the operation throws, or the EDT cannot be reached in time
     */
    public static <T> T runRead(ReadOperation<T> operation) {
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<RuntimeException> runtimeError = new AtomicReference<>();
        AtomicReference<Exception> checkedError = new AtomicReference<>();

        Runnable task = () -> {
            try {
                result.set(operation.get());
            } catch (RuntimeException e) {
                runtimeError.set(e);
            } catch (Exception e) {
                checkedError.set(e);
            }
        };

        try {
            Swing.runNow(task, READ_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (UnableToSwingException e) {
            throw new ReadException(
                "Timed out after " + READ_TIMEOUT_SECONDS + "s waiting for the Swing thread", e);
        }

        if (runtimeError.get() != null) {
            throw runtimeError.get();
        }
        if (checkedError.get() != null) {
            throw new ReadException(checkedError.get().getMessage(), checkedError.get());
        }
        return result.get();
    }

    /**
     * Runs a read-only operation on the Swing thread with no return value.
     */
    public static void runRead(Runnable operation) {
        runRead(() -> {
            operation.run();
            return null;
        });
    }

    public static class ReadException extends RuntimeException {
        public ReadException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

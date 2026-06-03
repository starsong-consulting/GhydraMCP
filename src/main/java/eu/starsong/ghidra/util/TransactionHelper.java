package eu.starsong.ghidra.util;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class TransactionHelper {

    private static final long EDT_TIMEOUT_SECONDS = Long.getLong("ghidra.mcp.write.timeout", 900);

    @FunctionalInterface
    public interface GhidraSupplier<T> {
        T get() throws Exception;
    }

    public static <T> T executeInTransaction(Program program, String transactionName, GhidraSupplier<T> operation)
        throws TransactionException {

        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null for transaction");
        }
        if (!program.isChangeable()) {
            throw new TransactionException(
                "Program is not changeable (read-only/locked); cannot perform: " + transactionName);
        }

        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Exception> exception = new AtomicReference<>();
        // Ghidra calls this callback with the tx id if the transaction was explicitly aborted
        // (rollback). A null value after endTransaction means the transaction committed; a
        // false return from endTransaction WITHOUT this being set means we nested inside
        // another transaction — that's normal and not a failure.
        AtomicReference<Long> abortedTxId = new AtomicReference<>();

        try {
            // Bounded so a wedged EDT can't block the calling worker thread forever.
            // Swing.runNow runs inline when already on the EDT, so this is reentrant.
            Swing.runNow(() -> {
                int txId = -1;
                boolean success = false;
                try {
                    txId = program.startTransaction(transactionName, abortedTxId::set);
                    if (txId < 0) {
                        throw new TransactionException("Failed to start transaction: " + transactionName);
                    }
                    result.set(operation.get());
                    success = true;
                } catch (Exception e) {
                    exception.set(e);
                    Msg.error(TransactionHelper.class, "Transaction failed: " + transactionName, e);
                } finally {
                    if (txId >= 0) {
                        boolean ended = program.endTransaction(txId, success);
                        // Only treat `!ended` as a real failure when our transaction was
                        // explicitly aborted. Otherwise Ghidra returned false because we
                        // nested inside another open transaction (auto-analysis in particular).
                        if (!ended && abortedTxId.get() != null) {
                            Msg.error(TransactionHelper.class,
                                "Transaction aborted: " + transactionName + " (txId=" + abortedTxId.get() + ")");
                            if (exception.get() == null) {
                                exception.set(new TransactionException(
                                    "Transaction aborted: " + transactionName));
                            }
                        }
                    }
                }
            }, EDT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new TransactionException("Swing thread execution failed", e);
        }

        if (exception.get() != null) {
            throw new TransactionException("Operation failed", exception.get());
        }
        return result.get();
    }

    public static class TransactionException extends Exception {
        public TransactionException(String message) { super(message); }
        public TransactionException(String message, Throwable cause) { super(message, cause); }
    }
}

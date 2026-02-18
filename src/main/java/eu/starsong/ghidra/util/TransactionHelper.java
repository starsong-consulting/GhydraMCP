package eu.starsong.ghidra.util;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

public class TransactionHelper {

    private static final long EDT_TIMEOUT_SECONDS = Long.getLong("ghidra.mcp.edt.timeout", 900);
    private static final ExecutorService edtExecutor = Executors.newCachedThreadPool();

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
        AtomicReference<Long> abortedTxId = new AtomicReference<>();

        Runnable edtTask = () -> {
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
                    if (!program.endTransaction(txId, success)) {
                        String details = buildEndTransactionFailureDetails(program, transactionName, txId, success,
                            abortedTxId.get());
                        Msg.error(TransactionHelper.class, details);
                        TransactionException endTxException =
                            new TransactionException(details);
                        Exception existing = exception.get();
                        if (existing != null) {
                            existing.addSuppressed(endTxException);
                        } else {
                            exception.set(endTxException);
                        }
                    }
                }
            }
        };

        try {
            Future<?> future = edtExecutor.submit(() -> {
                try {
                    SwingUtilities.invokeAndWait(edtTask);
                } catch (Exception e) {
                    exception.set(e);
                }
            });

            future.get(EDT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new TransactionException(
                "EDT timeout after " + EDT_TIMEOUT_SECONDS + "s waiting for: " + transactionName);
        } catch (Exception e) {
            if (exception.get() != null) {
                throw new TransactionException("Swing thread execution failed", exception.get());
            }
            throw new TransactionException("Swing thread execution failed", e);
        }

        if (exception.get() != null) {
            Exception cause = exception.get();
            String causeMsg = cause.getMessage();
            if (causeMsg == null || causeMsg.isEmpty()) {
                causeMsg = cause.getClass().getSimpleName();
            }
            if (cause.getSuppressed().length > 0) {
                List<String> suppressed = new ArrayList<>();
                for (Throwable t : cause.getSuppressed()) {
                    if (t == null) {
                        continue;
                    }
                    String msg = t.getMessage();
                    if (msg == null || msg.isEmpty()) {
                        msg = t.getClass().getSimpleName();
                    }
                    suppressed.add(msg);
                }
                if (!suppressed.isEmpty()) {
                    causeMsg = causeMsg + " | Suppressed: " + String.join("; ", suppressed);
                }
            }
            throw new TransactionException("Operation failed: " + causeMsg, cause);
        }
        return result.get();
    }

    private static String buildEndTransactionFailureDetails(
        Program program,
        String transactionName,
        int txId,
        boolean successRequested,
        Long abortedId) {

        StringBuilder sb = new StringBuilder();
        sb.append("Failed to end transaction: ").append(transactionName)
            .append(" (txId=").append(txId)
            .append(", successRequested=").append(successRequested);

        try {
            sb.append(", changeable=").append(program.isChangeable());
        } catch (Exception ignored) {
            // Best effort
        }
        try {
            sb.append(", terminated=").append(program.hasTerminatedTransaction());
        } catch (Exception ignored) {
            // Best effort
        }
        try {
            sb.append(", closed=").append(program.isClosed());
        } catch (Exception ignored) {
            // Best effort
        }
        if (abortedId != null) {
            sb.append(", abortedTxId=").append(abortedId);
        }
        sb.append(")");

        return sb.toString();
    }

    public static class TransactionException extends Exception {
        public TransactionException(String message) { super(message); }
        public TransactionException(String message, Throwable cause) { super(message, cause); }
    }
}

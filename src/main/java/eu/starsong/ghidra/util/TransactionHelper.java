package eu.starsong.ghidra.util;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicReference;

public class TransactionHelper {
    
    @FunctionalInterface
    public interface GhidraSupplier<T> {
        T get() throws Exception;
    }

    public static <T> T executeInTransaction(Program program, String transactionName, GhidraSupplier<T> operation) 
        throws TransactionException {
        
        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null for transaction");
        }

        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Exception> exception = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = -1;
                boolean success = false;
                try {
                    txId = program.startTransaction(transactionName);
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
                            Msg.error(TransactionHelper.class, "Failed to end transaction: " + transactionName);
                            exception.set(new TransactionException("Failed to end transaction: " + transactionName));
                        }
                    }
                }
            });
        } catch (Exception e) {
            throw new TransactionException("Swing thread execution failed", e);
        }

        if (exception.get() != null) {
            String causeMsg = exception.get().getMessage();
            throw new TransactionException("Operation failed: " + causeMsg, exception.get());
        }
        return result.get();
    }

    public static class TransactionException extends Exception {
        public TransactionException(String message) { super(message); }
        public TransactionException(String message, Throwable cause) { super(message, cause); }
    }
}

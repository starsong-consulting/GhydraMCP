package eu.starsong.ghidra.util;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * LRU cache for DecompileResults keyed by function entry-point Address.
 * Keeps a single long-lived DecompInterface and reuses it across requests.
 *
 * Thread safety:
 * - Cache lookups are lock-free (synchronizedMap).
 * - Decompilation is serialized via decompLock (only one decompile at a time).
 * - Implements DomainObjectListener to invalidate on any program change.
 */
public class DecompilerCache implements DomainObjectListener {

    private static final int MAX_ENTRIES = 50;

    private final Map<Address, DecompileResults> cache;
    private final ReentrantLock decompLock = new ReentrantLock();

    private Program currentProgram;
    private DecompInterface decompiler;

    public DecompilerCache() {
        this.cache = Collections.synchronizedMap(
            new LinkedHashMap<Address, DecompileResults>(MAX_ENTRIES + 1, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<Address, DecompileResults> eldest) {
                    return size() > MAX_ENTRIES;
                }
            }
        );
    }

    /**
     * Get cached DecompileResults for a function, decompiling on cache miss.
     */
    public DecompileResults getDecompileResults(Function function, int timeout) {
        if (function == null) {
            return null;
        }

        Program program = function.getProgram();
        ensureProgram(program);

        Address entry = function.getEntryPoint();
        DecompileResults cached = cache.get(entry);
        if (cached != null) {
            return cached;
        }

        decompLock.lock();
        try {
            // Double-check after acquiring lock
            cached = cache.get(entry);
            if (cached != null) {
                return cached;
            }

            ensureDecompiler(program);
            DecompileResults results = decompiler.decompileFunction(function, timeout, TaskMonitor.DUMMY);
            if (results != null) {
                cache.put(entry, results);
            }
            return results;
        } catch (Exception e) {
            Msg.error(this, "Decompilation failed for " + function.getName(), e);
            return null;
        } finally {
            decompLock.unlock();
        }
    }

    /**
     * Convenience: get decompiled C code for a function.
     */
    public String getDecompiledCode(Function function, int timeout) {
        DecompileResults results = getDecompileResults(function, timeout);
        if (results != null && results.decompileCompleted()) {
            return results.getDecompiledFunction().getC();
        }
        if (results != null) {
            Msg.warn(this, "Decompilation did not complete for " + function.getName());
        }
        return null;
    }

    /**
     * Invalidate a single function's cached results (e.g. after a variable rename).
     */
    public void invalidate(Address functionAddress) {
        cache.remove(functionAddress);
    }

    /**
     * Clear the entire cache.
     */
    public void clear() {
        cache.clear();
    }

    /**
     * Dispose the decompiler and unregister listener. Call on plugin shutdown.
     */
    public void dispose() {
        decompLock.lock();
        try {
            cache.clear();
            disposeDecompiler();
            if (currentProgram != null) {
                currentProgram.removeListener(this);
                currentProgram = null;
            }
        } finally {
            decompLock.unlock();
        }
    }

    // --- DomainObjectListener ---

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
        cache.clear();
    }

    // --- Internal ---

    private void ensureProgram(Program program) {
        if (program == currentProgram) {
            return;
        }

        decompLock.lock();
        try {
            if (program == currentProgram) {
                return;
            }
            // Program switched — tear down old state
            cache.clear();
            disposeDecompiler();
            if (currentProgram != null) {
                currentProgram.removeListener(this);
            }
            currentProgram = program;
            if (currentProgram != null) {
                currentProgram.addListener(this);
            }
        } finally {
            decompLock.unlock();
        }
    }

    private void ensureDecompiler(Program program) {
        if (decompiler != null) {
            return;
        }
        decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.setEliminateUnreachable(true);
        options.grabFromProgram(program);
        decompiler.setOptions(options);
        decompiler.openProgram(program);
    }

    private void disposeDecompiler() {
        if (decompiler != null) {
            try {
                decompiler.dispose();
            } catch (Exception e) {
                Msg.warn(this, "Error disposing decompiler", e);
            }
            decompiler = null;
        }
    }
}

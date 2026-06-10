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
 * LRU cache of {@link DecompileResults} keyed by function entry-point address, backed by a
 * single long-lived {@link DecompInterface} that is reused across requests (re-opening the
 * program per call is the expensive part of decompilation).
 *
 * <p>Decompilation runs OFF the Swing/EDT thread — the decompiler manages its own threading,
 * so callers must NOT wrap these calls in {@code GhidraSwing.runRead}. Concurrent decompiles
 * are serialised via {@code decompLock}. The cache invalidates itself on any program change
 * (so results are never stale after a rename/retype) and resets when the program switches.
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
     * Cached decompile of a function, decompiling on a miss.
     */
    public DecompileResults getDecompileResults(Program program, Function function, int timeout) {
        if (function == null) {
            return null;
        }
        // Everything (program check, cache lookup, decompile) runs under decompLock.
        // A lock-free fast path raced program switches: thread A could read a cached
        // result keyed by program A's address while thread B was mid-switch to program B,
        // leaving the decompiler attached to a closed program (ClosedException in the field).
        decompLock.lock();
        try {
            ensureProgram(program);
            Address entry = function.getEntryPoint();
            DecompileResults cached = cache.get(entry);
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

    /** Drop a single function's cached results. */
    public void invalidate(Address functionAddress) {
        cache.remove(functionAddress);
    }

    /** Dispose the decompiler and unregister the listener. Call on shutdown. */
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

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
        // Any program change can invalidate decompiled output; clear conservatively.
        cache.clear();
    }

    private void ensureProgram(Program program) {
        if (program == currentProgram) {
            return;
        }
        decompLock.lock();
        try {
            if (program == currentProgram) {
                return;
            }
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

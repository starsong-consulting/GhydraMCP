package eu.starsong.ghidra.util;

    @FunctionalInterface
    public interface GhidraSupplier<T> {
        T get() throws Exception;
    }

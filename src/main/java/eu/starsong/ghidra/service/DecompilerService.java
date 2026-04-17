package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.DecompileResultDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * Service for decompilation operations.
 */
public class DecompilerService {

    private static final int DEFAULT_TIMEOUT = 60;

    private final FunctionService functionService;

    public DecompilerService(FunctionService functionService) {
        this.functionService = functionService;
    }

    public DecompilerService() {
        this.functionService = new FunctionService();
    }

    /**
     * Decompile a function by its address.
     */
    public DecompileResultDto decompile(Program program, String addressStr) {
        return decompile(program, addressStr, DEFAULT_TIMEOUT);
    }

    /**
     * Decompile a function by its address with a custom timeout.
     */
    public DecompileResultDto decompile(Program program, String addressStr, int timeout) {
        Function function = functionService.findByAddress(program, addressStr);
        if (function == null) {
            throw new NotFoundException("Function not found at address: " + addressStr, "FUNCTION_NOT_FOUND");
        }

        return decompileFunction(program, function, timeout);
    }

    /**
     * Decompile a function by its name.
     */
    public DecompileResultDto decompileByName(Program program, String name) {
        return decompileByName(program, name, DEFAULT_TIMEOUT);
    }

    /**
     * Decompile a function by its name with a custom timeout.
     */
    public DecompileResultDto decompileByName(Program program, String name, int timeout) {
        Function function = functionService.findByName(program, name);
        if (function == null) {
            throw new NotFoundException("Function not found with name: " + name, "FUNCTION_NOT_FOUND");
        }

        return decompileFunction(program, function, timeout);
    }

    /**
     * Decompile a Ghidra Function.
     */
    public DecompileResultDto decompileFunction(Program program, Function function, int timeout) {
        String functionName = function.getName();
        String functionAddress = function.getEntryPoint().toString();

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);

            DecompileResults results = decompiler.decompileFunction(
                function,
                timeout,
                new ConsoleTaskMonitor()
            );

            if (!results.decompileCompleted()) {
                String error = results.getErrorMessage();
                if (error == null || error.isEmpty()) {
                    error = "Decompilation did not complete";
                }
                return DecompileResultDto.failure(functionName, functionAddress, error);
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return DecompileResultDto.failure(functionName, functionAddress, "No high-level function available");
            }

            String decompilation = results.getDecompiledFunction().getC();
            if (decompilation == null || decompilation.isEmpty()) {
                return DecompileResultDto.failure(functionName, functionAddress, "Empty decompilation result");
            }

            return DecompileResultDto.success(functionName, functionAddress, decompilation);

        } catch (Exception e) {
            Msg.error(this, "Error decompiling function " + functionName, e);
            return DecompileResultDto.failure(functionName, functionAddress, "Decompilation error: " + e.getMessage());
        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Get the high-level function (P-Code) for a function.
     * This is useful for more advanced analysis.
     */
    public HighFunction getHighFunction(Program program, Function function, int timeout) {
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);

            DecompileResults results = decompiler.decompileFunction(
                function,
                timeout,
                new ConsoleTaskMonitor()
            );

            if (!results.decompileCompleted()) {
                return null;
            }

            return results.getHighFunction();

        } catch (Exception e) {
            Msg.error(this, "Error getting high function for " + function.getName(), e);
            return null;
        } finally {
            decompiler.dispose();
        }
    }
}

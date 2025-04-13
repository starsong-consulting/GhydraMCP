package eu.starsong.ghidra.util;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GhidraUtil {

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    public static int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }
    
    /**
     * Finds a data type by name within the program's data type managers.
     * @param program The current program.
     * @param dataTypeName The name of the data type to find.
     * @return The found DataType, or null if not found.
     */
    public static DataType findDataType(Program program, String dataTypeName) {
        if (program == null || dataTypeName == null || dataTypeName.isEmpty()) {
            return null;
        }
        DataTypeManager dtm = program.getDataTypeManager();
        List<DataType> foundTypes = new ArrayList<>();
        dtm.findDataTypes(dataTypeName, foundTypes);

        if (!foundTypes.isEmpty()) {
            // Prefer the first match, might need more sophisticated logic
            // if multiple types with the same name exist in different categories.
            return foundTypes.get(0); 
        } else {
            Msg.warn(GhidraUtil.class, "Data type not found: " + dataTypeName);
            return null;
        }
    }
    
    /**
     * Gets the current address as a string from the Ghidra tool.
     * @param tool The Ghidra plugin tool.
     * @return The current address as a string, or null if not available.
     */
    public static String getCurrentAddressString(PluginTool tool) {
        if (tool == null) {
            return null;
        }
        
        // Get current program
        ProgramManager programManager = tool.getService(ProgramManager.class);
        if (programManager == null) {
            return null;
        }
        
        Program program = programManager.getCurrentProgram();
        if (program == null) {
            return null;
        }
        
        // Get the current cursor location using CodeViewerService
        ghidra.app.services.CodeViewerService codeViewerService = tool.getService(ghidra.app.services.CodeViewerService.class);
        if (codeViewerService == null) {
            // Fallback to program's entry point if service not available
            return program.getImageBase().toString();
        }
        
        ghidra.program.util.ProgramLocation currentLocation = codeViewerService.getCurrentLocation();
        if (currentLocation == null) {
            // Fallback to program's entry point if location not available
            return program.getImageBase().toString();
        }
        
        // Return the current address
        return currentLocation.getAddress().toString();
    }
    
    /**
     * Gets information about the current function in the Ghidra tool.
     * @param tool The Ghidra plugin tool.
     * @param program The current program.
     * @return A map containing information about the current function, or an empty map if not available.
     */
    public static Map<String, Object> getCurrentFunctionInfo(PluginTool tool, Program program) {
        Map<String, Object> result = new HashMap<>();
        
        if (tool == null || program == null) {
            return result;
        }
        
        // Get the current cursor location using CodeViewerService
        ghidra.app.services.CodeViewerService codeViewerService = tool.getService(ghidra.app.services.CodeViewerService.class);
        if (codeViewerService == null) {
            return result;
        }
        
        ghidra.program.util.ProgramLocation currentLocation = codeViewerService.getCurrentLocation();
        if (currentLocation == null) {
            return result;
        }
        
        // Get the function at the current location
        Address currentAddress = currentLocation.getAddress();
        FunctionManager functionManager = program.getFunctionManager();
        Function function = functionManager.getFunctionContaining(currentAddress);
        
        if (function == null) {
            // If we couldn't find a function at the current address, return the first function as a fallback
            for (Function f : functionManager.getFunctions(true)) {
                function = f;
                break;
            }
            
            if (function == null) {
                return result;
            }
        }
        
        // Build the function info
        result.put("name", function.getName());
        result.put("address", function.getEntryPoint().toString());
        result.put("signature", function.getSignature().getPrototypeString());
        
        // Add more details
        if (function.getReturnType() != null) {
            result.put("returnType", function.getReturnType().getName());
        }
        
        if (function.getCallingConventionName() != null) {
            result.put("callingConvention", function.getCallingConventionName());
        }
        
        // Add parameters
        List<Map<String, String>> parameters = new ArrayList<>();
        for (Parameter param : function.getParameters()) {
            Map<String, String> paramInfo = new HashMap<>();
            paramInfo.put("name", param.getName());
            paramInfo.put("type", param.getDataType().getName());
            parameters.add(paramInfo);
        }
        result.put("parameters", parameters);
        
        return result;
    }
    
    /**
     * Gets information about a function by its name or address.
     * @param program The current program.
     * @param addressOrName The function address or name.
     * @return A map containing information about the function, or null if not found.
     */
    public static Map<String, Object> getFunctionInfoByAddress(Program program, String addressOrName) {
        if (program == null || addressOrName == null || addressOrName.isEmpty()) {
            return null;
        }
        
        Function function = null;
        
        // First try to interpret as an address
        try {
            Address address = program.getAddressFactory().getAddress(addressOrName);
            if (address != null) {
                function = program.getFunctionManager().getFunctionAt(address);
                if (function == null) {
                    function = program.getFunctionManager().getFunctionContaining(address);
                }
            }
        } catch (Exception e) {
            // Not a valid address, try as a name
            Msg.debug(GhidraUtil.class, "Could not interpret as address: " + addressOrName);
        }
        
        // If not found by address, try by name
        if (function == null) {
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(addressOrName)) {
                    function = f;
                    break;
                }
            }
        }
        
        if (function == null) {
            return null;
        }
        
        // Build the function info
        Map<String, Object> result = new HashMap<>();
        result.put("name", function.getName());
        result.put("address", function.getEntryPoint().toString());
        result.put("signature", function.getSignature().getPrototypeString());
        
        // Add more details
        if (function.getReturnType() != null) {
            result.put("returnType", function.getReturnType().getName());
        }
        
        if (function.getCallingConventionName() != null) {
            result.put("callingConvention", function.getCallingConventionName());
        }
        
        return result;
    }
    
    /**
     * Gets information about a function at the specified address.
     * @param program The current program.
     * @param addressStr The address as a string.
     * @return A map containing information about the function, or an empty map if not found.
     */
    public static Map<String, Object> getFunctionByAddress(Program program, String addressStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (program == null || addressStr == null || addressStr.isEmpty()) {
            return result;
        }
        
        AddressFactory addressFactory = program.getAddressFactory();
        Address address;
        
        try {
            address = addressFactory.getAddress(addressStr);
        } catch (Exception e) {
            Msg.error(GhidraUtil.class, "Invalid address format: " + addressStr, e);
            return result;
        }
        
        if (address == null) {
            return result;
        }
        
        FunctionManager functionManager = program.getFunctionManager();
        Function function = functionManager.getFunctionAt(address);
        
        if (function == null) {
            function = functionManager.getFunctionContaining(address);
        }
        
        if (function == null) {
            return result;
        }
        
        result.put("name", function.getName());
        result.put("address", function.getEntryPoint().toString());
        result.put("signature", function.getSignature().getPrototypeString());
        
        // Add decompilation
        String decompilation = decompileFunction(function);
        result.put("decompilation", decompilation != null ? decompilation : "");
        
        return result;
    }
    
    /**
     * Decompiles a function at the specified address.
     * @param program The current program.
     * @param addressStr The address as a string.
     * @return A map containing the decompilation result, or an empty map if not found.
     */
    public static Map<String, Object> decompileFunction(Program program, String addressStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (program == null || addressStr == null || addressStr.isEmpty()) {
            return result;
        }
        
        AddressFactory addressFactory = program.getAddressFactory();
        Address address;
        
        try {
            address = addressFactory.getAddress(addressStr);
        } catch (Exception e) {
            Msg.error(GhidraUtil.class, "Invalid address format: " + addressStr, e);
            return result;
        }
        
        if (address == null) {
            return result;
        }
        
        FunctionManager functionManager = program.getFunctionManager();
        Function function = functionManager.getFunctionAt(address);
        
        if (function == null) {
            function = functionManager.getFunctionContaining(address);
        }
        
        if (function == null) {
            return result;
        }
        
        String decompilation = decompileFunction(function);
        result.put("decompilation", decompilation != null ? decompilation : "");
        
        return result;
    }
    
    /**
     * Helper method to decompile a function.
     * @param function The function to decompile.
     * @return The decompiled code as a string, or null if decompilation failed.
     */
    public static String decompileFunction(Function function) {
        if (function == null) {
            return null;
        }
        
        Program program = function.getProgram();
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        
        decompiler.setOptions(options);
        decompiler.openProgram(program);
        
        try {
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            } else {
                Msg.warn(GhidraUtil.class, "Decompilation failed for function: " + function.getName());
                return "// Decompilation failed for " + function.getName();
            }
        } catch (Exception e) {
            Msg.error(GhidraUtil.class, "Error during decompilation of function: " + function.getName(), e);
            return "// Error during decompilation: " + e.getMessage();
        } finally {
            decompiler.dispose();
        }
    }
    
    /**
     * Gets information about variables in a function.
     * @param function The function to get variables from.
     * @return A list of maps containing information about each variable.
     */
    public static List<Map<String, Object>> getFunctionVariables(Function function) {
        List<Map<String, Object>> variables = new ArrayList<>();
        
        if (function == null) {
            return variables;
        }
        
        // Add parameters
        for (Parameter param : function.getParameters()) {
            Map<String, Object> varInfo = new HashMap<>();
            varInfo.put("name", param.getName());
            varInfo.put("type", param.getDataType().getName());
            varInfo.put("isParameter", true);
            variables.add(varInfo);
        }
        
        // Add local variables
        for (Variable var : function.getAllVariables()) {
            if (var instanceof Parameter) {
                continue; // Skip parameters, already added
            }
            
            Map<String, Object> varInfo = new HashMap<>();
            varInfo.put("name", var.getName());
            varInfo.put("type", var.getDataType().getName());
            varInfo.put("isParameter", false);
            variables.add(varInfo);
        }
        
        return variables;
    }
}

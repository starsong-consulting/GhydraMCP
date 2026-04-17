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
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
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
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GhidraUtil {

    private static final Pattern ARRAY_TYPE_PATTERN = Pattern.compile("^(.*)\\[(\\d+)\\]$");

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
     * Resolve a data type by name, handling C-style array suffixes, path lookups,
     * signature parser strings, and common primitive aliases (byte, dword, uint32_t, ...).
     */
    public static DataType resolveDataType(Program program, String dataTypeName) {
        if (program == null || dataTypeName == null) {
            return null;
        }

        String normalizedName = dataTypeName.trim();
        if (normalizedName.isEmpty()) {
            return null;
        }

        List<Integer> dimensions = new ArrayList<>();
        String baseTypeName = normalizedName;
        while (true) {
            Matcher matcher = ARRAY_TYPE_PATTERN.matcher(baseTypeName);
            if (!matcher.matches()) {
                break;
            }
            int elementCount;
            try {
                elementCount = Integer.parseInt(matcher.group(2));
            } catch (NumberFormatException e) {
                return null;
            }
            if (elementCount <= 0) {
                return null;
            }
            dimensions.add(0, elementCount);
            baseTypeName = matcher.group(1).trim();
            if (baseTypeName.isEmpty()) {
                return null;
            }
        }

        DataType dataType = resolveBaseDataType(program, baseTypeName);
        if (dataType == null) {
            return null;
        }

        for (Integer dimension : dimensions) {
            int elementLength = dataType.getLength();
            if (elementLength <= 0) {
                return null;
            }
            dataType = new ghidra.program.model.data.ArrayDataType(dataType, dimension, elementLength);
        }
        return dataType;
    }

    private static DataType resolveBaseDataType(Program program, String dataTypeName) {
        DataTypeManager dtm = program.getDataTypeManager();

        DataType dataType = dtm.getDataType("/" + dataTypeName);
        if (dataType == null) {
            dataType = dtm.findDataType("/" + dataTypeName);
        }
        if (dataType == null) {
            List<DataType> namedMatches = new ArrayList<>();
            dtm.findDataTypes(dataTypeName, namedMatches);
            dataType = choosePreferredDataType(namedMatches, dataTypeName);
        }
        if (dataType == null) {
            try {
                ghidra.app.util.parser.FunctionSignatureParser parser =
                    new ghidra.app.util.parser.FunctionSignatureParser(dtm, null);
                dataType = parser.parse(null, dataTypeName);
            } catch (Exception e) {
                Msg.debug(GhidraUtil.class, "Function signature parser failed for '" + dataTypeName + "': " + e.getMessage());
            }
        }
        if (dataType == null) {
            dataType = resolvePrimitiveAlias(dataTypeName);
        }
        return dataType;
    }

    private static DataType resolvePrimitiveAlias(String name) {
        return switch (name.toLowerCase(Locale.ROOT)) {
            case "byte", "int8_t" -> new ghidra.program.model.data.ByteDataType();
            case "uint8_t" -> new ghidra.program.model.data.UnsignedCharDataType();
            case "char" -> new ghidra.program.model.data.CharDataType();
            case "signed char" -> new ghidra.program.model.data.SignedCharDataType();
            case "unsigned char" -> new ghidra.program.model.data.UnsignedCharDataType();
            case "word", "int16_t" -> new ghidra.program.model.data.WordDataType();
            case "uint16_t", "ushort", "unsigned short" -> new ghidra.program.model.data.UnsignedShortDataType();
            case "dword", "int32_t" -> new ghidra.program.model.data.DWordDataType();
            case "qword" -> new ghidra.program.model.data.QWordDataType();
            case "float" -> new ghidra.program.model.data.FloatDataType();
            case "double" -> new ghidra.program.model.data.DoubleDataType();
            case "int" -> new ghidra.program.model.data.IntegerDataType();
            case "uint32_t", "unsigned int" -> new ghidra.program.model.data.UnsignedIntegerDataType();
            case "uint64_t", "ulonglong", "unsigned long long", "unsigned __int64" ->
                new ghidra.program.model.data.UnsignedLongLongDataType();
            case "int64_t", "__int64", "long long" -> new ghidra.program.model.data.LongLongDataType();
            case "long" -> new ghidra.program.model.data.LongDataType();
            case "pointer" -> new ghidra.program.model.data.PointerDataType();
            case "string" -> new ghidra.program.model.data.StringDataType();
            default -> null;
        };
    }

    private static DataType choosePreferredDataType(List<DataType> candidates, String requestedName) {
        if (candidates == null || candidates.isEmpty()) {
            return null;
        }
        for (DataType c : candidates) {
            if (c != null && requestedName.equals(c.getName()) && !isLikelyBuiltIn(c)) return c;
        }
        for (DataType c : candidates) {
            if (c != null && requestedName.equalsIgnoreCase(c.getName()) && !isLikelyBuiltIn(c)) return c;
        }
        for (DataType c : candidates) {
            if (c != null && requestedName.equals(c.getName())) return c;
        }
        for (DataType c : candidates) {
            if (c != null && requestedName.equalsIgnoreCase(c.getName())) return c;
        }
        return candidates.get(0);
    }

    private static boolean isLikelyBuiltIn(DataType dataType) {
        if (dataType == null) return false;
        String categoryPath = "";
        try {
            if (dataType.getCategoryPath() != null) {
                categoryPath = dataType.getCategoryPath().getPath().toLowerCase(Locale.ROOT);
            }
        } catch (Exception ignored) {
        }
        if (categoryPath.contains("/builtin") || categoryPath.contains("/builtins")) {
            return true;
        }
        return dataType.getClass().getName().toLowerCase(Locale.ROOT).contains("builtin");
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
        return decompileFunction(function, true, 30);
    }

    /**
     * Helper method to decompile a function with configurable options.
     * @param function The function to decompile.
     * @param showConstants If true, show actual constant values (strings, numbers) instead of placeholder addresses
     * @param timeout Timeout in seconds for decompilation
     * @return The decompiled code as a string, or null if decompilation failed.
     */
    public static String decompileFunction(Function function, boolean showConstants, int timeout) {
        if (function == null) {
            return null;
        }

        Program program = function.getProgram();
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();

        // Configure constant display - when true, shows actual values instead of DAT_* placeholders
        if (showConstants) {
            options.setEliminateUnreachable(true);
            options.grabFromProgram(program);
        }

        decompiler.setOptions(options);
        decompiler.openProgram(program);

        try {
            DecompileResults results = decompiler.decompileFunction(function, timeout, TaskMonitor.DUMMY);
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
     * Gets information about variables in a function, including decompiler variables.
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
            varInfo.put("storage", param.getVariableStorage().toString());
            varInfo.put("source", "database");
            variables.add(varInfo);
        }
        
        // Add local variables from database
        for (Variable var : function.getAllVariables()) {
            if (var instanceof Parameter) {
                continue; // Skip parameters, already added
            }
            
            Map<String, Object> varInfo = new HashMap<>();
            varInfo.put("name", var.getName());
            varInfo.put("type", var.getDataType().getName());
            varInfo.put("isParameter", false);
            varInfo.put("storage", var.getVariableStorage().toString());
            varInfo.put("source", "database");
            variables.add(varInfo);
        }
        
        // Add decompiler-generated variables
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(function.getProgram());
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            
            if (results.decompileCompleted()) {
                HighFunction highFunc = results.getHighFunction();
                if (highFunc != null) {
                    // Iterate over local variables from decompiler
                    for (java.util.Iterator<ghidra.program.model.pcode.HighSymbol> iter = 
                            highFunc.getLocalSymbolMap().getSymbols(); iter.hasNext(); ) {
                        
                        ghidra.program.model.pcode.HighSymbol highSymbol = iter.next();
                        
                        // Skip if this is already a tracked variable
                        boolean alreadyAdded = false;
                        for (Map<String, Object> var : variables) {
                            if (var.get("name").equals(highSymbol.getName())) {
                                alreadyAdded = true;
                                break;
                            }
                        }
                        
                        if (!alreadyAdded) {
                            Map<String, Object> varInfo = new HashMap<>();
                            varInfo.put("name", highSymbol.getName());
                            varInfo.put("type", highSymbol.getDataType() != null ? 
                                highSymbol.getDataType().getName() : "unknown");
                            varInfo.put("isParameter", highSymbol.isParameter());
                            varInfo.put("storage", highSymbol.getStorage() != null ? 
                                highSymbol.getStorage().toString() : "unknown");
                            varInfo.put("source", "decompiler");
                            
                            // Add PC address if available
                            if (highSymbol.getPCAddress() != null) {
                                varInfo.put("pcAddress", highSymbol.getPCAddress().toString());
                            }
                            
                            variables.add(varInfo);
                        }
                    }
                }
            }
        } 
        catch (Exception e) {
            Msg.error(GhidraUtil.class, "Error analyzing decompiler variables", e);
        }
        finally {
            decompiler.dispose();
        }
        
        return variables;
    }
    
    /**
     * Applies a function signature to an existing function.
     * @param function The function to update
     * @param signatureStr The C-style function signature string
     * @return true if successful, false otherwise
     */
    public static boolean setFunctionSignature(Function function, String signatureStr) {
        if (function == null || signatureStr == null || signatureStr.isEmpty()) {
            return false;
        }
        
        Program program = function.getProgram();
        if (program == null) {
            return false;
        }
        
        try {
            // Create a function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(
                    program.getDataTypeManager(), null);
            
            // Parse the signature string
            ghidra.program.model.data.FunctionDefinitionDataType functionDef = 
                parser.parse(function.getSignature(), signatureStr);
            
            if (functionDef == null) {
                return false;
            }
            
            // Get source type for update
            ghidra.program.model.symbol.SourceType sourceType = 
                ghidra.program.model.symbol.SourceType.USER_DEFINED;
                
            // Get the parameters from the function definition
            ghidra.program.model.data.ParameterDefinition[] paramDefs = 
                functionDef.getArguments();
            
            try {
                // Get return type from the function definition
                ghidra.program.model.data.DataType returnType = functionDef.getReturnType();
                
                // Set the return type
                function.setReturnType(returnType, sourceType);
                
                // Get calling convention if available
                if (functionDef.getCallingConvention() != null) {
                    String callingConvention = functionDef.getCallingConvention().getName();
                    function.setCallingConvention(callingConvention);
                }
                
                // Build parameter list
                List<Parameter> newParams = new ArrayList<>();
                if (paramDefs != null) {
                    for (int i = 0; i < paramDefs.length; i++) {
                        ghidra.program.model.data.ParameterDefinition paramDef = paramDefs[i];
                        String name = paramDef.getName();
                        ghidra.program.model.data.DataType dataType = paramDef.getDataType();
                        newParams.add(new ParameterImpl(name, dataType, program));
                    }
                }

                // Replace all parameters at once using replaceParameters
                function.replaceParameters(newParams,
                    ghidra.program.model.listing.Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    false, sourceType);
                
                return true;
            } catch (ghidra.util.exception.InvalidInputException e) {
                ghidra.util.Msg.error(GhidraUtil.class, 
                    "Error setting function parameters: " + e.getMessage(), e);
                return false;
            }
        }
        catch (Exception e) {
            ghidra.util.Msg.error(GhidraUtil.class, 
                "Error setting function signature: " + e.getMessage(), e);
            return false;
        }
    }
}

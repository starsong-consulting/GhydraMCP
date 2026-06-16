package eu.starsong.ghidra.util;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GhidraUtil {

    static final Pattern ARRAY_TYPE_PATTERN = Pattern.compile("^(.*)\\[(\\d+)\\]$");

    /**
     * Find a function by bare-or-fully-qualified name. A bare name (no "::")
     * resolves against the GLOBAL namespace only (Ghidra's SymbolPath semantics);
     * a qualified name (e.g. "FOM::Read") resolves within that namespace. Returns
     * the first matching FUNCTION symbol, or null. Wrap calls in GhidraSwing.runRead.
     */
    public static Function findFunctionByName(Program program, String name) {
        if (program == null || name == null || name.isEmpty()) {
            return null;
        }
        List<Symbol> symbols = NamespaceUtils.getSymbols(new SymbolPath(name), program, false);
        for (Symbol s : symbols) {
            if (s.getSymbolType() == SymbolType.FUNCTION) {
                return (Function) s.getObject();
            }
        }
        return null;
    }

    /**
     * Apply a bare-or-qualified name to an existing symbol. Call inside a transaction.
     *   "foo"          -> rename leaf, keep current namespace
     *   "A::B::foo"    -> create A::B under global if absent, then move + rename (atomic)
     *   "::foo"        -> move to global (leading "::" = global root)
     *   "Global::foo"  -> same as "::foo" (detected here; SymbolPath would otherwise collapse it)
     *   "::A::foo"     -> strip the leading "::", then behaves like "A::foo"
     */
    public static void applyQualifiedName(Program program, Symbol symbol, String newName, SourceType src)
            throws Exception {
        String raw = newName == null ? "" : newName.trim();
        boolean forceGlobal = false;
        if (raw.startsWith("::")) {
            forceGlobal = true;
            raw = raw.substring(2).trim();
        } else if (raw.regionMatches(true, 0, "Global::", 0, 8)) {
            forceGlobal = true;
            raw = raw.substring(8).trim();
        }
        if (raw.isEmpty()) {
            throw new IllegalArgumentException("Empty symbol name");
        }

        SymbolPath path = new SymbolPath(raw);
        String parent = path.getParentPath();
        Namespace root = program.getGlobalNamespace();

        if (parent != null) {
            Namespace ns = NamespaceUtils.createNamespaceHierarchy(parent, root, program, src);
            symbol.setNameAndNamespace(path.getName(), ns, src);
        } else if (forceGlobal) {
            symbol.setNameAndNamespace(path.getName(), root, src);
        } else {
            symbol.setName(path.getName(), src);
        }
    }

    /**
     * Create a label honoring a bare-or-qualified name. Call inside a transaction.
     * A bare name creates the label in the global namespace (a brand-new label has
     * no "current" namespace); a qualified name creates the namespace hierarchy and
     * places the label there. A leading "::"/"Global::" is stripped (equivalent to bare).
     */
    public static Symbol createLabelWithName(Program program, Address address, String newName, SourceType src)
            throws Exception {
        String raw = newName == null ? "" : newName.trim();
        if (raw.startsWith("::")) {
            raw = raw.substring(2).trim();
        } else if (raw.regionMatches(true, 0, "Global::", 0, 8)) {
            raw = raw.substring(8).trim();
        }
        if (raw.isEmpty()) {
            throw new IllegalArgumentException("Empty symbol name");
        }

        SymbolPath path = new SymbolPath(raw);
        String parent = path.getParentPath();
        SymbolTable st = program.getSymbolTable();
        if (parent == null) {
            return st.createLabel(address, path.getName(), src);
        }
        Namespace ns = NamespaceUtils.createNamespaceHierarchy(parent, program.getGlobalNamespace(), program, src);
        return st.createLabel(address, path.getName(), ns, src);
    }

    /**
     * Resolve an address string. Accepts direct parse, implicit hex prefix for bare hex-looking
     * values, space-qualified form (space::offset), and prefers overlay spaces when ambiguous.
     */
    public static Address resolveAddress(Program program, String rawAddress, boolean preferOverlay) {
        if (program == null || rawAddress == null) return null;
        String addr = rawAddress.trim();
        if (addr.isEmpty()) return null;

        AddressFactory addressFactory = program.getAddressFactory();
        Address parsed = tryParseAddress(addressFactory, addr);
        String preferredSpaceName = null;

        if (parsed == null && !addr.contains("::") && !addr.startsWith("0x") && !addr.startsWith("0X")) {
            parsed = tryParseAddress(addressFactory, "0x" + addr);
        }

        if (addr.contains("::")) {
            int idx = addr.indexOf("::");
            preferredSpaceName = addr.substring(0, idx).trim();
            String offsetPart = addr.substring(idx + 2).trim();
            if (parsed == null) {
                Long offset = parseAddressOffset(offsetPart);
                if (offset != null) {
                    AddressSpace space = addressFactory.getAddressSpace(preferredSpaceName);
                    if (space != null) {
                        try { parsed = space.getAddress(offset); } catch (Exception ignored) {}
                    }
                }
            }
        }

        if (preferOverlay && !addr.contains("::")) {
            Long offset = parseAddressOffset(
                addr.startsWith("0x") || addr.startsWith("0X") ? addr : "0x" + addr);
            if (offset == null) offset = parseAddressOffset(addr);
            if (offset != null) {
                Address overlayAddress = findOverlayAddressByOffset(program, offset, null);
                if (overlayAddress != null) return overlayAddress;
            }
        }

        if (preferOverlay && parsed != null && !parsed.getAddressSpace().isOverlaySpace()) {
            Address overlayAddress = findOverlayAddressByOffset(program, parsed.getOffset(), preferredSpaceName);
            if (overlayAddress != null) return overlayAddress;
        }
        return parsed;
    }

    public static Address resolveAddress(Program program, String rawAddress) {
        return resolveAddress(program, rawAddress, true);
    }

    private static Address tryParseAddress(AddressFactory factory, String s) {
        try { return factory.getAddress(s); } catch (Exception e) { return null; }
    }

    static Long parseAddressOffset(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        if (trimmed.isEmpty()) return null;
        try {
            if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                return Long.parseUnsignedLong(trimmed.substring(2), 16);
            }
            if (trimmed.matches("^[0-9a-fA-F]+$")) {
                return Long.parseUnsignedLong(trimmed, 16);
            }
            return Long.parseLong(trimmed);
        } catch (Exception e) {
            return null;
        }
    }

    private static Address findOverlayAddressByOffset(Program program, long offset, String preferredSpaceName) {
        Memory memory = program.getMemory();
        Address fallback = null;
        for (MemoryBlock block : memory.getBlocks()) {
            Address start = block.getStart();
            AddressSpace space = start.getAddressSpace();
            if (!space.isOverlaySpace()) continue;
            if (preferredSpaceName != null && !preferredSpaceName.isEmpty()
                && !preferredSpaceName.equals(space.getName())) continue;
            try {
                Address candidate = space.getAddress(offset);
                if (!block.contains(candidate)) continue;
                if (space.getName().toLowerCase().contains("runtime")) return candidate;
                if (fallback == null) fallback = candidate;
            } catch (Exception ignored) {}
        }
        return fallback;
    }

    /**
     * Resolve a data type by name, handling C-style array suffixes, path lookups,
     * signature parser strings, and common primitive aliases (byte, dword, uint32_t, ...).
     */
    public static DataType resolveDataType(Program program, String dataTypeName) {
        if (program == null || dataTypeName == null) return null;
        String normalizedName = dataTypeName.trim();
        if (normalizedName.isEmpty()) return null;

        List<Integer> dimensions = new ArrayList<>();
        String baseTypeName = normalizedName;
        while (true) {
            Matcher matcher = ARRAY_TYPE_PATTERN.matcher(baseTypeName);
            if (!matcher.matches()) break;
            int elementCount;
            try {
                elementCount = Integer.parseInt(matcher.group(2));
            } catch (NumberFormatException e) {
                return null;
            }
            if (elementCount <= 0) return null;
            dimensions.add(0, elementCount);
            baseTypeName = matcher.group(1).trim();
            if (baseTypeName.isEmpty()) return null;
        }

        DataType dataType = resolveBaseDataType(program, baseTypeName);
        if (dataType == null) return null;

        for (Integer dimension : dimensions) {
            int elementLength = dataType.getLength();
            if (elementLength <= 0) return null;
            dataType = new ghidra.program.model.data.ArrayDataType(dataType, dimension, elementLength);
        }
        return dataType;
    }

    private static DataType resolveBaseDataType(Program program, String dataTypeName) {
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = dtm.getDataType("/" + dataTypeName);
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

    static DataType resolvePrimitiveAlias(String name) {
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
        if (candidates == null || candidates.isEmpty()) return null;
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
        } catch (Exception ignored) {}
        if (categoryPath.contains("/builtin") || categoryPath.contains("/builtins")) return true;
        return dataType.getClass().getName().toLowerCase(Locale.ROOT).contains("builtin");
    }

    /**
     * Get function variables: parameters, locals from the function DB, and
     * decompiler-generated locals (merged, de-duped by name).
     */
    public static List<Map<String, Object>> getFunctionVariables(Function function) {
        if (function == null) return new ArrayList<>();

        // DB-backed reads (parameters, stored locals) walk live DB records: marshal onto
        // the EDT. The decompiler half below must stay OFF the EDT, hence the split.
        List<Map<String, Object>> variables = GhidraSwing.runRead(() -> {
            List<Map<String, Object>> dbVars = new ArrayList<>();
            for (Parameter param : function.getParameters()) {
                Map<String, Object> varInfo = new HashMap<>();
                varInfo.put("name", param.getName());
                varInfo.put("type", param.getDataType().getName());
                varInfo.put("isParameter", true);
                varInfo.put("storage", param.getVariableStorage().toString());
                varInfo.put("source", "database");
                dbVars.add(varInfo);
            }
            for (Variable var : function.getAllVariables()) {
                if (var instanceof Parameter) continue;
                Map<String, Object> varInfo = new HashMap<>();
                varInfo.put("name", var.getName());
                varInfo.put("type", var.getDataType().getName());
                varInfo.put("isParameter", false);
                varInfo.put("storage", var.getVariableStorage().toString());
                varInfo.put("source", "database");
                dbVars.add(varInfo);
            }
            return dbVars;
        });

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(function.getProgram());
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (results.decompileCompleted()) {
                HighFunction highFunc = results.getHighFunction();
                if (highFunc != null) {
                    for (var iter = highFunc.getLocalSymbolMap().getSymbols(); iter.hasNext(); ) {
                        ghidra.program.model.pcode.HighSymbol sym = iter.next();
                        boolean alreadyAdded = false;
                        for (Map<String, Object> v : variables) {
                            if (v.get("name").equals(sym.getName())) {
                                alreadyAdded = true;
                                break;
                            }
                        }
                        if (!alreadyAdded) {
                            Map<String, Object> varInfo = new HashMap<>();
                            varInfo.put("name", sym.getName());
                            varInfo.put("type", sym.getDataType() != null
                                ? sym.getDataType().getName() : "unknown");
                            varInfo.put("isParameter", sym.isParameter());
                            varInfo.put("storage", sym.getStorage() != null
                                ? sym.getStorage().toString() : "unknown");
                            varInfo.put("source", "decompiler");
                            if (sym.getPCAddress() != null) {
                                varInfo.put("pcAddress", sym.getPCAddress().toString());
                            }
                            variables.add(varInfo);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(GhidraUtil.class, "Error analyzing decompiler variables", e);
        } finally {
            decompiler.dispose();
        }
        return variables;
    }

    /**
     * Apply a C-style function signature string to an existing function.
     */
    public static boolean setFunctionSignature(Function function, String signatureStr) {
        if (function == null || signatureStr == null || signatureStr.isEmpty()) return false;
        Program program = function.getProgram();
        if (program == null) return false;

        try {
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(program.getDataTypeManager(), null);
            ghidra.program.model.data.FunctionDefinitionDataType functionDef =
                parser.parse(function.getSignature(), signatureStr);
            if (functionDef == null) return false;

            SourceType sourceType = SourceType.USER_DEFINED;
            ghidra.program.model.data.ParameterDefinition[] paramDefs = functionDef.getArguments();

            try {
                function.setReturnType(functionDef.getReturnType(), sourceType);
                if (functionDef.getCallingConvention() != null) {
                    function.setCallingConvention(functionDef.getCallingConvention().getName());
                }
                List<Parameter> newParams = new ArrayList<>();
                if (paramDefs != null) {
                    for (ghidra.program.model.data.ParameterDefinition pd : paramDefs) {
                        newParams.add(new ParameterImpl(pd.getName(), pd.getDataType(), program));
                    }
                }
                function.replaceParameters(newParams,
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    false, sourceType);
                return true;
            } catch (ghidra.util.exception.InvalidInputException e) {
                Msg.error(GhidraUtil.class, "Error setting function parameters: " + e.getMessage(), e);
                return false;
            }
        } catch (Exception e) {
            Msg.error(GhidraUtil.class, "Error setting function signature: " + e.getMessage(), e);
            return false;
        }
    }
}

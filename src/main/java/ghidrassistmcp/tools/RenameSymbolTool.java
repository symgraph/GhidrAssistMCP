/*
 * MCP tool for renaming symbols (functions, data, variables).
 * Consolidates rename_function, rename_data, and rename_variable into a single tool.
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that renames symbols (functions, data, or variables).
 * Replaces separate rename_function, rename_data, and rename_variable tools.
 */
public class RenameSymbolTool implements McpTool {

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public String getName() {
        return "rename_symbol";
    }

    @Override
    public String getDescription() {
        return "Rename a symbol (function, data/label, or local variable)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "target_type", Map.of(
                    "type", "string",
                    "description", "What kind of symbol to rename",
                    "enum", List.of("function", "data", "variable")
                ),
                "identifier", Map.of(
                    "type", "string",
                    "description", "Target identifier (function: old function name; data: address string; variable: function name)"
                ),
                "new_name", Map.of(
                    "type", "string",
                    "description", "New symbol name (functions may be qualified like Namespace::Func)"
                ),
                "variable_name", Map.of(
                    "type", "string",
                    "description", "Required when target_type is 'variable': old local name to rename"
                )
            ),
            List.of("target_type", "identifier", "new_name"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        RenameSymbolCore.RenameResult result = RenameSymbolCore.renameOne(arguments, currentProgram);
        return McpSchema.CallToolResult.builder()
            .addTextContent(result.message)
            .build();
    }
}

/**
 * Shared implementation for symbol renaming operations.
 *
 * Package-private so both `RenameSymbolTool` and a batch variant can share logic
 * without duplicating implementations.
 */
final class RenameSymbolCore {

    static final class RenameResult {
        final boolean success;
        final String message;

        RenameResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    private RenameSymbolCore() {
        // utility
    }

    static RenameResult renameOne(Map<String, Object> arguments, Program program) {
        if (program == null) {
            return new RenameResult(false, "No program currently loaded");
        }

        String targetType = getString(arguments, "target_type");
        String identifier = getString(arguments, "identifier");
        String newName = getString(arguments, "new_name");

        if (targetType == null || targetType.isEmpty()) {
            return new RenameResult(false, "target_type parameter is required ('function', 'data', or 'variable')");
        }
        if (identifier == null || identifier.isEmpty()) {
            return new RenameResult(false, "identifier parameter is required");
        }
        if (newName == null || newName.isEmpty()) {
            return new RenameResult(false, "new_name parameter is required");
        }

        targetType = targetType.toLowerCase();

        switch (targetType) {
            case "function":
                return renameFunction(program, identifier, newName);
            case "data":
                return renameData(program, identifier, newName);
            case "variable": {
                String variableName = getString(arguments, "variable_name");
                if (variableName == null || variableName.isEmpty()) {
                    return new RenameResult(false, "variable_name parameter is required when target_type is 'variable'");
                }
                return renameVariable(program, identifier, variableName, newName);
            }
            default:
                return new RenameResult(false, "Invalid target_type. Use 'function', 'data', or 'variable'");
        }
    }

    private static String getString(Map<String, Object> arguments, String key) {
        Object v = arguments.get(key);
        if (v instanceof String) {
            return (String) v;
        }
        return null;
    }

    static final class VariableRenameRequest {
        final int index;
        final String oldName;
        final String newName;

        VariableRenameRequest(int index, String oldName, String newName) {
            this.index = index;
            this.oldName = oldName;
            this.newName = newName;
        }
    }

    /**
     * Batch rename variables within a single function using one decompile pass.
     *
     * This avoids the "renumbering" issue that can occur when you re-decompile after each rename
     * and rely on decompiler-generated names like uVar23/uVar24 being stable.
     *
     * Returns a result per request index (partial success supported).
     */
    static Map<Integer, RenameResult> renameVariablesBatch(Program program, String functionName,
                                                          List<VariableRenameRequest> renames) {
        Map<Integer, RenameResult> resultsByIndex = new HashMap<>();

        if (program == null) {
            for (VariableRenameRequest r : renames) {
                resultsByIndex.put(r.index, new RenameResult(false, "No program currently loaded"));
            }
            return resultsByIndex;
        }
        if (functionName == null || functionName.isEmpty()) {
            for (VariableRenameRequest r : renames) {
                resultsByIndex.put(r.index, new RenameResult(false, "Function name is required for variable renames"));
            }
            return resultsByIndex;
        }

        Function function = findFunctionByName(program, functionName);
        if (function == null) {
            for (VariableRenameRequest r : renames) {
                resultsByIndex.put(r.index, new RenameResult(false, "Function not found: " + functionName));
            }
            return resultsByIndex;
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults decompileResults = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);

            if (decompileResults.isTimedOut()) {
                for (VariableRenameRequest r : renames) {
                    resultsByIndex.put(r.index, new RenameResult(false,
                        "Decompilation timed out for function: " + functionName));
                }
                return resultsByIndex;
            }
            if (!decompileResults.isValid()) {
                for (VariableRenameRequest r : renames) {
                    resultsByIndex.put(r.index, new RenameResult(false,
                        "Decompilation error for function " + functionName + ": " + decompileResults.getErrorMessage()));
                }
                return resultsByIndex;
            }

            HighFunction highFunction = decompileResults.getHighFunction();
            if (highFunction == null) {
                for (VariableRenameRequest r : renames) {
                    resultsByIndex.put(r.index, new RenameResult(false,
                        "Could not get high function for: " + functionName));
                }
                return resultsByIndex;
            }

            Map<String, HighSymbol> symbolsByName = new HashMap<>();
            Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol s = symbols.next();
                // First one wins; duplicate names are rare but possible.
                symbolsByName.putIfAbsent(s.getName(), s);
            }

            // Resolve all symbols up-front from the single decompile pass.
            final List<ResolvedVarRename> toApply = new ArrayList<>();
            for (VariableRenameRequest req : renames) {
                if (req.oldName == null || req.oldName.isEmpty()) {
                    resultsByIndex.put(req.index, new RenameResult(false, "variable_name is required"));
                    continue;
                }
                if (req.newName == null || req.newName.isEmpty()) {
                    resultsByIndex.put(req.index, new RenameResult(false, "new_name parameter is required"));
                    continue;
                }

                HighSymbol sym = symbolsByName.get(req.oldName);
                if (sym == null) {
                    resultsByIndex.put(req.index, new RenameResult(false,
                        "Variable '" + req.oldName + "' not found in function '" + functionName + "'"));
                    continue;
                }
                toApply.add(new ResolvedVarRename(req.index, req.oldName, req.newName, sym));
            }

            // Apply on EDT. Use per-rename transactions so partial success is preserved.
            try {
                SwingUtilities.invokeAndWait(() -> {
                    for (ResolvedVarRename r : toApply) {
                        int txId = program.startTransaction("Rename Variable");
                        try {
                            HighFunctionDBUtil.updateDBVariable(r.symbol, r.newName, null, SourceType.USER_DEFINED);
                            program.endTransaction(txId, true);
                            resultsByIndex.put(r.index, new RenameResult(true,
                                "Successfully renamed variable '" + r.oldName + "' to '" + r.newName +
                                    "' in function '" + functionName + "'"));
                        } catch (DuplicateNameException e) {
                            program.endTransaction(txId, false);
                            resultsByIndex.put(r.index, new RenameResult(false,
                                "Variable with name '" + r.newName + "' already exists in function '" + functionName + "'"));
                        } catch (InvalidInputException e) {
                            program.endTransaction(txId, false);
                            resultsByIndex.put(r.index, new RenameResult(false, "Invalid variable name: " + r.newName));
                        } catch (Exception e) {
                            program.endTransaction(txId, false);
                            resultsByIndex.put(r.index, new RenameResult(false, "Error renaming variable: " + e.getMessage()));
                        }
                    }
                });
            } catch (Exception e) {
                // If EDT dispatch fails, mark anything that wasn't already resolved as a failure.
                for (ResolvedVarRename r : toApply) {
                    resultsByIndex.putIfAbsent(r.index, new RenameResult(false,
                        "Error executing rename on EDT: " + e.getMessage()));
                }
            }

            return resultsByIndex;
        } catch (Exception e) {
            for (VariableRenameRequest r : renames) {
                resultsByIndex.put(r.index, new RenameResult(false, "Error renaming variable: " + e.getMessage()));
            }
            return resultsByIndex;
        } finally {
            decompiler.dispose();
        }
    }

    private static final class ResolvedVarRename {
        final int index;
        final String oldName;
        final String newName;
        final HighSymbol symbol;

        ResolvedVarRename(int index, String oldName, String newName, HighSymbol symbol) {
            this.index = index;
            this.oldName = oldName;
            this.newName = newName;
            this.symbol = symbol;
        }
    }

    /**
     * Rename a function.
     * Supports C++ qualified names (e.g., "Class::method" or "Outer::Inner::method").
     * When a qualified name is provided, the namespace hierarchy is created if it doesn't exist.
     *
     * Note: Symbol operations must run on the Swing EDT to avoid race conditions with
     * Ghidra's Symbol Tree UI updates.
     */
    private static RenameResult renameFunction(Program program, String oldName, String newName) {
        Function function = findFunctionByName(program, oldName);
        if (function == null) {
            return new RenameResult(false, "Function not found: " + oldName);
        }

        AtomicReference<RenameResult> resultRef = new AtomicReference<>();
        final Function targetFunction = function;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int transactionID = program.startTransaction("Rename Function");
                try {
                    Object[] parsed = parseAndCreateNamespace(program, newName);
                    if (parsed == null) {
                        program.endTransaction(transactionID, false);
                        resultRef.set(new RenameResult(false, "Invalid qualified name format: " + newName));
                        return;
                    }

                    Namespace targetNamespace = (Namespace) parsed[0];
                    String simpleName = (String) parsed[1];

                    // Check if a function with this name already exists in the target namespace
                    Function existingFunction = findFunctionByName(program, simpleName);
                    if (existingFunction != null && existingFunction != targetFunction &&
                        existingFunction.getParentNamespace().equals(targetNamespace)) {
                        program.endTransaction(transactionID, false);
                        resultRef.set(new RenameResult(false,
                            "Function with name '" + simpleName + "' already exists in namespace '" +
                                targetNamespace.getName(true) + "'"));
                        return;
                    }

                    if (!targetNamespace.isGlobal()) {
                        targetFunction.setParentNamespace(targetNamespace);
                    }

                    targetFunction.setName(simpleName, SourceType.USER_DEFINED);
                    program.endTransaction(transactionID, true);

                    String resultName = targetNamespace.isGlobal()
                        ? simpleName
                        : targetNamespace.getName(true) + "::" + simpleName;
                    resultRef.set(new RenameResult(true,
                        "Successfully renamed function '" + oldName + "' to '" + resultName + "'"));
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    resultRef.set(new RenameResult(false, "Error renaming function: " + e.getMessage()));
                }
            });
        } catch (Exception e) {
            return new RenameResult(false, "Error executing rename on EDT: " + e.getMessage());
        }

        return resultRef.get() != null ? resultRef.get() : new RenameResult(false, "Unknown error renaming function");
    }

    /**
     * Rename data/label at an address.
     *
     * Note: Symbol operations must run on the Swing EDT to avoid race conditions with
     * Ghidra's Symbol Tree UI updates.
     */
    private static RenameResult renameData(Program program, String identifier, String newName) {
        Address address = resolveDataAddress(program, identifier);
        if (address == null) {
            return new RenameResult(false, "Could not resolve data/global symbol: " + identifier);
        }

        AtomicReference<RenameResult> resultRef = new AtomicReference<>();
        final Address targetAddress = address;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int transactionID = program.startTransaction("Rename Data");
                try {
                    Data data = program.getListing().getDataAt(targetAddress);
                    if (data != null) {
                        Symbol primarySymbol = data.getPrimarySymbol();
                        if (primarySymbol != null) {
                            String oldName = primarySymbol.getName();
                            try {
                                primarySymbol.setName(newName, SourceType.USER_DEFINED);
                                program.endTransaction(transactionID, true);
                                resultRef.set(new RenameResult(true,
                                    "Successfully renamed data at " + identifier +
                                        " from '" + oldName + "' to '" + newName + "'"));
                                return;
                            } catch (DuplicateNameException e) {
                                program.endTransaction(transactionID, false);
                                resultRef.set(new RenameResult(false,
                                    "Symbol with name '" + newName + "' already exists"));
                                return;
                            } catch (InvalidInputException e) {
                                program.endTransaction(transactionID, false);
                                resultRef.set(new RenameResult(false, "Invalid symbol name: " + newName));
                                return;
                            }
                        }

                        program.getSymbolTable().createLabel(targetAddress, newName, SourceType.USER_DEFINED);
                        program.endTransaction(transactionID, true);
                        resultRef.set(new RenameResult(true,
                            "Successfully created label '" + newName + "' at " + identifier));
                        return;
                    }

                    Symbol[] symbols = program.getSymbolTable().getSymbols(targetAddress);
                    if (symbols.length > 0) {
                        Symbol symbol = symbols[0];
                        String oldName = symbol.getName();
                        try {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                            program.endTransaction(transactionID, true);
                            resultRef.set(new RenameResult(true,
                                "Successfully renamed symbol at " + identifier +
                                    " from '" + oldName + "' to '" + newName + "'"));
                            return;
                        } catch (DuplicateNameException e) {
                            program.endTransaction(transactionID, false);
                            resultRef.set(new RenameResult(false,
                                "Symbol with name '" + newName + "' already exists"));
                            return;
                        } catch (InvalidInputException e) {
                            program.endTransaction(transactionID, false);
                            resultRef.set(new RenameResult(false, "Invalid symbol name: " + newName));
                            return;
                        }
                    }

                    program.getSymbolTable().createLabel(targetAddress, newName, SourceType.USER_DEFINED);
                    program.endTransaction(transactionID, true);
                    resultRef.set(new RenameResult(true,
                        "Successfully created label '" + newName + "' at " + identifier));
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    resultRef.set(new RenameResult(false, "Error creating label: " + e.getMessage()));
                }
            });
        } catch (Exception e) {
            return new RenameResult(false, "Error executing rename on EDT: " + e.getMessage());
        }

        return resultRef.get() != null ? resultRef.get() : new RenameResult(false, "Unknown error renaming data");
    }

    private static Address resolveDataAddress(Program program, String identifier) {
        try {
            Address address = program.getAddressFactory().getAddress(identifier);
            if (address != null && program.getFunctionManager().getFunctionAt(address) == null) {
                return address;
            }
        } catch (Exception e) {
            // Fall through to symbol lookup
        }

        SymbolIterator symbols = program.getSymbolTable().getSymbolIterator();
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (!symbol.getName().equals(identifier)) {
                continue;
            }

            Address address = symbol.getAddress();
            if (address != null && program.getFunctionManager().getFunctionAt(address) == null) {
                return address;
            }
        }

        return null;
    }

    /**
     * Rename a local variable within a function.
     *
     * Note: Symbol operations must run on the Swing EDT to avoid race conditions with
     * Ghidra's Symbol Tree UI updates.
     */
    private static RenameResult renameVariable(Program program, String functionName,
                                              String oldVariableName, String newVariableName) {
        Function function = findFunctionByName(program, functionName);
        if (function == null) {
            return new RenameResult(false, "Function not found: " + functionName);
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);

            if (results.isTimedOut()) {
                return new RenameResult(false, "Decompilation timed out for function: " + functionName);
            }
            if (!results.isValid()) {
                return new RenameResult(false,
                    "Decompilation error for function " + functionName + ": " + results.getErrorMessage());
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return new RenameResult(false, "Could not get high function for: " + functionName);
            }

            HighSymbol targetSymbol = null;
            Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                if (symbol.getName().equals(oldVariableName)) {
                    targetSymbol = symbol;
                    break;
                }
            }

            if (targetSymbol == null) {
                return new RenameResult(false,
                    "Variable '" + oldVariableName + "' not found in function '" + functionName + "'");
            }

            AtomicReference<RenameResult> resultRef = new AtomicReference<>();
            final HighSymbol symbolToRename = targetSymbol;

            SwingUtilities.invokeAndWait(() -> {
                int transactionID = program.startTransaction("Rename Variable");
                try {
                    HighFunctionDBUtil.updateDBVariable(symbolToRename, newVariableName, null, SourceType.USER_DEFINED);
                    program.endTransaction(transactionID, true);
                    resultRef.set(new RenameResult(true,
                        "Successfully renamed variable '" + oldVariableName + "' to '" + newVariableName +
                            "' in function '" + functionName + "'"));
                } catch (DuplicateNameException e) {
                    program.endTransaction(transactionID, false);
                    resultRef.set(new RenameResult(false,
                        "Variable with name '" + newVariableName + "' already exists in function '" + functionName + "'"));
                } catch (InvalidInputException e) {
                    program.endTransaction(transactionID, false);
                    resultRef.set(new RenameResult(false, "Invalid variable name: " + newVariableName));
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    resultRef.set(new RenameResult(false, "Error renaming variable: " + e.getMessage()));
                }
            });

            return resultRef.get() != null ? resultRef.get() : new RenameResult(false, "Unknown error renaming variable");
        } catch (Exception e) {
            return new RenameResult(false, "Error renaming variable: " + e.getMessage());
        } finally {
            decompiler.dispose();
        }
    }

    private static Function findFunctionByName(Program program, String functionName) {
        return FunctionLookup.findByName(program, functionName);
    }

    /**
     * Parse a qualified name (e.g., "Class::method" or "Outer::Inner::method")
     * and return the namespace and simple name.
     * Creates namespace hierarchy if it doesn't exist.
     *
     * @return Object[] with [Namespace, String simpleName], or null on error
     */
    private static Object[] parseAndCreateNamespace(Program program, String qualifiedName) {
        if (!qualifiedName.contains("::")) {
            return new Object[] { program.getGlobalNamespace(), qualifiedName };
        }

        String[] parts = qualifiedName.split("::");
        if (parts.length < 2) {
            return null;
        }

        String simpleName = parts[parts.length - 1];
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace currentNamespace = program.getGlobalNamespace();

        for (int i = 0; i < parts.length - 1; i++) {
            String nsName = parts[i].trim();
            if (nsName.isEmpty()) {
                continue;
            }

            try {
                Namespace existingNs = symbolTable.getNamespace(nsName, currentNamespace);
                if (existingNs != null) {
                    currentNamespace = existingNs;
                } else {
                    currentNamespace = symbolTable.createClass(currentNamespace, nsName, SourceType.USER_DEFINED);
                }
            } catch (Exception e) {
                try {
                    currentNamespace = symbolTable.createNameSpace(currentNamespace, nsName, SourceType.USER_DEFINED);
                } catch (Exception e2) {
                    return null;
                }
            }
        }

        return new Object[] { currentNamespace, simpleName };
    }
}

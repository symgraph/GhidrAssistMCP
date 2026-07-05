/*
 * Indexed function-by-name lookup shared by tools.
 */
package ghidrassistmcp.tools;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

/**
 * Resolves functions by name using the symbol table's name index instead of
 * iterating every function in the program. A linear scan over
 * FunctionManager.getFunctions(true) costs one database record read per
 * function in the program for a single lookup; on large binaries that is
 * seconds per call. The name index makes the cost proportional to the number
 * of symbols sharing the exact name (usually one).
 */
public final class FunctionLookup {

    private FunctionLookup() {
    }

    /**
     * Find a non-external function whose plain name equals {@code name}.
     * Matches the same set as the linear scan it replaces (iterating
     * getFunctions(true) and comparing Function.getName()); when several
     * functions share the name, the lowest entry point wins, mirroring the
     * address-ordered scan.
     */
    public static Function findByName(Program program, String name) {
        Function best = null;
        SymbolIterator symbols = program.getSymbolTable().getSymbols(name);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() != SymbolType.FUNCTION || symbol.isExternal()) {
                continue;
            }
            if (symbol.getObject() instanceof Function function) {
                if (best == null || function.getEntryPoint().compareTo(best.getEntryPoint()) < 0) {
                    best = function;
                }
            }
        }
        return best;
    }

    /**
     * Find a function by plain or C++-qualified name (e.g. "Class::method" or
     * "Outer::Inner::method"). For qualified names, candidates are found via
     * the name index on the simple name and filtered by namespace hierarchy.
     */
    public static Function findByQualifiedName(Program program, String identifier) {
        if (identifier.contains("::")) {
            String[] parts = identifier.split("::");
            if (parts.length >= 2) {
                String simpleName = parts[parts.length - 1];
                String[] namespaceParts = new String[parts.length - 1];
                System.arraycopy(parts, 0, namespaceParts, 0, parts.length - 1);

                Function best = null;
                SymbolIterator symbols = program.getSymbolTable().getSymbols(simpleName);
                while (symbols.hasNext()) {
                    Symbol symbol = symbols.next();
                    if (symbol.getSymbolType() != SymbolType.FUNCTION || symbol.isExternal()) {
                        continue;
                    }
                    if (symbol.getObject() instanceof Function function
                            && matchesNamespaceHierarchy(function, namespaceParts)) {
                        if (best == null || function.getEntryPoint().compareTo(best.getEntryPoint()) < 0) {
                            best = function;
                        }
                    }
                }
                return best;
            }
        }
        return findByName(program, identifier);
    }

    /**
     * Walk the function's parent namespaces backwards against the qualified
     * name's namespace parts (innermost first).
     */
    private static boolean matchesNamespaceHierarchy(Function function, String[] namespaceParts) {
        Namespace ns = function.getParentNamespace();
        for (int i = namespaceParts.length - 1; i >= 0; i--) {
            if (ns == null || ns.isGlobal()) {
                return false;
            }
            if (!ns.getName().equals(namespaceParts[i])) {
                return false;
            }
            ns = ns.getParentNamespace();
        }
        return true;
    }
}

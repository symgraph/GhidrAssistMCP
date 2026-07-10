/*
 * Indexed function-by-name lookup shared by tools.
 */
package ghidrassistmcp.tools;

import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;

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
     * Find a non-external function whose plain name equals {@code name}. This
     * includes default-source thunk functions, which Ghidra intentionally omits
     * from {@link ghidra.program.model.symbol.SymbolTable#getSymbols(String)}.
     * When several functions share the name, the lowest entry point wins,
     * mirroring the address-ordered scan this method replaces.
     */
    public static Function findByName(Program program, String name) {
        return new Lookup(program, name, null).find();
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

                return new Lookup(program, simpleName, namespaceParts).find();
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

    /**
     * Performs one indexed lookup and augments its results with default thunks.
     * A default thunk has no indexed name record: its displayed name is derived
     * from the function it thunks. Starting from indexed target functions and
     * following their reverse thunk relationships preserves the old lookup set
     * without returning to a program-wide function scan.
     */
    private static final class Lookup {
        private static final String DEFAULT_THUNK_PREFIX = "thunk_";

        private final Program program;
        private final FunctionManager functionManager;
        private final String name;
        private final String[] namespaceParts;
        private final Set<Address> processedSources = new HashSet<>();
        private Function best;

        private Lookup(Program program, String name, String[] namespaceParts) {
            this.program = program;
            this.functionManager = program.getFunctionManager();
            this.name = name;
            this.namespaceParts = namespaceParts;
        }

        private Function find() {
            addIndexedSources(name);
            addDynamicSource(name);

            // A default thunk of a default-named function is called
            // "thunk_FUN_<address>". The thunk itself is not name-indexed, so
            // resolve the underlying dynamic function and follow its thunks.
            if (name.startsWith(DEFAULT_THUNK_PREFIX)) {
                addDynamicSource(name.substring(DEFAULT_THUNK_PREFIX.length()));
            }
            return best;
        }

        private void addIndexedSources(String indexedName) {
            SymbolIterator symbols = program.getSymbolTable().getSymbols(indexedName);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol.getSymbolType() == SymbolType.FUNCTION
                        && symbol.getObject() instanceof Function function) {
                    addSource(function);
                }
            }
        }

        private void addDynamicSource(String dynamicName) {
            Address address = SymbolUtilities.parseDynamicName(
                program.getAddressFactory(), dynamicName);
            if (address != null) {
                addSource(functionManager.getFunctionAt(address));
            }
        }

        private void addSource(Function function) {
            if (function == null || !processedSources.add(function.getEntryPoint())) {
                return;
            }

            consider(function);

            Address[] thunkAddresses = function.getFunctionThunkAddresses(true);
            if (thunkAddresses == null) {
                return;
            }
            for (Address thunkAddress : thunkAddresses) {
                consider(functionManager.getFunctionAt(thunkAddress));
            }
        }

        private void consider(Function function) {
            if (function == null || function.isExternal() || !name.equals(function.getName())) {
                return;
            }
            if (namespaceParts != null && !matchesNamespaceHierarchy(function, namespaceParts)) {
                return;
            }
            if (best == null
                    || function.getEntryPoint().compareTo(best.getEntryPoint()) < 0) {
                best = function;
            }
        }
    }
}

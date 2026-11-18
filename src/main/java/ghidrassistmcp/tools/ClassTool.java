/*
 * MCP tool for class operations.
 * Consolidates list_classes, search_classes, and get_class_info.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool for class operations.
 * Consolidates list_classes, search_classes, and get_class_info.
 *
 * Actions:
 * - list: List all classes with optional pattern filtering and pagination
 * - get_info: Get detailed class information including methods, fields, vtables
 */
public class ClassTool implements McpTool {

    /**
     * Inner class representing a class member with detailed information.
     */
    public static class ClassMemberInfo {
        public enum MemberType {
            METHOD, FIELD, VTABLE, VFUNCTION, TYPEINFO, STATIC_FIELD, CONSTRUCTOR, DESTRUCTOR, OPERATOR
        }

        private String name;
        private String type;
        private MemberType memberType;
        private boolean isStatic;
        private boolean isPublic;
        private Address address;
        private int vtableOffset;
        private List<String> vtableFunctions;

        public ClassMemberInfo(String name, String type, MemberType memberType,
                              boolean isStatic, boolean isPublic, Address address) {
            this.name = name;
            this.type = type;
            this.memberType = memberType;
            this.isStatic = isStatic;
            this.isPublic = isPublic;
            this.address = address;
            this.vtableOffset = -1;
            this.vtableFunctions = new ArrayList<>();
        }

        public ClassMemberInfo(String name, String type, MemberType memberType,
                              boolean isStatic, boolean isPublic, Address address, int vtableOffset) {
            this(name, type, memberType, isStatic, isPublic, address);
            this.vtableOffset = vtableOffset;
        }

        public ClassMemberInfo(String name, String type, MemberType memberType,
                              boolean isStatic, boolean isPublic, Address address, List<String> vtableFunctions) {
            this(name, type, memberType, isStatic, isPublic, address);
            this.vtableFunctions = new ArrayList<>(vtableFunctions);
        }

        public String getName() { return name; }
        public String getType() { return type; }
        public MemberType getMemberType() { return memberType; }
        public boolean isStatic() { return isStatic; }
        public boolean isPublic() { return isPublic; }
        public Address getAddress() { return address; }
        public int getVtableOffset() { return vtableOffset; }
        public List<String> getVtableFunctions() { return vtableFunctions; }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("%s %s%s %s %s",
                isPublic ? "public" : "private",
                isStatic ? "static " : "",
                memberType.toString().toLowerCase(),
                type,
                name));

            if (address != null) {
                sb.append(" @ ").append(address);
            }

            if (vtableOffset >= 0) {
                sb.append(String.format(" [vtable+0x%x]", vtableOffset));
            }

            if (memberType == MemberType.VTABLE && vtableFunctions != null && !vtableFunctions.isEmpty()) {
                sb.append(" -> ");
                for (int i = 0; i < vtableFunctions.size(); i++) {
                    if (i > 0) {
                        sb.append(", ");
                    }
                    sb.append(String.format("vtable[%d]->%s", i, vtableFunctions.get(i)));
                }
            }

            return sb.toString();
        }
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public boolean isLongRunning() {
        return true;  // get_info action uses decompiler
    }

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "classes";
    }

    @Override
    public String getDescription() {
        return "Class operations: list (with optional pattern filtering) or get_info for detailed class information";
    }

    @Override
    public JsonSchema getInputSchema() {
        Map<String, Object> props = new HashMap<>();
        props.put("action", Map.of(
            "type", "string",
            "description", "Class operation to perform",
            "enum", List.of("list", "get_info")
        ));
        props.put("class_name", new JsonSchema("string", null, null, null, null, null));
        props.put("pattern", new JsonSchema("string", null, null, null, null, null));
        props.put("case_sensitive", new JsonSchema("boolean", null, null, null, null, null));
        props.put("offset", new JsonSchema("integer", null, null, null, null, null));
        props.put("limit", new JsonSchema("integer", null, null, null, null, null));

        return new JsonSchema("object", props, List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }

        String action = (String) arguments.get("action");
        if (action == null || action.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("action parameter is required ('list' or 'get_info')").build())
                .build();
        }

        action = action.toLowerCase();

        switch (action) {
            case "list":
                return executeList(arguments, currentProgram);
            case "get_info":
                return executeGetInfo(arguments, currentProgram);
            default:
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Invalid action. Use 'list' or 'get_info'").build())
                    .build();
        }
    }

    // ========== LIST ACTION ==========

    private McpSchema.CallToolResult executeList(Map<String, Object> arguments, Program currentProgram) {
        String pattern = (String) arguments.get("pattern");
        boolean caseSensitive = true;
        if (arguments.get("case_sensitive") instanceof Boolean) {
            caseSensitive = (Boolean) arguments.get("case_sensitive");
        }

        int offset = 0;
        int limit = 100;
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }

        Set<String> allClassNames = getAllClassNames(currentProgram);
        List<String> resultClasses;

        if (pattern != null && !pattern.trim().isEmpty()) {
            // Filter by pattern
            resultClasses = new ArrayList<>();
            String searchPattern = caseSensitive ? pattern : pattern.toLowerCase();

            for (String className : allClassNames) {
                String nameToSearch = caseSensitive ? className : className.toLowerCase();
                if (nameToSearch.contains(searchPattern)) {
                    resultClasses.add(className);
                }
            }
        } else {
            resultClasses = new ArrayList<>(allClassNames);
        }

        Collections.sort(resultClasses);

        StringBuilder result = new StringBuilder();
        if (pattern != null && !pattern.trim().isEmpty()) {
            result.append("Classes matching pattern: \"").append(pattern).append("\"");
            result.append(" (case ").append(caseSensitive ? "sensitive" : "insensitive").append(")\n\n");
        } else {
            result.append("Classes in program:\n\n");
        }

        int totalCount = resultClasses.size();
        int count = 0;

        for (int i = offset; i < resultClasses.size() && count < limit; i++) {
            result.append("- ").append(resultClasses.get(i)).append("\n");
            count++;
        }

        if (totalCount == 0) {
            if (pattern != null && !pattern.trim().isEmpty()) {
                result.append("No classes found matching pattern: \"").append(pattern).append("\"");
            } else {
                result.append("No classes found in the program.");
            }
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount);
            result.append(pattern != null && !pattern.trim().isEmpty() ? " matching classes" : " classes");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }

    // ========== GET_INFO ACTION ==========

    private McpSchema.CallToolResult executeGetInfo(Map<String, Object> arguments, Program currentProgram) {
        String className = (String) arguments.get("class_name");
        if (className == null || className.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("class_name parameter is required for get_info action").build())
                .build();
        }

        Map<String, List<ClassMemberInfo>> members = getClassMembers(className, currentProgram);
        String result = formatClassMembers(className, members);

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result).build())
            .build();
    }

    // ========== SHARED HELPER METHODS ==========

    private Set<String> getAllClassNames(Program program) {
        Set<String> classNames = new HashSet<>();
        SymbolTable symbolTable = program.getSymbolTable();

        // Method 1: Direct SymbolType.CLASS symbols
        try {
            SymbolIterator classSymbols = symbolTable.getAllSymbols(true);
            while (classSymbols.hasNext()) {
                Symbol symbol = classSymbols.next();
                if (symbol.getSymbolType() == SymbolType.CLASS) {
                    classNames.add(symbol.getName(true));
                }
            }
        } catch (Exception e) {
            // Continue with other methods
        }

        // Method 2: Parent namespaces of all symbols
        try {
            SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
            while (allSymbols.hasNext()) {
                Symbol symbol = allSymbols.next();
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    if (isLikelyClass(ns)) {
                        classNames.add(ns.getName(true));
                    }
                }
            }
        } catch (Exception e) {
            // Continue with other methods
        }

        // Method 3: Recursive namespace traversal
        try {
            findClassesRecursively(program.getGlobalNamespace(), symbolTable, classNames);
        } catch (Exception e) {
            // Continue with other methods
        }

        // Method 4: C++ mangled name heuristics
        try {
            findCppClassesFromMangledNames(symbolTable, classNames);
        } catch (Exception e) {
            // Continue with other methods
        }

        // Method 5: Look for vtables
        try {
            findClassesFromVTables(symbolTable, classNames);
        } catch (Exception e) {
            // Continue with other methods
        }

        return classNames;
    }

    private boolean isLikelyClass(Namespace namespace) {
        SymbolType type = namespace.getSymbol().getSymbolType();
        return type == SymbolType.CLASS || type == SymbolType.NAMESPACE;
    }

    private void findClassesRecursively(Namespace namespace, SymbolTable symbolTable, Set<String> classNames) {
        try {
            SymbolIterator children = symbolTable.getSymbols(namespace);
            while (children.hasNext()) {
                Symbol symbol = children.next();
                if (symbol.getSymbolType() == SymbolType.CLASS) {
                    classNames.add(symbol.getName(true));
                }

                if (symbol.getSymbolType() == SymbolType.NAMESPACE) {
                    Object obj = symbol.getObject();
                    if (obj instanceof Namespace) {
                        Namespace childNamespace = (Namespace) obj;
                        findClassesRecursively(childNamespace, symbolTable, classNames);
                    }
                }
            }
        } catch (Exception e) {
            // Skip if we can't traverse this namespace
        }
    }

    private void findCppClassesFromMangledNames(SymbolTable symbolTable, Set<String> classNames) {
        try {
            SymbolIterator allSymbols = symbolTable.getAllSymbols(true);

            while (allSymbols.hasNext()) {
                Symbol symbol = allSymbols.next();
                String name = symbol.getName();

                if (name.contains("::")) {
                    if (name.contains("ctor") || name.contains("dtor") ||
                        name.matches(".*::[~]?\\w+\\(.*\\)")) {

                        String className = extractClassNameFromMethod(name);
                        if (className != null && !className.isEmpty()) {
                            classNames.add(className);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Skip if symbol iteration fails
        }
    }

    private void findClassesFromVTables(SymbolTable symbolTable, Set<String> classNames) {
        try {
            SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
            while (allSymbols.hasNext()) {
                Symbol symbol = allSymbols.next();
                String name = symbol.getName();

                if (name.toLowerCase().contains("vtable") || name.toLowerCase().contains("vftable")) {
                    String className = extractClassNameFromVTable(name);
                    if (className != null && !className.isEmpty()) {
                        classNames.add(className);
                    }
                }
            }
        } catch (Exception e) {
            // Skip if symbol iteration fails
        }
    }

    private String extractClassNameFromMethod(String methodName) {
        int lastScope = methodName.lastIndexOf("::");
        if (lastScope > 0) {
            return methodName.substring(0, lastScope);
        }
        return null;
    }

    private String extractClassNameFromVTable(String vtableName) {
        if (vtableName.startsWith("vtable for ")) {
            return vtableName.substring("vtable for ".length());
        }
        if (vtableName.startsWith("vftable for ")) {
            return vtableName.substring("vftable for ".length());
        }
        if (vtableName.contains("::vtable")) {
            return vtableName.substring(0, vtableName.indexOf("::vtable"));
        }
        if (vtableName.contains("::vftable")) {
            return vtableName.substring(0, vtableName.indexOf("::vftable"));
        }
        return null;
    }

    // ========== GET_INFO METHODS ==========

    private Map<String, List<ClassMemberInfo>> getClassMembers(String className, Program program) {
        Map<String, List<ClassMemberInfo>> members = new HashMap<>();
        members.put("methods", new ArrayList<>());
        members.put("fields", new ArrayList<>());
        members.put("vtables", new ArrayList<>());
        members.put("virtual_functions", new ArrayList<>());
        members.put("typeinfo", new ArrayList<>());
        members.put("static_members", new ArrayList<>());

        SymbolTable symbolTable = program.getSymbolTable();
        Listing listing = program.getListing();

        Namespace classNamespace = findClassNamespace(className, program);
        if (classNamespace != null) {
            List<Symbol> classSymbols = getSymbolsInNamespace(classNamespace, symbolTable);

            for (Symbol symbol : classSymbols) {
                analyzeSymbol(symbol, className, members, listing, program);
            }
        }

        findVTablesAndTypeInfo(className, members, symbolTable, listing, program);
        extractVirtualFunctions(members, listing, program);

        for (List<ClassMemberInfo> memberList : members.values()) {
            memberList.sort(Comparator.comparing(ClassMemberInfo::getName));
        }

        return members;
    }

    private Namespace findClassNamespace(String className, Program program) {
        Set<String> allClassNames = getAllClassNames(program);

        String targetClassName = null;
        for (String foundClassName : allClassNames) {
            if (foundClassName.equals(className)) {
                targetClassName = foundClassName;
                break;
            }
            String[] parts = foundClassName.split("::");
            if (parts.length > 0 && parts[parts.length - 1].equals(className)) {
                targetClassName = foundClassName;
                break;
            }
        }

        if (targetClassName == null) {
            for (String foundClassName : allClassNames) {
                if (foundClassName.toLowerCase().equals(className.toLowerCase())) {
                    targetClassName = foundClassName;
                    break;
                }
                String[] parts = foundClassName.split("::");
                if (parts.length > 0 && parts[parts.length - 1].toLowerCase().equals(className.toLowerCase())) {
                    targetClassName = foundClassName;
                    break;
                }
            }
        }

        if (targetClassName == null) {
            return null;
        }

        return findNamespaceForClassName(targetClassName, program);
    }

    private Namespace findNamespaceForClassName(String className, Program program) {
        SymbolTable symbolTable = program.getSymbolTable();

        try {
            SymbolIterator symbolIter = symbolTable.getAllSymbols(true);
            while (symbolIter.hasNext()) {
                Symbol symbol = symbolIter.next();
                if (symbol.getSymbolType() == SymbolType.CLASS) {
                    if (symbol.getName().equals(className) || symbol.getName(true).equals(className)) {
                        Object obj = symbol.getObject();
                        if (obj instanceof Namespace) {
                            return (Namespace) obj;
                        }
                    }
                }
            }

            symbolIter = symbolTable.getAllSymbols(true);
            while (symbolIter.hasNext()) {
                Symbol symbol = symbolIter.next();
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    if (ns.getName().equals(className) || ns.getName(true).equals(className)) {
                        if (ns.getSymbol().getSymbolType() == SymbolType.CLASS) {
                            return ns;
                        }
                    }
                }
            }

            symbolIter = symbolTable.getAllSymbols(true);
            while (symbolIter.hasNext()) {
                Symbol symbol = symbolIter.next();
                String symbolName = symbol.getName();

                if (symbolName.contains("::") && symbolName.contains(className)) {
                    if (symbolName.contains("ctor") || symbolName.contains("dtor") ||
                        symbolName.matches(".*::" + className + "::.*")) {

                        Namespace ns = symbol.getParentNamespace();
                        if (ns != null && !ns.isGlobal() &&
                            (ns.getName().equals(className) || ns.getName(true).contains(className))) {
                            return ns;
                        }
                    }
                }
            }

        } catch (Exception e) {
            // Continue to return null
        }

        return null;
    }

    private List<Symbol> getSymbolsInNamespace(Namespace namespace, SymbolTable symbolTable) {
        List<Symbol> symbols = new ArrayList<>();

        try {
            SymbolIterator symbolIter = symbolTable.getSymbols(namespace);
            while (symbolIter.hasNext()) {
                symbols.add(symbolIter.next());
            }
        } catch (Exception e) {
            // Return empty list
        }

        return symbols;
    }

    private void analyzeSymbol(Symbol symbol, String className,
                              Map<String, List<ClassMemberInfo>> members,
                              Listing listing, Program program) {
        String symbolName = symbol.getName();
        SymbolType symbolType = symbol.getSymbolType();
        Address address = symbol.getAddress();

        if (isVTable(symbol, className)) {
            List<String> vtableFunctions = parseVTableFunctions(symbol, listing, program);
            ClassMemberInfo vtable = new ClassMemberInfo(
                symbolName, "vtable", ClassMemberInfo.MemberType.VTABLE,
                true, false, address, vtableFunctions);
            members.get("vtables").add(vtable);
            return;
        }

        if (isTypeInfo(symbol, className)) {
            ClassMemberInfo typeinfo = new ClassMemberInfo(
                symbolName, "typeinfo", ClassMemberInfo.MemberType.TYPEINFO,
                true, false, address);
            members.get("typeinfo").add(typeinfo);
            return;
        }

        if (symbolType == SymbolType.FUNCTION) {
            ClassMemberInfo method = createMethodInfo(symbol, listing);
            if (method != null) {
                members.get("methods").add(method);
            }
        } else if (symbolType == SymbolType.GLOBAL) {
            ClassMemberInfo staticMember = createStaticMemberInfo(symbol, listing);
            if (staticMember != null) {
                members.get("static_members").add(staticMember);
            }
        } else if (symbolType == SymbolType.LOCAL_VAR || symbolType == SymbolType.PARAMETER) {
            ClassMemberInfo field = createFieldInfo(symbol, listing);
            if (field != null) {
                members.get("fields").add(field);
            }
        } else if (symbolType == SymbolType.LABEL) {
            analyzeLabel(symbol, className, members, listing);
        } else {
            ClassMemberInfo generic = createGenericMemberInfo(symbol, listing);
            if (generic != null) {
                members.get("fields").add(generic);
            }
        }
    }

    private boolean isVTable(Symbol symbol, String className) {
        String name = symbol.getName().toLowerCase();
        String classLower = className.toLowerCase();

        return name.contains("vtable") ||
               name.contains("vftable") ||
               name.contains("_ztv") ||
               name.contains("_7" + classLower) ||
               (name.contains(classLower) && name.contains("vft")) ||
               name.matches(".*vtbl.*") ||
               name.matches(".*::" + classLower + "::.*vtable.*") ||
               name.matches(".*::" + classLower + "::.*vftable.*") ||
               name.equals(classLower + "::vftable") ||
               name.endsWith("::vftable") ||
               name.endsWith("::vtable");
    }

    private boolean isTypeInfo(Symbol symbol, String className) {
        String name = symbol.getName().toLowerCase();
        String classLower = className.toLowerCase();

        return name.contains("typeinfo") ||
               name.contains("_zti") ||
               name.contains("_rti") ||
               name.contains("class_type_info") ||
               (name.contains(classLower) && (name.contains("rtti") || name.contains("type")));
    }

    private ClassMemberInfo createMethodInfo(Symbol symbol, Listing listing) {
        String methodName = symbol.getName();
        String returnType = "unknown";
        ClassMemberInfo.MemberType memberType = ClassMemberInfo.MemberType.METHOD;

        Function function = listing.getFunctionAt(symbol.getAddress());
        if (function != null && function.getSignature() != null) {
            returnType = function.getSignature().getReturnType().getDisplayName();
        }

        if (methodName.contains("ctor") || methodName.contains("constructor")) {
            memberType = ClassMemberInfo.MemberType.CONSTRUCTOR;
        } else if (methodName.contains("dtor") || methodName.contains("destructor") || methodName.startsWith("~")) {
            memberType = ClassMemberInfo.MemberType.DESTRUCTOR;
        } else if (methodName.contains("operator")) {
            memberType = ClassMemberInfo.MemberType.OPERATOR;
        }

        return new ClassMemberInfo(methodName, returnType, memberType,
                                  false, true, symbol.getAddress());
    }

    private ClassMemberInfo createFieldInfo(Symbol symbol, Listing listing) {
        String fieldName = symbol.getName();
        String fieldType = "unknown";

        Data data = listing.getDataAt(symbol.getAddress());
        if (data != null && data.getDataType() != null) {
            fieldType = data.getDataType().getDisplayName();
        }

        return new ClassMemberInfo(fieldName, fieldType, ClassMemberInfo.MemberType.FIELD,
                                  false, true, symbol.getAddress());
    }

    private ClassMemberInfo createStaticMemberInfo(Symbol symbol, Listing listing) {
        String fieldName = symbol.getName();
        String fieldType = "unknown";

        Data data = listing.getDataAt(symbol.getAddress());
        if (data != null && data.getDataType() != null) {
            fieldType = data.getDataType().getDisplayName();
        }

        return new ClassMemberInfo(fieldName, fieldType, ClassMemberInfo.MemberType.STATIC_FIELD,
                                  true, true, symbol.getAddress());
    }

    private ClassMemberInfo createGenericMemberInfo(Symbol symbol, Listing listing) {
        String memberName = symbol.getName();
        String memberType = "unknown";

        Data data = listing.getDataAt(symbol.getAddress());
        if (data != null && data.getDataType() != null) {
            memberType = data.getDataType().getDisplayName();
        }

        return new ClassMemberInfo(memberName, memberType, ClassMemberInfo.MemberType.FIELD,
                                  false, true, symbol.getAddress());
    }

    private void analyzeLabel(Symbol symbol, String className,
                             Map<String, List<ClassMemberInfo>> members, Listing listing) {

        if (isVTable(symbol, className) || isTypeInfo(symbol, className)) {
            return;
        }

        ClassMemberInfo labelMember = createGenericMemberInfo(symbol, listing);
        if (labelMember != null) {
            if (isLikelyMethod(symbol, listing)) {
                labelMember = new ClassMemberInfo(labelMember.getName(), labelMember.getType(),
                                                 ClassMemberInfo.MemberType.METHOD,
                                                 labelMember.isStatic(), labelMember.isPublic(),
                                                 labelMember.getAddress());
                members.get("methods").add(labelMember);
            } else {
                members.get("fields").add(labelMember);
            }
        }
    }

    private boolean isLikelyMethod(Symbol symbol, Listing listing) {
        Function function = listing.getFunctionAt(symbol.getAddress());
        return function != null;
    }

    private void findVTablesAndTypeInfo(String className, Map<String, List<ClassMemberInfo>> members,
                                       SymbolTable symbolTable, Listing listing, Program program) {

        try {
            SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
            String classNameLower = className.toLowerCase();
            while (allSymbols.hasNext()) {
                Symbol symbol = allSymbols.next();
                String symbolNameLower = symbol.getName().toLowerCase();
                if ((symbolNameLower.contains("vtable") || symbolNameLower.contains("vftable")) &&
                    symbolNameLower.contains(classNameLower)) {
                    if (isVTable(symbol, className)) {
                        List<String> vtableFunctions = parseVTableFunctions(symbol, listing, program);
                        ClassMemberInfo vtable = new ClassMemberInfo(
                            symbol.getName(), "vtable", ClassMemberInfo.MemberType.VTABLE,
                            true, false, symbol.getAddress(), vtableFunctions);
                        members.get("vtables").add(vtable);
                    }
                }
            }
        } catch (Exception e) {
            // Continue if symbol iteration fails
        }

        try {
            SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
            while (allSymbols.hasNext()) {
                Symbol symbol = allSymbols.next();
                if (symbol.getName().toLowerCase().contains("typeinfo") &&
                    symbol.getName().toLowerCase().contains(className.toLowerCase())) {
                    if (isTypeInfo(symbol, className)) {
                        ClassMemberInfo typeinfo = new ClassMemberInfo(
                            symbol.getName(), "typeinfo", ClassMemberInfo.MemberType.TYPEINFO,
                            true, false, symbol.getAddress());
                        members.get("typeinfo").add(typeinfo);
                    }
                }
            }
        } catch (Exception e) {
            // Continue if search fails
        }
    }

    private List<String> parseVTableFunctions(Symbol vtableSymbol, Listing listing, Program program) {
        List<String> functions = new ArrayList<>();
        Address vtableAddr = vtableSymbol.getAddress();

        if (vtableAddr == null) {
            return functions;
        }

        try {
            Data vtableData = listing.getDataAt(vtableAddr);
            if (vtableData != null) {
                functions.addAll(parseVTableEntriesForDisplay(vtableData, listing, program));
            } else {
                functions.addAll(parseVTableManuallyForDisplay(vtableAddr, listing, program));
            }
        } catch (Exception e) {
            try {
                functions.addAll(parseVTableManuallyForDisplay(vtableAddr, listing, program));
            } catch (Exception e2) {
                // Return empty list
            }
        }

        return functions;
    }

    private List<String> parseVTableEntriesForDisplay(Data vtableData, Listing listing, Program program) {
        List<String> functions = new ArrayList<>();

        DataType dataType = vtableData.getDataType();
        if (dataType instanceof Array) {
            Array arrayType = (Array) dataType;
            int numElements = arrayType.getNumElements();

            for (int i = 0; i < numElements; i++) {
                Data elementData = vtableData.getComponent(i);
                if (elementData != null) {
                    Address functionAddr = getFunctionAddressFromPointer(elementData, program);
                    if (functionAddr != null) {
                        Function virtualFunction = listing.getFunctionAt(functionAddr);
                        if (virtualFunction != null) {
                            functions.add(virtualFunction.getName());
                        } else {
                            functions.add("FUN_" + functionAddr.toString().replace(":", ""));
                        }
                    }
                }
            }
        }

        return functions;
    }

    private List<String> parseVTableManuallyForDisplay(Address vtableAddr, Listing listing, Program program) {
        List<String> functions = new ArrayList<>();

        int pointerSize = program.getDefaultPointerSize();
        Address currentAddr = vtableAddr;

        for (int i = 0; i < 50; i++) {
            try {
                Data pointerData = listing.getDataAt(currentAddr);
                Address functionAddr = null;

                if (pointerData != null && pointerData.getDataType() instanceof Pointer) {
                    functionAddr = getFunctionAddressFromPointer(pointerData, program);
                } else {
                    long pointerValue = program.getMemory().getLong(currentAddr);
                    if (pointerValue != 0) {
                        try {
                            functionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(pointerValue);
                        } catch (Exception e) {
                            break;
                        }
                    }
                }

                if (functionAddr != null) {
                    Function virtualFunction = listing.getFunctionAt(functionAddr);
                    if (virtualFunction != null) {
                        functions.add(virtualFunction.getName());
                    } else {
                        if (program.getMemory().contains(functionAddr)) {
                            functions.add("FUN_" + functionAddr.toString().replace(":", ""));
                        } else {
                            break;
                        }
                    }
                } else {
                    break;
                }

                currentAddr = currentAddr.add(pointerSize);

            } catch (Exception e) {
                break;
            }
        }

        return functions;
    }

    private void extractVirtualFunctions(Map<String, List<ClassMemberInfo>> members,
                                       Listing listing, Program program) {

        for (ClassMemberInfo vtable : members.get("vtables")) {
            Address vtableAddr = vtable.getAddress();

            Data vtableData = listing.getDataAt(vtableAddr);
            if (vtableData != null) {
                parseVTableEntries(vtableData, members.get("virtual_functions"), listing, program);
            } else {
                parseVTableManually(vtableAddr, members.get("virtual_functions"), listing, program);
            }
        }
    }

    private void parseVTableEntries(Data vtableData, List<ClassMemberInfo> virtualFunctions,
                                   Listing listing, Program program) {

        DataType dataType = vtableData.getDataType();
        if (dataType instanceof Array) {
            Array arrayType = (Array) dataType;
            int numElements = arrayType.getNumElements();

            for (int i = 0; i < numElements; i++) {
                Data elementData = vtableData.getComponent(i);
                if (elementData != null) {
                    Address functionAddr = getFunctionAddressFromPointer(elementData, program);
                    if (functionAddr != null) {
                        Function virtualFunction = listing.getFunctionAt(functionAddr);
                        if (virtualFunction != null) {
                            ClassMemberInfo vfunc = new ClassMemberInfo(
                                virtualFunction.getName(),
                                virtualFunction.getSignature() != null ?
                                    virtualFunction.getSignature().getReturnType().getDisplayName() : "unknown",
                                ClassMemberInfo.MemberType.VFUNCTION,
                                false, true, functionAddr, i * program.getDefaultPointerSize());
                            virtualFunctions.add(vfunc);
                        }
                    }
                }
            }
        }
    }

    private void parseVTableManually(Address vtableAddr, List<ClassMemberInfo> virtualFunctions,
                                    Listing listing, Program program) {

        int pointerSize = program.getDefaultPointerSize();
        Address currentAddr = vtableAddr;
        int offset = 0;

        for (int i = 0; i < 50; i++) {
            try {
                Data pointerData = listing.getDataAt(currentAddr);
                Address functionAddr = null;

                if (pointerData != null && pointerData.getDataType() instanceof Pointer) {
                    functionAddr = getFunctionAddressFromPointer(pointerData, program);
                } else {
                    long pointerValue = program.getMemory().getLong(currentAddr);
                    if (pointerValue != 0) {
                        functionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(pointerValue);
                    }
                }

                if (functionAddr != null) {
                    Function virtualFunction = listing.getFunctionAt(functionAddr);
                    if (virtualFunction != null) {
                        ClassMemberInfo vfunc = new ClassMemberInfo(
                            virtualFunction.getName(),
                            virtualFunction.getSignature() != null ?
                                virtualFunction.getSignature().getReturnType().getDisplayName() : "unknown",
                            ClassMemberInfo.MemberType.VFUNCTION,
                            false, true, functionAddr, offset);
                        virtualFunctions.add(vfunc);
                    }
                } else {
                    break;
                }

                currentAddr = currentAddr.add(pointerSize);
                offset += pointerSize;

            } catch (Exception e) {
                break;
            }
        }
    }

    private Address getFunctionAddressFromPointer(Data pointerData, Program program) {
        if (pointerData.getDataType() instanceof Pointer) {
            Object value = pointerData.getValue();
            if (value instanceof Address) {
                return (Address) value;
            }
        }
        return null;
    }

    private String formatClassMembers(String className, Map<String, List<ClassMemberInfo>> members) {
        StringBuilder result = new StringBuilder();
        result.append("Class: ").append(className).append("\n\n");

        if (!members.get("methods").isEmpty()) {
            result.append("Methods (").append(members.get("methods").size()).append("):\n");
            for (ClassMemberInfo method : members.get("methods")) {
                result.append("  ").append(method.toString()).append("\n");
            }
            result.append("\n");
        }

        if (!members.get("fields").isEmpty()) {
            result.append("Fields (").append(members.get("fields").size()).append("):\n");
            for (ClassMemberInfo field : members.get("fields")) {
                result.append("  ").append(field.toString()).append("\n");
            }
            result.append("\n");
        }

        if (!members.get("vtables").isEmpty()) {
            result.append("VTables (").append(members.get("vtables").size()).append("):\n");
            for (ClassMemberInfo vtable : members.get("vtables")) {
                result.append("  ").append(vtable.toString()).append("\n");
            }
            result.append("\n");
        }

        if (!members.get("virtual_functions").isEmpty()) {
            result.append("Virtual Functions (").append(members.get("virtual_functions").size()).append("):\n");
            for (ClassMemberInfo vfunc : members.get("virtual_functions")) {
                result.append("  ").append(vfunc.toString()).append("\n");
            }
            result.append("\n");
        }

        if (!members.get("static_members").isEmpty()) {
            result.append("Static Members (").append(members.get("static_members").size()).append("):\n");
            for (ClassMemberInfo staticMember : members.get("static_members")) {
                result.append("  ").append(staticMember.toString()).append("\n");
            }
            result.append("\n");
        }

        if (!members.get("typeinfo").isEmpty()) {
            result.append("Type Info (").append(members.get("typeinfo").size()).append("):\n");
            for (ClassMemberInfo typeinfo : members.get("typeinfo")) {
                result.append("  ").append(typeinfo.toString()).append("\n");
            }
            result.append("\n");
        }

        int totalMembers = members.values().stream().mapToInt(List::size).sum();
        if (totalMembers == 0) {
            result.append("No class members found for class: ").append(className);
        } else {
            result.append("Total members found: ").append(totalMembers);
        }

        return result.toString();
    }
}

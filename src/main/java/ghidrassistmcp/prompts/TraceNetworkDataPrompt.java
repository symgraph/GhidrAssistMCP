/*
 * MCP Prompt for tracing network data flows.
 */
package ghidrassistmcp.prompts;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.decompiler.DecompilerSession;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Prompt for tracing network send/recv call stacks to analyze protocol
 * payload data structures and identify network-related vulnerabilities.
 * Supports both POSIX and Winsock network APIs.
 */
public class TraceNetworkDataPrompt implements McpPrompt {

    private final DecompilerService decompilerService;

    public TraceNetworkDataPrompt(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    // POSIX network functions
    private static final String[] POSIX_SEND_FUNCTIONS = {
        "send", "sendto", "sendmsg", "write", "writev", "sendfile",
        "SSL_write", "gnutls_record_send", "BIO_write"
    };

    private static final String[] POSIX_RECV_FUNCTIONS = {
        "recv", "recvfrom", "recvmsg", "read", "readv",
        "SSL_read", "gnutls_record_recv", "BIO_read"
    };

    private static final String[] POSIX_SOCKET_FUNCTIONS = {
        "socket", "connect", "bind", "listen", "accept", "accept4",
        "shutdown", "close", "getsockopt", "setsockopt",
        "getpeername", "getsockname", "socketpair"
    };

    // Winsock network functions
    private static final String[] WINSOCK_SEND_FUNCTIONS = {
        "send", "sendto", "WSASend", "WSASendTo", "WSASendMsg",
        "WSASendDisconnect", "TransmitFile", "TransmitPackets"
    };

    private static final String[] WINSOCK_RECV_FUNCTIONS = {
        "recv", "recvfrom", "WSARecv", "WSARecvFrom", "WSARecvMsg",
        "WSARecvDisconnect"
    };

    private static final String[] WINSOCK_SOCKET_FUNCTIONS = {
        "socket", "WSASocket", "WSASocketA", "WSASocketW",
        "connect", "WSAConnect", "WSAConnectByName", "WSAConnectByList",
        "bind", "listen", "accept", "WSAAccept",
        "shutdown", "closesocket", "WSACleanup", "WSAStartup",
        "getsockopt", "setsockopt", "ioctlsocket", "WSAIoctl",
        "getpeername", "getsockname", "select", "WSAPoll",
        "WSAAsyncSelect", "WSAEventSelect"
    };

    // Network-related dangerous patterns
    private static final String[] NETWORK_DANGEROUS_FUNCTIONS = {
        "strcpy", "strcat", "sprintf", "vsprintf", "gets",
        "memcpy", "memmove", "bcopy",
        "atoi", "atol", "strtol", "strtoul",  // Integer parsing from network data
        "ntohl", "ntohs", "htonl", "htons"     // Byte order conversion
    };

    @Override
    public String getName() {
        return "trace_network_data";
    }

    @Override
    public String getDescription() {
        return "Trace network send/recv call stacks for POSIX and Winsock APIs to analyze " +
               "protocol payload data structures and identify network-related vulnerabilities";
    }

    @Override
    public List<McpSchema.PromptArgument> getArguments() {
        return List.of(
            new McpSchema.PromptArgument(
                "function_name",
                "Name or address of a specific function to analyze (optional - if not provided, analyzes all network functions)",
                false
            ),
            new McpSchema.PromptArgument(
                "direction",
                "Filter by direction: 'send', 'recv', or 'both' (default: both)",
                false
            ),
            new McpSchema.PromptArgument(
                "api",
                "Filter by API: 'posix', 'winsock', or 'both' (default: both)",
                false
            )
        );
    }

    @Override
    public McpSchema.GetPromptResult generatePrompt(Map<String, String> arguments, Program program) {
        String functionIdentifier = arguments.get("function_name");
        String direction = arguments.getOrDefault("direction", "both").toLowerCase();
        String api = arguments.getOrDefault("api", "both").toLowerCase();

        StringBuilder context = new StringBuilder();
        context.append("# Network Data Flow Analysis Request\n\n");
        context.append("Analyze network send/recv operations to understand protocol payload ");
        context.append("data structures and identify potential network-related vulnerabilities.\n\n");

        if (program != null) {
            // Find network functions in the program
            Map<String, List<Function>> networkFunctions = findNetworkFunctions(program, direction, api);

            if (functionIdentifier != null && !functionIdentifier.isEmpty()) {
                // Analyze a specific function's relationship to network operations
                Function targetFunction = findFunction(program, functionIdentifier);
                if (targetFunction != null) {
                    context.append("## Target Function Analysis\n");
                    context.append("- **Name**: ").append(targetFunction.getName()).append("\n");
                    context.append("- **Address**: ").append(targetFunction.getEntryPoint()).append("\n");
                    context.append("- **Signature**: ").append(targetFunction.getPrototypeString(false, false)).append("\n\n");

                    // Decompile the target function
                    String decompiled = decompileFunction(program, targetFunction);
                    if (decompiled != null) {
                        context.append("### Decompiled Code\n```c\n");
                        context.append(decompiled);
                        context.append("\n```\n\n");
                    }

                    // Find network functions called by this function
                    context.append("### Network Functions Called\n");
                    appendCalledNetworkFunctions(context, targetFunction, networkFunctions, program);
                } else {
                    context.append("**Warning**: Function '").append(functionIdentifier).append("' not found.\n\n");
                }
            }

            // List discovered network functions
            context.append("## Discovered Network Functions in Binary\n\n");
            appendNetworkFunctionSummary(context, networkFunctions, program);

            // Find callers of network functions (call stack analysis)
            context.append("## Network Function Call Stacks\n\n");
            appendCallStackAnalysis(context, networkFunctions, program);

        } else {
            context.append("**Note**: No program loaded. Please provide function details manually.\n\n");
        }

        // Analysis guidance
        appendAnalysisGuidance(context);

        List<McpSchema.PromptMessage> messages = new ArrayList<>();
        messages.add(new McpSchema.PromptMessage(
            McpSchema.Role.USER,
            new McpSchema.TextContent(context.toString())
        ));

        String description = "Trace network data";
        if (functionIdentifier != null && !functionIdentifier.isEmpty()) {
            description += " for: " + functionIdentifier;
        }

        return new McpSchema.GetPromptResult(description, messages);
    }

    private Map<String, List<Function>> findNetworkFunctions(Program program, String direction, String api) {
        Map<String, List<Function>> result = new LinkedHashMap<>();
        result.put("send", new ArrayList<>());
        result.put("recv", new ArrayList<>());
        result.put("socket", new ArrayList<>());

        Set<String> sendFuncs = new HashSet<>();
        Set<String> recvFuncs = new HashSet<>();
        Set<String> socketFuncs = new HashSet<>();

        // Add functions based on API filter
        if (api.equals("posix") || api.equals("both")) {
            if (direction.equals("send") || direction.equals("both")) {
                for (String f : POSIX_SEND_FUNCTIONS) sendFuncs.add(f);
            }
            if (direction.equals("recv") || direction.equals("both")) {
                for (String f : POSIX_RECV_FUNCTIONS) recvFuncs.add(f);
            }
            for (String f : POSIX_SOCKET_FUNCTIONS) socketFuncs.add(f);
        }

        if (api.equals("winsock") || api.equals("both")) {
            if (direction.equals("send") || direction.equals("both")) {
                for (String f : WINSOCK_SEND_FUNCTIONS) sendFuncs.add(f);
            }
            if (direction.equals("recv") || direction.equals("both")) {
                for (String f : WINSOCK_RECV_FUNCTIONS) recvFuncs.add(f);
            }
            for (String f : WINSOCK_SOCKET_FUNCTIONS) socketFuncs.add(f);
        }

        // Search for functions in the program
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbols = symbolTable.getAllSymbols(true);

        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            String name = symbol.getName();

            // Check if it's a function
            Function func = program.getFunctionManager().getFunctionAt(symbol.getAddress());
            if (func == null) {
                func = program.getFunctionManager().getReferencedFunction(symbol.getAddress());
            }

            if (func != null || symbol.isExternal()) {
                if (sendFuncs.contains(name)) {
                    result.get("send").add(func != null ? func : createPlaceholderFunction(name, symbol));
                } else if (recvFuncs.contains(name)) {
                    result.get("recv").add(func != null ? func : createPlaceholderFunction(name, symbol));
                } else if (socketFuncs.contains(name)) {
                    result.get("socket").add(func != null ? func : createPlaceholderFunction(name, symbol));
                }
            }
        }

        return result;
    }

    private Function createPlaceholderFunction(String name, Symbol symbol) {
        // For external functions, we return null but track via symbol
        return null;
    }

    private void appendNetworkFunctionSummary(StringBuilder context, Map<String, List<Function>> networkFunctions, Program program) {
        SymbolTable symbolTable = program.getSymbolTable();

        context.append("### Send Functions\n");
        if (networkFunctions.get("send").isEmpty()) {
            // Check for external symbols
            List<String> externalSend = findExternalNetworkSymbols(symbolTable, POSIX_SEND_FUNCTIONS, WINSOCK_SEND_FUNCTIONS);
            if (externalSend.isEmpty()) {
                context.append("No send functions found.\n\n");
            } else {
                for (String name : externalSend) {
                    context.append("- **").append(name).append("** (external/imported)\n");
                }
                context.append("\n");
            }
        } else {
            for (Function func : networkFunctions.get("send")) {
                if (func != null) {
                    context.append("- **").append(func.getName(true)).append("** @ ").append(func.getEntryPoint()).append("\n");
                }
            }
            context.append("\n");
        }

        context.append("### Recv Functions\n");
        if (networkFunctions.get("recv").isEmpty()) {
            List<String> externalRecv = findExternalNetworkSymbols(symbolTable, POSIX_RECV_FUNCTIONS, WINSOCK_RECV_FUNCTIONS);
            if (externalRecv.isEmpty()) {
                context.append("No recv functions found.\n\n");
            } else {
                for (String name : externalRecv) {
                    context.append("- **").append(name).append("** (external/imported)\n");
                }
                context.append("\n");
            }
        } else {
            for (Function func : networkFunctions.get("recv")) {
                if (func != null) {
                    context.append("- **").append(func.getName(true)).append("** @ ").append(func.getEntryPoint()).append("\n");
                }
            }
            context.append("\n");
        }

        context.append("### Socket Management Functions\n");
        if (networkFunctions.get("socket").isEmpty()) {
            List<String> externalSocket = findExternalNetworkSymbols(symbolTable, POSIX_SOCKET_FUNCTIONS, WINSOCK_SOCKET_FUNCTIONS);
            if (externalSocket.isEmpty()) {
                context.append("No socket functions found.\n\n");
            } else {
                for (String name : externalSocket) {
                    context.append("- **").append(name).append("** (external/imported)\n");
                }
                context.append("\n");
            }
        } else {
            for (Function func : networkFunctions.get("socket")) {
                if (func != null) {
                    context.append("- **").append(func.getName(true)).append("** @ ").append(func.getEntryPoint()).append("\n");
                }
            }
            context.append("\n");
        }
    }

    private List<String> findExternalNetworkSymbols(SymbolTable symbolTable, String[]... functionArrays) {
        List<String> found = new ArrayList<>();
        Set<String> targetNames = new HashSet<>();

        for (String[] arr : functionArrays) {
            for (String name : arr) {
                targetNames.add(name);
            }
        }

        SymbolIterator symbols = symbolTable.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (targetNames.contains(symbol.getName())) {
                found.add(symbol.getName());
            }
        }

        return found;
    }

    private void appendCalledNetworkFunctions(StringBuilder context, Function targetFunction,
                                              Map<String, List<Function>> networkFunctions, Program program) {
        Set<String> allNetworkNames = new HashSet<>();

        for (String f : POSIX_SEND_FUNCTIONS) allNetworkNames.add(f);
        for (String f : POSIX_RECV_FUNCTIONS) allNetworkNames.add(f);
        for (String f : POSIX_SOCKET_FUNCTIONS) allNetworkNames.add(f);
        for (String f : WINSOCK_SEND_FUNCTIONS) allNetworkNames.add(f);
        for (String f : WINSOCK_RECV_FUNCTIONS) allNetworkNames.add(f);
        for (String f : WINSOCK_SOCKET_FUNCTIONS) allNetworkNames.add(f);

        var calledFunctions = targetFunction.getCalledFunctions(TaskMonitor.DUMMY);
        boolean foundNetwork = false;

        for (Function called : calledFunctions) {
            if (allNetworkNames.contains(called.getName())) {
                String category = categorizeNetworkFunction(called.getName());
                context.append("- **").append(called.getName()).append("** (").append(category).append(") @ ")
                       .append(called.getEntryPoint()).append("\n");
                foundNetwork = true;
            }
        }

        if (!foundNetwork) {
            context.append("No direct network function calls found. This function may be part of a call chain.\n");
        }
        context.append("\n");
    }

    private String categorizeNetworkFunction(String name) {
        for (String f : POSIX_SEND_FUNCTIONS) if (f.equals(name)) return "POSIX send";
        for (String f : POSIX_RECV_FUNCTIONS) if (f.equals(name)) return "POSIX recv";
        for (String f : POSIX_SOCKET_FUNCTIONS) if (f.equals(name)) return "POSIX socket";
        for (String f : WINSOCK_SEND_FUNCTIONS) if (f.equals(name)) return "Winsock send";
        for (String f : WINSOCK_RECV_FUNCTIONS) if (f.equals(name)) return "Winsock recv";
        for (String f : WINSOCK_SOCKET_FUNCTIONS) if (f.equals(name)) return "Winsock socket";
        return "network";
    }

    private void appendCallStackAnalysis(StringBuilder context, Map<String, List<Function>> networkFunctions, Program program) {
        SymbolTable symbolTable = program.getSymbolTable();

        // Find callers of send functions
        context.append("### Functions Calling Send Operations\n");
        appendCallersForCategory(context, "send", symbolTable, program, POSIX_SEND_FUNCTIONS, WINSOCK_SEND_FUNCTIONS);

        context.append("### Functions Calling Recv Operations\n");
        appendCallersForCategory(context, "recv", symbolTable, program, POSIX_RECV_FUNCTIONS, WINSOCK_RECV_FUNCTIONS);
    }

    private void appendCallersForCategory(StringBuilder context, String category, SymbolTable symbolTable,
                                          Program program, String[]... functionArrays) {
        Set<String> targetNames = new HashSet<>();
        for (String[] arr : functionArrays) {
            for (String name : arr) {
                targetNames.add(name);
            }
        }

        Set<String> callerNames = new HashSet<>();
        SymbolIterator symbols = symbolTable.getAllSymbols(true);

        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (targetNames.contains(symbol.getName())) {
                // Find references to this symbol
                ReferenceIterator refs = program.getReferenceManager().getReferencesTo(symbol.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function callerFunc = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    if (callerFunc != null && !callerFunc.isThunk()) {
                        callerNames.add(callerFunc.getName() + " @ " + callerFunc.getEntryPoint());
                    }
                }
            }
        }

        if (callerNames.isEmpty()) {
            context.append("No direct callers found (may be dynamically resolved).\n\n");
        } else {
            for (String caller : callerNames) {
                context.append("- ").append(caller).append("\n");
            }
            context.append("\n");
        }
    }

    private void appendAnalysisGuidance(StringBuilder context) {
        context.append("## Protocol Payload Analysis Tasks\n\n");

        context.append("### 1. Data Structure Identification\n");
        context.append("Analyze the buffer parameters passed to send/recv functions:\n");
        context.append("- Identify the buffer type and size\n");
        context.append("- Look for structure definitions used as network payloads\n");
        context.append("- Track buffer allocations and their sizes\n");
        context.append("- Identify any serialization/deserialization routines\n\n");

        context.append("### 2. Protocol Format Analysis\n");
        context.append("Determine the network protocol structure:\n");
        context.append("- **Header Format**: Fixed-size headers, length fields, magic bytes\n");
        context.append("- **Payload Format**: TLV (Type-Length-Value), fixed structures, variable data\n");
        context.append("- **Encoding**: Binary, text-based (HTTP, JSON), encrypted, compressed\n");
        context.append("- **Byte Order**: Network byte order (big-endian) vs host byte order\n");
        context.append("- **Framing**: Message boundaries, delimiters, length-prefixed\n\n");

        context.append("### 3. Data Flow Tracing\n");
        context.append("Track how network data flows through the application:\n");
        context.append("- **Recv Path**: recv() -> parsing -> validation -> processing -> storage\n");
        context.append("- **Send Path**: data creation -> serialization -> send()\n");
        context.append("- Identify intermediate buffers and transformations\n");
        context.append("- Note any encryption/decryption or encoding/decoding steps\n\n");

        context.append("### 4. Network Security Vulnerability Analysis\n\n");

        context.append("#### Buffer Overflow Vulnerabilities\n");
        context.append("- Check if recv() length parameter is properly bounded\n");
        context.append("- Verify buffer size matches or exceeds received data\n");
        context.append("- Look for fixed-size buffers receiving variable-length network data\n");
        context.append("- Check for integer overflow in length calculations\n\n");

        context.append("#### Input Validation Issues\n");
        context.append("- Is received data validated before use?\n");
        context.append("- Are length fields from network data trusted without validation?\n");
        context.append("- Are there bounds checks on array indices from network data?\n");
        context.append("- Is there proper null-termination handling for strings?\n\n");

        context.append("#### Integer Handling Issues\n");
        context.append("- Check for integer overflow when parsing length fields\n");
        context.append("- Verify proper use of ntohl/ntohs for byte order conversion\n");
        context.append("- Look for signed/unsigned confusion in size calculations\n\n");

        context.append("#### Memory Safety Issues\n");
        context.append("- Double-free on connection errors\n");
        context.append("- Use-after-free in async network handlers\n");
        context.append("- Memory leaks on partial message handling\n");
        context.append("- Uninitialized memory sent over network\n\n");

        context.append("#### Protocol-Level Vulnerabilities\n");
        context.append("- Command injection in protocol handlers\n");
        context.append("- Path traversal in file transfer protocols\n");
        context.append("- Authentication/authorization bypass\n");
        context.append("- Session fixation or hijacking\n");
        context.append("- Replay attack susceptibility\n\n");

        context.append("### 5. Output Format\n");
        context.append("For network protocol analysis, provide:\n");
        context.append("- **Protocol Structure Diagram**: Visual representation of message format\n");
        context.append("- **Data Type Definitions**: C struct definitions for protocol messages\n");
        context.append("- **State Machine**: Connection/protocol state transitions\n");
        context.append("- **Vulnerability Report**: Any security issues found with severity ratings\n");
    }

    private Function findFunction(Program program, String identifier) {
        try {
            var addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                return program.getFunctionManager().getFunctionAt(addr);
            }
        } catch (Exception e) {
            // Not an address
        }

        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (function.getName().equals(identifier)) {
                return function;
            }
        }
        return null;
    }

    private String decompileFunction(Program program, Function function) {
        try (DecompilerSession session = decompilerService.open(program)) {
            DecompileResults results = session.decompiler().decompileFunction(function,
                session.options().getDefaultTimeout(), TaskMonitor.DUMMY);
            if (results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            }
        }
        return null;
    }
}

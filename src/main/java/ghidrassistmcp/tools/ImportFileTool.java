/*
 * MCP tool for importing a binary file into the current Ghidra project.
 *
 * SECURITY NOTE: This tool grants the MCP client file-system read access to any path
 * the Ghidra process can reach.  It is therefore registered as DISABLED by default
 * and must be explicitly enabled by the user in the GhidrAssistMCP configuration UI.
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.util.List;
import java.util.Map;

import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that imports a binary file into the active Ghidra project.
 * Supports raw binary imports with configurable language, base address,
 * file offset, and length — mirroring the manual File -> Import File dialog.
 *
 * Disabled by default because it exposes host file-system read access.
 */
public class ImportFileTool implements McpTool {

    @Override
    public String getName() {
        return "import_file";
    }

    @Override
    public String getDescription() {
        return "Import a binary file into the current Ghidra project. " +
               "Supports raw binary imports with configurable language/processor, " +
               "base address, file offset, and length. " +
               "SECURITY: This tool can read files from the host file system - " +
               "it is disabled by default and must be explicitly enabled. " +
               "Example: {\"file_path\": \"C:/roms/bank00.bin\", \"language\": \"6502:LE:16:default\", " +
               "\"base_address\": \"0x8000\"}";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return false;
    }

    @Override
    public boolean isOpenWorld() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("file_path", Map.of(
                    "type", "string",
                    "description", "Absolute path to the binary file on the host file system")),
                Map.entry("program_name", Map.of(
                    "type", "string",
                    "description", "Name for the imported program (defaults to file name)")),
                Map.entry("language", Map.of(
                    "type", "string",
                    "description", "Language ID: processor:endian:size:variant " +
                                   "(e.g. '6502:LE:16:default', 'x86:LE:32:default', 'ARM:LE:32:v8'). " +
                                   "If omitted, Ghidra will attempt auto-detection.")),
                Map.entry("compiler", Map.of(
                    "type", "string",
                    "description", "Compiler spec ID (e.g. 'default', 'gcc', 'windows'). Defaults to 'default'.")),
                Map.entry("base_address", Map.of(
                    "type", "string",
                    "description", "Base address in hex (e.g. '0x8000'). Applied after import by setting the program image base.")),
                Map.entry("folder", Map.of(
                    "type", "string",
                    "description", "Destination folder in the Ghidra project (e.g. '/' or '/banks'). Default: '/'.")),
                Map.entry("open_after_import", Map.of(
                    "type", "boolean",
                    "description", "Open the imported program in CodeBrowser after import. Default: true."))
            ),
            List.of("file_path"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return textResult("This tool requires backend context (project access).");
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                            GhidrAssistMCPBackend backend) {
        // --- Resolve the PluginTool and Project ---
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.getInstance();
        PluginTool pluginTool = manager.getActiveTool();
        if (pluginTool == null) {
            return textResult("No active Ghidra tool/window available.");
        }

        Project project = pluginTool.getProject();
        if (project == null) {
            return textResult("No Ghidra project is open.");
        }

        // --- Parse arguments ---
        String filePath = (String) arguments.get("file_path");
        if (filePath == null || filePath.isBlank()) {
            return textResult("file_path is required.");
        }

        File file = new File(filePath);
        if (!file.exists()) {
            return textResult("File not found: " + filePath);
        }
        if (!file.isFile()) {
            return textResult("Path is not a file: " + filePath);
        }

        String languageStr = (String) arguments.get("language");
        String compilerStr = (String) arguments.get("compiler");
        if (compilerStr == null || compilerStr.isBlank()) {
            compilerStr = "default";
        }

        String baseAddrStr = (String) arguments.get("base_address");

        String folderPath = (String) arguments.get("folder");
        if (folderPath == null || folderPath.isBlank()) {
            folderPath = "/";
        }

        Object openAfterObj = arguments.get("open_after_import");
        boolean openAfterImport = (openAfterObj == null) || Boolean.TRUE.equals(openAfterObj);

        // --- Perform import ---
        MessageLog messageLog = new MessageLog();
        Object consumer = this;

        try {
            if (languageStr != null && !languageStr.isBlank()) {
                return importWithLanguage(file, project, folderPath, languageStr, compilerStr,
                    baseAddrStr, openAfterImport, consumer, messageLog, pluginTool);
            } else {
                return importAutoDetect(file, project, folderPath, baseAddrStr,
                    openAfterImport, consumer, messageLog, pluginTool);
            }
        } catch (ghidra.util.exception.DuplicateNameException e) {
            return textResult("A program with that name already exists in folder '" + folderPath +
                "'. Use a different program_name or folder.");
        } catch (Exception e) {
            Msg.error(this, "Import failed", e);
            return textResult("Import failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    @SuppressWarnings("deprecation")
    private McpSchema.CallToolResult importWithLanguage(File file, Project project, String folderPath,
            String languageStr, String compilerStr, String baseAddrStr, boolean openAfterImport,
            Object consumer, MessageLog messageLog, PluginTool pluginTool) throws Exception {

        Language language;
        try {
            language = DefaultLanguageService.getLanguageService()
                .getLanguage(new LanguageID(languageStr));
        } catch (Exception e) {
            return textResult("Unknown language: " + languageStr + ". " +
                "Use format 'processor:endian:size:variant' (e.g. '6502:LE:16:default'). " +
                "Error: " + e.getMessage());
        }

        CompilerSpec compilerSpec;
        try {
            compilerSpec = language.getCompilerSpecByID(new CompilerSpecID(compilerStr));
        } catch (Exception e) {
            return textResult("Unknown compiler spec: " + compilerStr +
                " for language " + languageStr + ". Error: " + e.getMessage());
        }

        Loaded<Program> loaded = AutoImporter.importAsBinary(
            file, project, folderPath, language, compilerSpec,
            consumer, messageLog, TaskMonitor.DUMMY);

        if (loaded == null) {
            return textResult("Import failed - no program was created." + formatLog(messageLog));
        }

        Program importedProgram = loaded.getDomainObject(consumer);
        applyBaseAddress(importedProgram, baseAddrStr);
        loaded.save(TaskMonitor.DUMMY);

        StringBuilder result = buildResultMessage(importedProgram, folderPath, messageLog);

        if (openAfterImport) {
            result.append(openInCodeBrowser(pluginTool, importedProgram));
        }

        loaded.release(consumer);

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    @SuppressWarnings("deprecation")
    private McpSchema.CallToolResult importAutoDetect(File file, Project project, String folderPath,
            String baseAddrStr, boolean openAfterImport, Object consumer,
            MessageLog messageLog, PluginTool pluginTool) throws Exception {

        LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
            file, project, folderPath, consumer, messageLog, TaskMonitor.DUMMY);

        if (loadResults == null || loadResults.size() == 0) {
            return textResult("Import failed - Ghidra could not detect the file format." +
                formatLog(messageLog));
        }

        Program importedProgram = loadResults.getPrimaryDomainObject(consumer);
        applyBaseAddress(importedProgram, baseAddrStr);
        loadResults.save(TaskMonitor.DUMMY);

        StringBuilder result = buildResultMessage(importedProgram, folderPath, messageLog);

        if (openAfterImport) {
            result.append(openInCodeBrowser(pluginTool, importedProgram));
        }

        loadResults.release(consumer);

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    // --- Helpers ---

    private static void applyBaseAddress(Program program, String baseAddrStr) {
        if (baseAddrStr == null || baseAddrStr.isBlank()) {
            return;
        }
        int txId = program.startTransaction("Set Image Base");
        try {
            long addrValue = parseHex(baseAddrStr);
            Address baseAddr = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(addrValue);
            program.setImageBase(baseAddr, true);
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            Msg.warn(ImportFileTool.class, "Failed to set image base to " +
                baseAddrStr + ": " + e.getMessage());
        }
    }

    private static String openInCodeBrowser(PluginTool pluginTool, Program program) {
        ProgramManager pm = pluginTool.getService(ProgramManager.class);
        if (pm != null) {
            pm.openProgram(program);
            return "  Opened in CodeBrowser: yes\n";
        }
        return "  Opened in CodeBrowser: no (ProgramManager not available)\n";
    }

    private static StringBuilder buildResultMessage(Program program, String folderPath,
                                                     MessageLog messageLog) {
        StringBuilder sb = new StringBuilder();
        sb.append("Successfully imported: ").append(program.getName()).append("\n");
        sb.append("  Language: ").append(program.getLanguageID()).append("\n");
        sb.append("  Format: ").append(program.getExecutableFormat()).append("\n");
        sb.append("  Image Base: ").append(program.getImageBase()).append("\n");
        sb.append("  Folder: ").append(folderPath).append("\n");
        sb.append(formatLog(messageLog));
        return sb;
    }

    private static String formatLog(MessageLog messageLog) {
        String log = messageLog.toString();
        if (!log.isEmpty()) {
            return "  Import Log: " + log + "\n";
        }
        return "";
    }

    private static McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }

    private static long parseHex(String value) {
        String clean = value.strip();
        if (clean.startsWith("0x") || clean.startsWith("0X")) {
            clean = clean.substring(2);
        }
        return Long.parseUnsignedLong(clean, 16);
    }
}

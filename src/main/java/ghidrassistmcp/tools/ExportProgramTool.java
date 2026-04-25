/*
 * MCP tool to export the current program/binary to disk.
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.app.util.exporter.OriginalFileExporter;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Exports the active program to a host file.
 */
public class ExportProgramTool implements McpTool {

    @Override
    public String getName() {
        return "export_program";
    }

    @Override
    public String getDescription() {
        return "Export the program to disk. Supports format 'binary' (raw bytes) or 'original_file'. " +
               "Use after patching bytes to write a modified binary. " +
               "SECURITY: This tool writes to the host filesystem and is disabled by default.";
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
            Map.of(
                "output_path", Map.of(
                    "type", "string",
                    "description", "Absolute output path on the host filesystem"),
                "format", Map.of(
                    "type", "string",
                    "description", "Export format",
                    "enum", List.of("binary", "original_file")),
                "overwrite", Map.of(
                    "type", "boolean",
                    "description", "Overwrite existing file. Default: false")
            ),
            List.of("output_path"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return textResult("No program currently loaded");
        }

        String outputPath = (String) arguments.get("output_path");
        if (outputPath == null || outputPath.isBlank()) {
            return textResult("output_path is required");
        }

        String format = (String) arguments.get("format");
        if (format == null || format.isBlank()) {
            format = "binary";
        }
        format = format.toLowerCase();

        boolean overwrite = Boolean.TRUE.equals(arguments.get("overwrite"));

        File outputFile = new File(outputPath);
        if (outputFile.exists() && !overwrite) {
            return textResult("Output file already exists: " + outputPath + " (set overwrite=true to replace it)");
        }

        File parent = outputFile.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            return textResult("Failed to create output directory: " + parent.getAbsolutePath());
        }

        Exporter exporter;
        switch (format) {
            case "binary":
                exporter = new BinaryExporter();
                break;
            case "original_file":
                exporter = new OriginalFileExporter();
                break;
            default:
                return textResult("Unsupported format: " + format + ". Use 'binary' or 'original_file'.");
        }

        try {
            boolean success = exporter.export(outputFile, currentProgram, null, TaskMonitor.DUMMY);
            if (!success) {
                return textResult("Export failed (exporter returned false). Check Ghidra logs for details.");
            }

            return textResult("Export successful\n" +
                "Program: " + currentProgram.getName() + "\n" +
                "Format: " + format + "\n" +
                "Output: " + outputFile.getAbsolutePath() + "\n" +
                "Bytes written: " + outputFile.length());
        } catch (ExporterException | IOException e) {
            return textResult("Export failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }
}

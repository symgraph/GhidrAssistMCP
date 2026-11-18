/*
 * MCP Prompt interface for pre-built analysis workflows.
 */
package ghidrassistmcp.prompts;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.modern.McpSchema;

/**
 * Interface for MCP prompts that provide pre-built analysis workflows.
 */
public interface McpPrompt {

    /**
     * Get the prompt name
     */
    String getName();

    /**
     * Get the prompt description
     */
    String getDescription();

    /**
     * Get the arguments schema for this prompt
     */
    List<McpSchema.PromptArgument> getArguments();

    /**
     * Generate the prompt messages
     *
     * @param arguments The prompt arguments
     * @param program The current program context
     * @return The generated prompt messages
     */
    McpSchema.GetPromptResult generatePrompt(Map<String, String> arguments, Program program);
}

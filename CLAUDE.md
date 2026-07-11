# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Building the Extension
```bash
# Set GHIDRA_INSTALL_DIR environment variable first
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Build the extension
gradle distributeExtension

# Or specify Ghidra path directly
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra distributeExtension
```

### Project Structure
This is a Ghidra extension project with the following key components:

- **Main Plugin**: `GhidrAssistMCPPlugin.java` - Core plugin with UI provider and actions
- **Analyzer**: `GhidrAssistMCPAnalyzer.java` - Custom analyzer for binary analysis
- **Loader**: `GhidrAssistMCPLoader.java` - Custom loader for specific file formats
- **Exporter**: `GhidrAssistMCPExporter.java` - Custom exporter functionality
- **File System**: `GhidrAssistMCPFileSystem.java` - Custom file system implementation

### Key Directories
- `src/main/java/ghidrassistmcp/` - Main Java source code
- `src/test/java/` - Test files
- `data/` - Language specifications (SLEIGH files)
- `ghidra_scripts/` - Ghidra scripts
- `lib/` - External dependencies
- `dist/` - Built extension output

### Development Notes
- Extension uses Ghidra's plugin architecture with standard lifecycle methods
- All components extend appropriate Ghidra base classes (AbstractAnalyzer, AbstractProgramWrapperLoader, etc.)
- Built extension will be placed in `dist/` directory
- Language specifications in `data/languages/` define custom processor architectures
- Help documentation is in `src/main/help/`

### Dependencies
- Requires Ghidra installation with matching Gradle version
- Uses Ghidra's buildExtension.gradle for build configuration
- MCP SDK (io.modelcontextprotocol.sdk:mcp:0.9.0) for Model Context Protocol support
- Jetty 11.0.20 for embedded HTTP server
- Jackson 2.17.0 for JSON processing

### MCP Server
The extension includes an embedded MCP (Model Context Protocol) server that:
- Runs on port 8080 by default
- Provides SSE endpoint at `/mcp/sse` and HTTP request endpoint at `/mcp/message`
- Automatically tracks the currently loaded program
- Exposes Ghidra analysis capabilities via MCP tools:
  - `get_program_info`: Get basic program information
  - `list_functions`: List all functions in the program
  - `get_function_info`: Get detailed function information

### Build Requirements
- Java 25 or higher
- Gradle version matching your Ghidra installation
- Internet connection for dependency downloads from Maven Central

### Build Command Notes
- Always use the build command: `GHIDRA_INSTALL_DIR=/home/jtang613/tools/ghidra_11.4_PUBLIC/ /opt/gradle/bin/gradle buildExtension`

### Testing
- No formal test suite currently exists
- Manual testing through Ghidra UI and MCP client connections
- Test tools individually through the Configuration tab

### Core Architecture
The extension follows a plugin-based architecture:
- **Plugin Layer**: `GhidrAssistMCPPlugin` manages lifecycle, Ghidra integration, and multi-program tracking via ProgramManager service
- **Server Layer**: `GhidrAssistMCPServer` handles HTTP/SSE MCP protocol
- **Backend Layer**: `GhidrAssistMCPBackend` manages tool registry, execution, and program resolution
- **UI Layer**: `GhidrAssistMCPProvider` provides configuration and logging interface
- **Tool Layer**: 39 individual tools implementing the `McpTool` interface

### Multi-Program Support
- All tools support an optional `program_name` parameter to target specific programs
- Use `list_programs` tool to see all open programs
- Program resolution supports exact, case-insensitive, and partial name matching

### MCP Tools System
Tools are dynamically registered and can be enabled/disabled:
- All tools extend `McpTool` interface with `getName()`, `getDescription()`, `getInputSchema()`, and `execute()`
- Tools are organized into categories: Analysis, Modification, Navigation, and Advanced
- Backend maintains tool registry with enable/disable states
- UI provides real-time tool management and activity logging

### Development Workflow
1. Build with `gradle buildExtension`
2. Install generated ZIP from `dist/` directory in Ghidra
3. Enable plugin in Ghidra's Configure Plugins dialog
4. Access UI via Window → GhidrAssistMCP
5. Configure server settings and test tools through UI

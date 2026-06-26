/* 
 * 
 */
package ghidrassistmcp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

/**
 * GhidrAssistMCP Plugin - Provides an MCP (Model Context Protocol) server for Ghidra analysis capabilities.
 * Features a configurable UI with tool management and request logging.
 */
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "MCP Server for Ghidra",
	description = "Provides a configurable MCP (Model Context Protocol) server for Ghidra analysis capabilities with tool management and logging."
)
public class GhidrAssistMCPPlugin extends ProgramPlugin {

	private GhidrAssistMCPProvider provider;
	private GhidrAssistMCPManager manager;
	private boolean isServerOwner = false;

	// Current UI location tracking
	private volatile ProgramLocation currentLocation1;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidrAssistMCPPlugin(PluginTool tool) {
		super(tool);
		
		// Create the UI provider but don't register it yet
		provider = new GhidrAssistMCPProvider(tool, this);
	}

	@Override
	public void init() {
		super.init();

		// Get the singleton manager
		manager = GhidrAssistMCPManager.getInstance();

		// Register the UI provider with the tool first
		if (provider != null) {
			try {
				tool.addComponentProvider(provider, true);
				Msg.info(this, "Successfully registered UI provider");
			} catch (IllegalArgumentException e) {
				if (e.getMessage() != null && e.getMessage().contains("was already added")) {
					Msg.info(this, "UI provider already registered, continuing");
				} else {
					Msg.error(this, "Failed to register UI provider (non-fatal): " + e.getMessage());
				}
			} catch (Exception e) {
				Msg.error(this, "Failed to register UI provider (non-fatal): " + e.getMessage());
			}
		}

		// Register this tool with the singleton manager
		// The first tool to register becomes the server owner and gets its provider used
		isServerOwner = manager.registerTool(tool, provider);

		if (isServerOwner) {
			Msg.info(this, "This plugin instance is the MCP server owner");
		} else {
			Msg.info(this, "This plugin instance registered with existing MCP server");
		}

		if (provider != null) {
			provider.logSession("Plugin initialized" + (isServerOwner ? " (server owner)" : ""));
		}
	}
	
	/**
	 * Apply new configuration from the UI.
	 * Delegates to the singleton manager which handles server restart if needed.
	 */
	public void applyConfiguration(String host, int port, boolean enabled, boolean asyncEnabled, Map<String, Boolean> toolStates) {
		if (manager != null) {
			manager.applyConfiguration(host, port, enabled, asyncEnabled, toolStates);
		}
	}
	
	@Override
	protected void programActivated(Program program) {
		super.programActivated(program);

		// Notify manager that this tool is now active (focus tracking)
		if (manager != null) {
			manager.setActiveTool(tool);
		}

		GhidrAssistMCPBackend backend = getBackend();
		if (backend != null) {
			backend.onProgramActivated(program);
		}
		if (provider != null && program != null) {
			provider.logSession("Program activated: " + program.getName());
		}
	}
	
	@Override
	protected void locationChanged(ProgramLocation loc) {
		super.locationChanged(loc);
		this.currentLocation1 = loc;

		// Set this as the active plugin for UI context access
		if (manager != null) {
			manager.setActivePlugin(this);
		}

		if (provider != null && loc != null) {
			provider.logMessage("Location changed to: " + loc.getAddress());
		}
	}
	
	@Override
	protected void programDeactivated(Program program) {
		super.programDeactivated(program);
		GhidrAssistMCPBackend backend = getBackend();
		if (backend != null) {
			backend.onProgramDeactivated(program);
		}
		if (provider != null) {
			provider.logSession("Program deactivated: " + (program != null ? program.getName() : "null"));
		}
	}
	
	@Override
	protected void dispose() {
		if (provider != null) {
			provider.logSession("Plugin disposing");

			try {
				tool.removeComponentProvider(provider);
			} catch (Exception e) {
				Msg.error(this, "Error removing UI provider", e);
			}
			provider = null;
		}

		// Unregister this tool from the singleton manager
		// The manager will stop the server when all tools are unregistered
		if (manager != null) {
			manager.unregisterTool(tool);
		}

		super.dispose();
	}
	
	/**
	 * Get the MCP backend for tool management.
	 * Returns the shared backend from the singleton manager.
	 */
	public GhidrAssistMCPBackend getBackend() {
		return manager != null ? manager.getBackend() : null;
	}

	/**
	 * Get the singleton manager.
	 */
	public GhidrAssistMCPManager getManager() {
		return manager;
	}

	/**
	 * Get the current server configuration.
	 * Returns configuration from the singleton manager.
	 */
	public String getCurrentHost() {
		return manager != null ? manager.getCurrentHost() : "localhost";
	}

	public int getCurrentPort() {
		return manager != null ? manager.getCurrentPort() : 8080;
	}

	public boolean isServerEnabled() {
		return manager != null ? manager.isServerEnabled() : false;
	}
	
	/**
	 * Get the current program using ProgramManager service for accurate tracking.
	 * This method properly handles multi-program scenarios.
	 */
	@Override
	public Program getCurrentProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			Program current = pm.getCurrentProgram();
			if (current != null) {
				return current;
			}
		}
		// Fall back to parent implementation
		return super.getCurrentProgram();
	}

	/**
	 * Get all open programs in the current tool.
	 * This allows tools to list and select from multiple open programs.
	 */
	public List<Program> getAllOpenPrograms() {
		List<Program> programs = new ArrayList<>();
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			Program[] openPrograms = pm.getAllOpenPrograms();
			if (openPrograms != null) {
				for (Program p : openPrograms) {
					programs.add(p);
				}
			}
		}
		return programs;
	}

	/**
	 * Find an open program by name.
	 * Supports partial matching if exact match not found.
	 *
	 * @param programName The name of the program to find
	 * @return The matching program, or null if not found
	 */
	public Program getProgramByName(String programName) {
		if (programName == null || programName.trim().isEmpty()) {
			return getCurrentProgram();
		}

		List<Program> programs = getAllOpenPrograms();

		// Exact project path match (e.g. "/v1/app.exe" disambiguates from "/v2/app.exe")
		for (Program p : programs) {
			DomainFile df = p.getDomainFile();
			if (df != null && df.getPathname().equals(programName)) {
				return p;
			}
		}

		// Exact name match
		for (Program p : programs) {
			if (p.getName().equals(programName)) {
				return p;
			}
		}

		// Case-insensitive match
		for (Program p : programs) {
			if (p.getName().equalsIgnoreCase(programName)) {
				return p;
			}
		}

		// Partial match
		for (Program p : programs) {
			if (p.getName().toLowerCase().contains(programName.toLowerCase())) {
				return p;
			}
		}

		return null;
	}

	/**
	 * Get the current UI address from the location tracker.
	 */
	public Address getCurrentAddress() {
		if (currentLocation1 != null) {
			return currentLocation1.getAddress();
		}
		return null;
	}

	/**
	 * Get the current function containing the UI cursor.
	 */
	public Function getCurrentFunction() {
		Program program = getCurrentProgram();
		Address address = getCurrentAddress();

		if (program != null && address != null) {
			FunctionManager functionManager = program.getFunctionManager();
			return functionManager.getFunctionContaining(address);
		}
		return null;
	}
}

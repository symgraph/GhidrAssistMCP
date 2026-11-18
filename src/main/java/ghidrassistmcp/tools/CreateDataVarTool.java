package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

public class CreateDataVarTool implements McpTool {

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isIdempotent() { return true; }

    @Override
    public String getName() { return "create_data_var"; }

    @Override
    public String getDescription() { return "Create a defined data variable at a specific address"; }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "address", Map.of("type", "string", "description", "Address for the data variable"),
                "data_type", Map.of("type", "string", "description", "Data type name"),
                "name", Map.of("type", "string", "description", "Optional name for the data variable")
            ),
            List.of("address", "data_type"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder("No program currently loaded").build()).build();
        }

        String addressStr = (String) arguments.get("address");
        String dataTypeName = (String) arguments.get("data_type");
        String name = (String) arguments.get("name");

        Address address;
        try { address = currentProgram.getAddressFactory().getAddress(addressStr); }
        catch (Exception e) {
            return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder("Invalid address: " + addressStr).build()).build();
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType dataType = dtm.getDataType("/" + dataTypeName);
        if (dataType == null) dataType = dtm.getDataType(dataTypeName);
        if (dataType == null) {
            return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder("Data type not found: " + dataTypeName).build()).build();
        }

        int txId = currentProgram.startTransaction("Create Data Variable");
        try {
            if (dataType.getLength() > 0) {
                currentProgram.getListing().clearCodeUnits(address, address.add(dataType.getLength() - 1), false);
            }
            currentProgram.getListing().createData(address, dataType);

            if (name != null && !name.isEmpty()) {
                currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
            }

            currentProgram.endTransaction(txId, true);
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Created " + dataType.getName() + " at " + addressStr +
                    (name != null ? " named '" + name + "'" : "")).build())
                .build();
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder("Error: " + e.getMessage()).build()).build();
        }
    }
}

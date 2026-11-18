/*
 * MCP tool for managing bookmarks.
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool for listing, adding, and deleting bookmarks.
 */
public class BookmarksTool implements McpTool {

    @Override
    public boolean isReadOnly() {
        // May modify program when adding/deleting bookmarks
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public String getName() {
        return "bookmarks";
    }

    @Override
    public String getDescription() {
        return "Manage bookmarks: list, add, or delete bookmarks at addresses";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "action", Map.of(
                    "type", "string",
                    "description", "Bookmark operation to perform",
                    "enum", List.of("list", "set", "remove")
                ),
                "address", Map.of(
                    "type", "string",
                    "description", "Address string (required for add/delete)"
                ),
                "category", Map.of(
                    "type", "string",
                    "description", "Optional: category to filter by (list) or set (add)"
                ),
                "comment", Map.of(
                    "type", "string",
                    "description", "Optional: comment text (add)"
                ),
                "type", Map.of(
                    "type", "string",
                    "description", "Optional: bookmark type string (defaults to NOTE for add; for delete, if omitted deletes all bookmark types at address)"
                )
            ),
            List.of("action"), null, null, null);
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
                .addContent(McpSchema.TextContent.builder("Action is required: 'list', 'add', or 'delete'").build())
                .build();
        }

        action = action.toLowerCase();
        BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();

        switch (action) {
            case "list":
                return listBookmarks(bookmarkManager, arguments);

            case "set":
                return addBookmark(currentProgram, bookmarkManager, arguments);

            case "remove":
                return deleteBookmark(currentProgram, bookmarkManager, arguments);

            default:
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Invalid action: " + action + ". Use 'list', 'set', or 'remove'").build())
                    .build();
        }
    }

    private McpSchema.CallToolResult listBookmarks(BookmarkManager bookmarkManager, Map<String, Object> arguments) {
        String filterCategory = (String) arguments.get("category");

        StringBuilder result = new StringBuilder();
        result.append("Bookmarks:\n\n");

        // Get all bookmark types
        BookmarkType[] types = bookmarkManager.getBookmarkTypes();
        int totalCount = 0;

        for (BookmarkType type : types) {
            Iterator<Bookmark> bookmarks = bookmarkManager.getBookmarksIterator(type.getTypeString());

            while (bookmarks.hasNext()) {
                Bookmark bookmark = bookmarks.next();

                // Apply category filter if specified
                if (filterCategory != null && !filterCategory.isEmpty()) {
                    if (!bookmark.getCategory().toLowerCase().contains(filterCategory.toLowerCase())) {
                        continue;
                    }
                }

                result.append("- ").append(bookmark.getAddress())
                      .append(" [").append(type.getTypeString()).append("]")
                      .append(" (").append(bookmark.getCategory()).append(")")
                      .append(": ").append(bookmark.getComment())
                      .append("\n");
                totalCount++;
            }
        }

        if (totalCount == 0) {
            result.append("No bookmarks found");
            if (filterCategory != null) {
                result.append(" matching category '").append(filterCategory).append("'");
            }
            result.append(".\n");
        } else {
            result.append("\nTotal: ").append(totalCount).append(" bookmarks\n");
        }

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }

    private McpSchema.CallToolResult addBookmark(Program program, BookmarkManager bookmarkManager,
                                                  Map<String, Object> arguments) {
        String addressStr = (String) arguments.get("address");
        String category = (String) arguments.get("category");
        String comment = (String) arguments.get("comment");
        String type = (String) arguments.get("type");

        if (addressStr == null || addressStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Address is required to add a bookmark").build())
                .build();
        }

        if (category == null || category.isEmpty()) {
            category = "Analysis";
        }

        if (comment == null || comment.isEmpty()) {
            comment = "MCP Bookmark";
        }

        if (type == null || type.isEmpty()) {
            type = BookmarkType.NOTE;
        }

        Address address;
        try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Invalid address: " + addressStr).build())
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Error parsing address: " + e.getMessage()).build())
                .build();
        }

        int txId = program.startTransaction("Add Bookmark");
        try {
            bookmarkManager.setBookmark(address, type, category, comment);
            program.endTransaction(txId, true);

            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Added bookmark at " + addressStr + " [" + type + "] (" + category + "): " + comment).build())
                .build();

        } catch (Exception e) {
            program.endTransaction(txId, false);
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Error adding bookmark: " + e.getMessage()).build())
                .build();
        }
    }

    private McpSchema.CallToolResult deleteBookmark(Program program, BookmarkManager bookmarkManager,
                                                     Map<String, Object> arguments) {
        String addressStr = (String) arguments.get("address");
        String type = (String) arguments.get("type");

        if (addressStr == null || addressStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Address is required to delete a bookmark").build())
                .build();
        }

        Address address;
        try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Invalid address: " + addressStr).build())
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Error parsing address: " + e.getMessage()).build())
                .build();
        }

        int txId = program.startTransaction("Delete Bookmark");
        try {
            Bookmark[] bookmarks;
            if (type != null && !type.isEmpty()) {
                Bookmark bookmark = bookmarkManager.getBookmark(address, type, null);
                bookmarks = bookmark != null ? new Bookmark[]{bookmark} : new Bookmark[0];
            } else {
                bookmarks = bookmarkManager.getBookmarks(address);
            }

            if (bookmarks.length == 0) {
                program.endTransaction(txId, false);
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("No bookmarks found at " + addressStr).build())
                    .build();
            }

            for (Bookmark bookmark : bookmarks) {
                bookmarkManager.removeBookmark(bookmark);
            }

            program.endTransaction(txId, true);
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Deleted " + bookmarks.length + " bookmark(s) at " + addressStr).build())
                .build();

        } catch (Exception e) {
            program.endTransaction(txId, false);
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Error deleting bookmark: " + e.getMessage()).build())
                .build();
        }
    }
}

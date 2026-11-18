/*
 * MCP Cache Entry with validation support.
 */
package ghidrassistmcp.cache;

import java.time.Instant;

import io.modelcontextprotocol.modern.McpSchema;

/**
 * Represents a cached tool result with metadata for validation.
 */
public class CacheEntry {

    private final McpSchema.CallToolResult result;
    private final Instant createdAt;
    private final long programModificationNumber;
    private final String programName;
    private final String cacheKey;
    private volatile int hitCount;

    /**
     * Create a new cache entry
     */
    public CacheEntry(String cacheKey, McpSchema.CallToolResult result,
                      String programName, long programModificationNumber) {
        this.cacheKey = cacheKey;
        this.result = result;
        this.programName = programName;
        this.programModificationNumber = programModificationNumber;
        this.createdAt = Instant.now();
        this.hitCount = 0;
    }

    /**
     * Get the cached result
     */
    public McpSchema.CallToolResult getResult() {
        hitCount++;
        return result;
    }

    /**
     * Get when this entry was created
     */
    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * Get the program modification number at cache time
     */
    public long getProgramModificationNumber() {
        return programModificationNumber;
    }

    /**
     * Get the program name this entry is for
     */
    public String getProgramName() {
        return programName;
    }

    /**
     * Get the cache key
     */
    public String getCacheKey() {
        return cacheKey;
    }

    /**
     * Get the number of times this entry has been hit
     */
    public int getHitCount() {
        return hitCount;
    }

    /**
     * Check if this cache entry is still valid for the given program state
     *
     * @param currentProgramName Current program name
     * @param currentModificationNumber Current program modification number
     * @return true if the cache entry is still valid
     */
    public boolean isValid(String currentProgramName, long currentModificationNumber) {
        // Entry is invalid if:
        // 1. Program has changed
        if (!this.programName.equals(currentProgramName)) {
            return false;
        }

        // 2. Program has been modified since cache was created
        if (this.programModificationNumber != currentModificationNumber) {
            return false;
        }

        return true;
    }

    /**
     * Get the age of this cache entry in milliseconds
     */
    public long getAgeMillis() {
        return Instant.now().toEpochMilli() - createdAt.toEpochMilli();
    }

    @Override
    public String toString() {
        return String.format("CacheEntry[key=%s, program=%s, modNum=%d, hits=%d, age=%dms]",
            cacheKey, programName, programModificationNumber, hitCount, getAgeMillis());
    }
}

/*
 * MCP Tool Result Cache implementation.
 */
package ghidrassistmcp.cache;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Cache for MCP tool results with program modification-based invalidation.
 */
public class McpCache {

    private static final int DEFAULT_MAX_ENTRIES = 1000;
    private static final long DEFAULT_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes

    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final int maxEntries;
    private final long maxAgeMs;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AtomicLong hitCount = new AtomicLong(0);
    private final AtomicLong missCount = new AtomicLong(0);
    private final AtomicLong evictionCount = new AtomicLong(0);

    /**
     * Create a cache with default settings
     */
    public McpCache() {
        this(DEFAULT_MAX_ENTRIES, DEFAULT_MAX_AGE_MS);
    }

    /**
     * Create a cache with specified settings
     */
    public McpCache(int maxEntries, long maxAgeMs) {
        this.maxEntries = maxEntries;
        this.maxAgeMs = maxAgeMs;
        Msg.info(this, "McpCache initialized with maxEntries=" + maxEntries + ", maxAgeMs=" + maxAgeMs);
    }

    /**
     * Generate a cache key for a tool call
     */
    public String generateKey(String toolName, Map<String, Object> arguments, String programName) {
        return generateKey(toolName, arguments, programName, "");
    }

    public String generateKey(String toolName, Map<String, Object> arguments, String programName,
            String discriminator) {
        StringBuilder keyBuilder = new StringBuilder();
        keyBuilder.append(toolName).append(":");
        keyBuilder.append(programName).append(":");
        keyBuilder.append(discriminator != null ? discriminator : "").append(":");

        // Sort and serialize arguments for consistent key generation
        try {
            String argsJson = objectMapper.writeValueAsString(arguments);
            keyBuilder.append(argsJson.hashCode());
        } catch (JsonProcessingException e) {
            keyBuilder.append(arguments.hashCode());
        }

        return keyBuilder.toString();
    }

    /**
     * Get a cached result if valid
     *
     * @param key The cache key
     * @param program The current program (for validation)
     * @return The cached result or null if not found/invalid
     */
    public McpSchema.CallToolResult get(String key, Program program) {
        CacheEntry entry = cache.get(key);

        if (entry == null) {
            missCount.incrementAndGet();
            return null;
        }

        // Check if entry is still valid
        String programName = program != null ? program.getName() : "";
        long modNum = program != null ? program.getModificationNumber() : 0;

        if (!entry.isValid(programName, modNum)) {
            // Invalidate stale entry
            cache.remove(key);
            evictionCount.incrementAndGet();
            missCount.incrementAndGet();
            Msg.debug(this, "Cache entry invalidated (program modified): " + key);
            return null;
        }

        // Check age
        if (entry.getAgeMillis() > maxAgeMs) {
            cache.remove(key);
            evictionCount.incrementAndGet();
            missCount.incrementAndGet();
            Msg.debug(this, "Cache entry expired: " + key);
            return null;
        }

        hitCount.incrementAndGet();
        Msg.debug(this, "Cache hit: " + key);
        return entry.getResult();
    }

    /**
     * Store a result in the cache
     *
     * @param key The cache key
     * @param result The result to cache
     * @param program The current program
     */
    public void put(String key, McpSchema.CallToolResult result, Program program) {
        // Enforce size limit
        if (cache.size() >= maxEntries) {
            evictOldest();
        }

        String programName = program != null ? program.getName() : "";
        long modNum = program != null ? program.getModificationNumber() : 0;

        CacheEntry entry = new CacheEntry(key, result, programName, modNum);
        cache.put(key, entry);
        Msg.debug(this, "Cache put: " + key);
    }

    /**
     * Invalidate all entries for a specific program
     */
    public void invalidateProgram(String programName) {
        int removed = 0;
        var iterator = cache.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (entry.getValue().getProgramName().equals(programName)) {
                iterator.remove();
                removed++;
            }
        }
        if (removed > 0) {
            evictionCount.addAndGet(removed);
            Msg.info(this, "Invalidated " + removed + " cache entries for program: " + programName);
        }
    }

    /**
     * Clear the entire cache
     */
    public void clear() {
        int size = cache.size();
        cache.clear();
        evictionCount.addAndGet(size);
        Msg.info(this, "Cache cleared, removed " + size + " entries");
    }

    /**
     * Evict the oldest entries to make room
     */
    private void evictOldest() {
        // Find and remove the oldest 10% of entries
        int toEvict = Math.max(1, maxEntries / 10);
        int evicted = 0;

        // Simple eviction: remove entries with oldest creation time
        var entries = cache.entrySet().stream()
            .sorted((a, b) -> a.getValue().getCreatedAt().compareTo(b.getValue().getCreatedAt()))
            .limit(toEvict)
            .toList();

        for (var entry : entries) {
            cache.remove(entry.getKey());
            evicted++;
        }

        evictionCount.addAndGet(evicted);
        Msg.debug(this, "Evicted " + evicted + " oldest cache entries");
    }

    /**
     * Get cache statistics
     */
    public String getStats() {
        long hits = hitCount.get();
        long misses = missCount.get();
        long total = hits + misses;
        double hitRate = total > 0 ? (double) hits / total * 100 : 0;

        return String.format("Cache Stats: size=%d, hits=%d, misses=%d, hitRate=%.1f%%, evictions=%d",
            cache.size(), hits, misses, hitRate, evictionCount.get());
    }

    /**
     * Get the current cache size
     */
    public int size() {
        return cache.size();
    }

    /**
     * Check if cache contains a key
     */
    public boolean containsKey(String key) {
        return cache.containsKey(key);
    }
}

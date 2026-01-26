package com.portswigger.globalmatchreplace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

final class ChangeStore {
    private static final String ROOT_KEY = "gmr-diff-cache";
    private static final String MAX_MB_KEY = "maxMb";
    private static final String DATA_KEY = "data";
    private static final char FIELD_SEP = '\u0001';
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

    private final MontoyaApi api;
    private PersistedObject root;
    // Access-ordered LinkedHashMap provides LRU behavior for eviction.
    private final LinkedHashMap<Key, Entry> lru = new LinkedHashMap<>(16, 0.75f, true);
    private final Map<String, Key> aliasByHash = new java.util.HashMap<>();
    private long maxBytes;
    private long currentBytes;

    ChangeStore(MontoyaApi api, int maxMb) {
        this.api = api;
        PersistedObject extensionData = api.persistence().extensionData();
        this.root = getOrCreateChild(extensionData, ROOT_KEY);
        this.maxBytes = mbToBytes(maxMb);
        // Load any persisted diffs for the current Burp session.
        load();
    }

    synchronized int maxBytesMb() {
        return (int) Math.max(1, maxBytes / (1024 * 1024));
    }

    synchronized void setMaxBytesMb(int mb) {
        this.maxBytes = mbToBytes(mb);
        // Shrink immediately so the cache never exceeds the configured cap.
        evictToSize();
        persist();
    }

    void storeRequest(String original, String modified, List<String> summaries) {
        if (original != null && modified != null && !original.equals(modified)) {
            // Store request diffs under the hash of the modified content.
            store(Type.REQUEST, modified, original, summaries);
        }
    }

    void storeResponse(String original, String modified, List<String> summaries) {
        if (original != null && modified != null && !original.equals(modified)) {
            // Store response diffs under the hash of the modified content.
            store(Type.RESPONSE, modified, original, summaries);
        }
    }

    Optional<ChangeRecord> requestChangeFor(String modified) {
        return lookup(Type.REQUEST, modified);
    }

    Optional<ChangeRecord> responseChangeFor(String modified) {
        return lookup(Type.RESPONSE, modified);
    }

    private synchronized Optional<ChangeRecord> lookup(Type type, String modified) {
        if (modified == null) {
            return Optional.empty();
        }
        // Lookups are done by hash to avoid large string keys.
        String hash = hashOf(modified);
        Key key = resolveKey(type, hash);
        Entry entry = lru.get(key);
        return entry == null ? Optional.empty() : Optional.of(entry.record);
    }

    private synchronized void store(Type type, String modified, String original, List<String> summaries) {
        if (modified == null || original == null) {
            return;
        }
        String hash = hashOf(modified);
        String bodyHash = hashOf(extractBody(modified));
        String headersHash = hashOf(normalizeHeaders(modified));
        String originalHash = hashOf(original);
        // Store compressed original + modified to keep session size small.
        byte[] compressed = compress(original);
        byte[] compressedModified = compress(modified);
        long entrySize = compressed.length + compressedModified.length + summariesSize(summaries);
        Key key = new Key(type, hash);
        Entry existing = lru.remove(key);
        if (existing != null) {
            currentBytes -= existing.sizeBytes;
            removeAliases(existing.aliases, key);
        }
        // Keep original+modified so diffs remain stable even if rules change later.
        ChangeRecord record = new ChangeRecord(original, modified, summaries);
        List<String> aliases = new ArrayList<>();
        // Aliases allow lookups even when Burp supplies different request variants (body/headers/original).
        if (!bodyHash.equals(hash)) {
            aliases.add(bodyHash);
        }
        if (!headersHash.equals(hash) && !headersHash.equals(bodyHash)) {
            aliases.add(headersHash);
        }
        if (!originalHash.equals(hash) && !aliases.contains(originalHash)) {
            aliases.add(originalHash);
        }
        lru.put(key, new Entry(record, compressed, compressedModified, entrySize, aliases, key));
        registerAliases(aliases, key);
        currentBytes += entrySize;
        evictToSize();
        persist();
    }

    private void evictToSize() {
        while (currentBytes > maxBytes && !lru.isEmpty()) {
            Map.Entry<Key, Entry> eldest = lru.entrySet().iterator().next();
            currentBytes -= eldest.getValue().sizeBytes;
            removeAliases(eldest.getValue().aliases, eldest.getKey());
            lru.remove(eldest.getKey());
        }
    }

    private void load() {
        PersistedObject store = ensureRoot();
        if (store == null) {
            return;
        }
        // Load persisted size cap and diff entries for this session.
        Integer mb = store.getInteger(MAX_MB_KEY);
        if (mb != null && mb > 0) {
            maxBytes = mbToBytes(mb);
        }
        String payload = store.getString(DATA_KEY);
        if (payload == null || payload.isEmpty()) {
            return;
        }
        for (String line : payload.split("\n")) {
            if (line.isEmpty()) {
                continue;
            }
            Entry parsed = deserializeEntry(line);
            if (parsed == null) {
                continue;
            }
            Key key = parsed.key;
            lru.put(key, parsed);
            registerAliases(parsed.aliases, key);
            currentBytes += parsed.sizeBytes;
        }
    }

    private void persist() {
        PersistedObject store = ensureRoot();
        if (store == null) {
            return;
        }
        // Persist a compact, line-delimited cache snapshot under a single key.
        store.setInteger(MAX_MB_KEY, maxBytesMb());
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<Key, Entry> entry : lru.entrySet()) {
            builder.append(serializeEntry(entry.getKey(), entry.getValue())).append('\n');
        }
        store.setString(DATA_KEY, builder.toString());
    }

    private long summariesSize(List<String> summaries) {
        if (summaries == null) {
            return 0;
        }
        long size = 0;
        for (String summary : summaries) {
            size += summary.length();
        }
        return size;
    }

    private String serializeSummaries(List<String> summaries) {
        if (summaries == null || summaries.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < summaries.size(); i++) {
            if (i > 0) {
                builder.append('\u0001');
            }
            builder.append(summaries.get(i));
        }
        return builder.toString();
    }

    private List<String> deserializeSummaries(String value) {
        if (value == null || value.isEmpty()) {
            return List.of();
        }
        String[] parts = value.split("\u0001", -1);
        List<String> out = new ArrayList<>();
        Collections.addAll(out, parts);
        return out;
    }

    private byte[] compress(String input) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try (GZIPOutputStream gzip = new GZIPOutputStream(output)) {
                gzip.write(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            return output.toByteArray();
        } catch (IOException ex) {
            // Fall back to raw bytes if compression fails.
            return input.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private String decompress(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(data))) {
            return new String(gzip.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException ex) {
            // Fall back to raw bytes if decompression fails.
            return new String(data, java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private String hashOf(String value) {
        String normalized = normalize(value);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(normalized.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            // Fallback if SHA-256 is unavailable.
            return Integer.toHexString(normalized.hashCode());
        }
    }

    private long mbToBytes(int mb) {
        return (long) mb * 1024L * 1024L;
    }

    private PersistedObject ensureRoot() {
        if (root != null || api == null) {
            return root;
        }
        PersistedObject extensionData = api.persistence().extensionData();
        root = getOrCreateChild(extensionData, ROOT_KEY);
        return root;
    }

    private PersistedObject getOrCreateChild(PersistedObject parent, String key) {
        if (parent == null) {
            return null;
        }
        PersistedObject child = parent.getChildObject(key);
        if (child != null) {
            return child;
        }
        // Child objects must be explicitly created before getChildObject returns non-null.
        PersistedObject created = PersistedObject.persistedObject();
        parent.setChildObject(key, created);
        return parent.getChildObject(key);
    }

    private String serializeEntry(Key key, Entry entry) {
        String type = key.type.name();
        String hash = key.hash;
        String aliases = serializeAliases(entry.aliases);
        String summaries = serializeSummaries(entry.record.summaries());
        String original = BASE64_ENCODER.encodeToString(entry.compressedOriginal);
        String modified = BASE64_ENCODER.encodeToString(entry.compressedModified);
        return encode(type) + FIELD_SEP
            + encode(hash) + FIELD_SEP
            + encode(aliases) + FIELD_SEP
            + encode(summaries) + FIELD_SEP
            + encode(original) + FIELD_SEP
            + encode(modified);
    }

    private Entry deserializeEntry(String line) {
        String[] parts = line.split(String.valueOf(FIELD_SEP), -1);
        if (parts.length < 5) {
            return null;
        }
        String typeName = decode(parts[0]);
        String hash = decode(parts[1]);
        String aliasesRaw = decode(parts[2]);
        String summariesRaw = decode(parts[3]);
        String originalB64 = decode(parts[4]);
        String modifiedB64 = parts.length > 5 ? decode(parts[5]) : "";
        if (typeName.isEmpty() || hash.isEmpty() || originalB64.isEmpty()) {
            return null;
        }
        Type type;
        try {
            type = Type.valueOf(typeName);
        } catch (IllegalArgumentException ex) {
            return null;
        }
        byte[] compressed = BASE64_DECODER.decode(originalB64);
        byte[] compressedModified = modifiedB64.isEmpty() ? new byte[0] : BASE64_DECODER.decode(modifiedB64);
        String original = decompress(compressed);
        String modified = compressedModified.length == 0 ? "" : decompress(compressedModified);
        List<String> summaries = deserializeSummaries(summariesRaw);
        ChangeRecord record = new ChangeRecord(original, modified, summaries == null ? List.of() : summaries);
        long size = compressed.length + compressedModified.length + summariesSize(summaries);
        List<String> aliases = deserializeAliases(aliasesRaw);
        return new Entry(record, compressed, compressedModified, size, aliases, new Key(type, hash));
    }

    private String encode(String value) {
        return BASE64_ENCODER.encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private String decode(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        byte[] decoded = BASE64_DECODER.decode(value);
        return new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
    }

    private String normalize(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\r\n", "\n");
    }

    private String extractBody(String message) {
        if (message == null) {
            return "";
        }
        String normalized = normalize(message);
        int idx = normalized.indexOf("\n\n");
        if (idx < 0) {
            return "";
        }
        return normalized.substring(idx + 2);
    }

    private String normalizeHeaders(String message) {
        if (message == null) {
            return "";
        }
        String normalized = normalize(message);
        int idx = normalized.indexOf("\n\n");
        String headerBlock = idx >= 0 ? normalized.substring(0, idx) : normalized;
        String body = idx >= 0 ? normalized.substring(idx + 2) : "";
        String[] lines = headerBlock.split("\n");
        if (lines.length == 0) {
            return normalized;
        }
        String startLine = lines[0];
        List<String> headers = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            headers.add(lines[i].trim());
        }
        headers.sort(String.CASE_INSENSITIVE_ORDER);
        StringBuilder builder = new StringBuilder();
        builder.append(startLine).append('\n');
        for (String header : headers) {
            if (!header.isEmpty()) {
                builder.append(header).append('\n');
            }
        }
        builder.append('\n').append(body);
        return builder.toString();
    }

    private Key resolveKey(Type type, String hash) {
        Key key = new Key(type, hash);
        if (lru.containsKey(key)) {
            return key;
        }
        Key aliasKey = aliasByHash.get(hash);
        if (aliasKey != null && aliasKey.type == type) {
            return aliasKey;
        }
        return key;
    }

    private void registerAliases(List<String> aliases, Key key) {
        if (aliases == null) {
            return;
        }
        for (String alias : aliases) {
            aliasByHash.put(alias, key);
        }
    }

    private void removeAliases(List<String> aliases, Key key) {
        if (aliases == null) {
            return;
        }
        for (String alias : aliases) {
            Key existing = aliasByHash.get(alias);
            if (existing != null && existing.equals(key)) {
                aliasByHash.remove(alias);
            }
        }
    }

    private String serializeAliases(List<String> aliases) {
        if (aliases == null || aliases.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < aliases.size(); i++) {
            if (i > 0) {
                builder.append('\u0001');
            }
            builder.append(aliases.get(i));
        }
        return builder.toString();
    }

    private List<String> deserializeAliases(String value) {
        if (value == null || value.isEmpty()) {
            return List.of();
        }
        String[] parts = value.split("\u0001", -1);
        List<String> out = new ArrayList<>();
        Collections.addAll(out, parts);
        return out;
    }

    static final class ChangeRecord {
        private final String original;
        private final String modified;
        private final List<String> summaries;

        ChangeRecord(String original, String modified, List<String> summaries) {
            this.original = original;
            this.modified = modified == null ? "" : modified;
            this.summaries = summaries == null ? List.of() : List.copyOf(summaries);
        }

        String original() {
            return original;
        }

        String modified() {
            return modified;
        }

        List<String> summaries() {
            return summaries;
        }
    }

    private enum Type { REQUEST, RESPONSE }

    private record Key(Type type, String hash) {}

    private static final class Entry {
        private final ChangeRecord record;
        private final byte[] compressedOriginal;
        private final byte[] compressedModified;
        private final long sizeBytes;
        private final List<String> aliases;
        private final Key key;

        Entry(ChangeRecord record, byte[] compressedOriginal, byte[] compressedModified, long sizeBytes, List<String> aliases, Key key) {
            this.record = record;
            this.compressedOriginal = compressedOriginal;
            this.compressedModified = compressedModified == null ? new byte[0] : compressedModified;
            this.sizeBytes = sizeBytes;
            this.aliases = aliases == null ? List.of() : List.copyOf(aliases);
            this.key = key;
        }
    }
}

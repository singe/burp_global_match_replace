package com.portswigger.globalmatchreplace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;

import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.nio.charset.StandardCharsets;

final class RulePersistence {
    private static final String ROOT_KEY = "global-match-replace";
    private static final String RULES_KEY = "rules";
    private static final String COUNT_KEY = "count";

    private static final String ENABLED_KEY = "enabled";
    private static final String TARGET_KEY = "target";
    private static final String MATCH_TYPE_KEY = "matchType";
    private static final String MATCH_KEY = "match";
    private static final String REPLACE_KEY = "replace";
    private static final String COMMENT_KEY = "comment";
    private static final String TOOLS_KEY = "tools";
    private static final String MULTILINE_KEY = "multiline";
    private static final String PREFS_KEY = "global-match-replace.rules";

    private static volatile List<Rule> sessionCache = List.of();

    private final PersistedObject root;
    private final Preferences preferences;

    RulePersistence(MontoyaApi api) {
        PersistedObject extensionData = api.persistence().extensionData();
        if (extensionData == null) {
            this.root = null;
        } else {
            PersistedObject child = extensionData.getChildObject(ROOT_KEY);
            if (child == null) {
                // Child objects are not auto-created; create before first use.
                PersistedObject created = PersistedObject.persistedObject();
                extensionData.setChildObject(ROOT_KEY, created);
                child = extensionData.getChildObject(ROOT_KEY);
            }
            this.root = child;
        }
        this.preferences = api.persistence().preferences();
    }

    List<Rule> load() {
        if (root == null) {
            // Preferences fallback keeps rules available if extensionData is unavailable.
            List<Rule> prefRules = loadFromPreferences();
            if (!prefRules.isEmpty()) {
                sessionCache = List.copyOf(prefRules);
                return prefRules;
            }
            return sessionCache;
        }
        PersistedObject rulesObject = getOrCreateChild(root, RULES_KEY);
        if (rulesObject == null) {
            return sessionCache;
        }
        Integer count = rulesObject.getInteger(COUNT_KEY);
        if (count == null || count <= 0) {
            return sessionCache;
        }
        List<Rule> rules = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            PersistedObject ruleObject = rulesObject.getChildObject("rule-" + i);
            if (ruleObject == null) {
                continue;
            }
            Rule rule = readRule(ruleObject);
            if (rule != null) {
                rules.add(rule);
            }
        }
        sessionCache = List.copyOf(rules);
        return rules;
    }

    void save(List<Rule> rules) {
        sessionCache = List.copyOf(rules);
        if (root == null) {
            saveToPreferences(rules);
            return;
        }
        PersistedObject rulesObject = getOrCreateChild(root, RULES_KEY);
        if (rulesObject == null) {
            saveToPreferences(rules);
            return;
        }
        // Replace entire rules subtree for simplicity and correctness.
        for (String key : rulesObject.childObjectKeys()) {
            rulesObject.deleteChildObject(key);
        }
        rulesObject.setInteger(COUNT_KEY, rules.size());
        for (int i = 0; i < rules.size(); i++) {
            PersistedObject ruleObject = getOrCreateChild(rulesObject, "rule-" + i);
            if (ruleObject == null) {
                saveToPreferences(rules);
                return;
            }
            writeRule(ruleObject, rules.get(i));
        }
    }

    private Rule readRule(PersistedObject ruleObject) {
        Boolean enabled = ruleObject.getBoolean(ENABLED_KEY);
        String target = ruleObject.getString(TARGET_KEY);
        String matchType = ruleObject.getString(MATCH_TYPE_KEY);
        String match = ruleObject.getString(MATCH_KEY);
        String replace = ruleObject.getString(REPLACE_KEY);
        String comment = ruleObject.getString(COMMENT_KEY);
        String tools = ruleObject.getString(TOOLS_KEY);
        Boolean multiline = ruleObject.getBoolean(MULTILINE_KEY);
        if (target == null || matchType == null) {
            return null;
        }
        Set<ToolType> toolSet = parseTools(tools);
        return new Rule(
            enabled != null && enabled,
            Rule.Target.valueOf(target),
            toolSet,
            Rule.MatchType.valueOf(matchType),
            match == null ? "" : match,
            replace == null ? "" : replace,
            comment == null ? "" : comment,
            // Legacy records default to multiline=true to preserve old behavior.
            multiline != null ? multiline : true
        );
    }

    private void writeRule(PersistedObject ruleObject, Rule rule) {
        ruleObject.setBoolean(ENABLED_KEY, rule.isEnabled());
        ruleObject.setString(TARGET_KEY, rule.getTarget().name());
        ruleObject.setString(MATCH_TYPE_KEY, rule.getMatchType().name());
        ruleObject.setString(MATCH_KEY, rule.getMatch());
        ruleObject.setString(REPLACE_KEY, rule.getReplace());
        ruleObject.setString(COMMENT_KEY, rule.getComment());
        ruleObject.setString(TOOLS_KEY, serializeTools(rule.getTools()));
        ruleObject.setBoolean(MULTILINE_KEY, rule.isMultiline());
    }

    private String serializeTools(Set<ToolType> tools) {
        if (tools.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (ToolType tool : tools) {
            if (builder.length() > 0) {
                builder.append(',');
            }
            builder.append(tool.name());
        }
        return builder.toString();
    }

    private Set<ToolType> parseTools(String tools) {
        if (tools == null || tools.isEmpty()) {
            return EnumSet.noneOf(ToolType.class);
        }
        EnumSet<ToolType> toolSet = EnumSet.noneOf(ToolType.class);
        for (String entry : tools.split(",")) {
            try {
                toolSet.add(ToolType.valueOf(entry));
            } catch (IllegalArgumentException ignored) {
                // ignore unknown tool names
            }
        }
        return toolSet;
    }

    private void saveToPreferences(List<Rule> rules) {
        if (preferences == null) {
            return;
        }
        // Compact, line-delimited fallback for environments without extensionData.
        StringBuilder builder = new StringBuilder();
        for (Rule rule : rules) {
            builder.append(encode(rule.isEnabled()))
                .append('|').append(encode(rule.getTarget().name()))
                .append('|').append(encode(rule.getMatchType().name()))
                .append('|').append(encode(rule.getMatch()))
                .append('|').append(encode(rule.getReplace()))
                .append('|').append(encode(rule.getComment()))
                .append('|').append(encode(serializeTools(rule.getTools())))
                .append('|').append(encode(Boolean.toString(rule.isMultiline())))
                .append('\n');
        }
        preferences.setString(PREFS_KEY, builder.toString());
    }

    private List<Rule> loadFromPreferences() {
        if (preferences == null) {
            return List.of();
        }
        String payload = preferences.getString(PREFS_KEY);
        if (payload == null || payload.isBlank()) {
            return List.of();
        }
        List<Rule> rules = new ArrayList<>();
        for (String line : payload.split("\\n")) {
            if (line.isBlank()) {
                continue;
            }
            String[] parts = line.split("\\|", -1);
            if (parts.length < 7) {
                continue;
            }
            boolean enabled = Boolean.parseBoolean(decode(parts[0]));
            String target = decode(parts[1]);
            String matchType = decode(parts[2]);
            String match = decode(parts[3]);
            String replace = decode(parts[4]);
            String comment = decode(parts[5]);
            Set<ToolType> tools = parseTools(decode(parts[6]));
            boolean multiline = parts.length > 7 ? Boolean.parseBoolean(decode(parts[7])) : true;
            try {
                rules.add(new Rule(enabled, Rule.Target.valueOf(target), tools, Rule.MatchType.valueOf(matchType), match, replace, comment, multiline));
            } catch (IllegalArgumentException ignored) {
                // skip invalid
            }
        }
        return rules;
    }

    private String encode(String value) {
        if (value == null) {
            value = "";
        }
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private String decode(String value) {
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return "";
        }
    }

    private String encode(boolean value) {
        return encode(Boolean.toString(value));
    }

    private PersistedObject getOrCreateChild(PersistedObject parent, String key) {
        if (parent == null) {
            return null;
        }
        PersistedObject child = parent.getChildObject(key);
        if (child != null) {
            return child;
        }
        PersistedObject created = PersistedObject.persistedObject();
        parent.setChildObject(key, created);
        return parent.getChildObject(key);
    }
}

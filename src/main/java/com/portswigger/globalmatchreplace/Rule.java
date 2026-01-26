package com.portswigger.globalmatchreplace;

import burp.api.montoya.core.ToolType;

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

final class Rule {
    enum Target {
        REQUEST,
        RESPONSE
    }

    enum MatchType {
        SIMPLE,
        REGEX
    }

    private boolean enabled;
    private Target target;
    private Set<ToolType> tools;
    private MatchType matchType;
    private String match;
    private String replace;
    private String comment;
    private boolean multiline;

    Rule(boolean enabled, Target target, Set<ToolType> tools, MatchType matchType, String match, String replace, String comment, boolean multiline) {
        this.enabled = enabled;
        this.target = Objects.requireNonNull(target);
        this.tools = EnumSet.copyOf(tools);
        this.matchType = Objects.requireNonNull(matchType);
        this.match = match == null ? "" : match;
        this.replace = replace == null ? "" : replace;
        this.comment = comment == null ? "" : comment;
        this.multiline = multiline;
    }

    static Rule defaultRule() {
        // New rules default to single-line matching for simplicity.
        return new Rule(true, Target.REQUEST, EnumSet.noneOf(ToolType.class), MatchType.SIMPLE, "", "", "", false);
    }

    Rule copy() {
        return new Rule(enabled, target, tools, matchType, match, replace, comment, multiline);
    }

    boolean isEnabled() {
        return enabled;
    }

    void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    Target getTarget() {
        return target;
    }

    void setTarget(Target target) {
        this.target = Objects.requireNonNull(target);
    }

    Set<ToolType> getTools() {
        return EnumSet.copyOf(tools);
    }

    void setTools(Set<ToolType> tools) {
        this.tools = EnumSet.copyOf(tools);
    }

    MatchType getMatchType() {
        return matchType;
    }

    void setMatchType(MatchType matchType) {
        this.matchType = Objects.requireNonNull(matchType);
    }

    String getMatch() {
        return match;
    }

    void setMatch(String match) {
        this.match = match == null ? "" : match;
    }

    String getReplace() {
        return replace;
    }

    void setReplace(String replace) {
        this.replace = replace == null ? "" : replace;
    }

    String getComment() {
        return comment;
    }

    void setComment(String comment) {
        this.comment = comment == null ? "" : comment;
    }

    boolean isMultiline() {
        return multiline;
    }

    void setMultiline(boolean multiline) {
        this.multiline = multiline;
    }

    boolean appliesTo(boolean messageIsRequest) {
        return target == (messageIsRequest ? Target.REQUEST : Target.RESPONSE);
    }

    boolean appliesToTool(ToolType toolType) {
        if (tools.isEmpty()) {
            return false;
        }
        if (toolType == null) {
            return true;
        }
        return tools.contains(toolType);
    }

    boolean hasValidPattern() {
        if (matchType != MatchType.REGEX) {
            return true;
        }
        if (match.isEmpty()) {
            return false;
        }
        try {
            // Validate with the same flags used during execution.
            Pattern.compile(match, regexFlags());
            return true;
        } catch (PatternSyntaxException ex) {
            return false;
        }
    }

    String apply(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        if (match.isEmpty()) {
            return input;
        }
        if (matchType == MatchType.SIMPLE) {
            if (!hasWildcards(match)) {
                return input.replace(match, replace);
            }
            try {
                // Simple wildcard rules compile to regex; replacement is literal.
                Pattern pattern = compileSimplePattern();
                return pattern.matcher(input).replaceAll(Matcher.quoteReplacement(replace));
            } catch (PatternSyntaxException ex) {
                return input;
            }
        }
        try {
            // Regex rules respect multiline toggle (MULTILINE always, DOTALL optional).
            Pattern pattern = Pattern.compile(match, regexFlags());
            return pattern.matcher(input).replaceAll(replace);
        } catch (PatternSyntaxException ex) {
            return input;
        }
    }

    String summary() {
        String matchPreview = match.replace("\r", "").replace("\n", "\\n");
        if (matchPreview.length() > 40) {
            matchPreview = matchPreview.substring(0, 37) + "...";
        }
        String replacePreview = replace.replace("\r", "").replace("\n", "\\n");
        if (replacePreview.length() > 40) {
            replacePreview = replacePreview.substring(0, 37) + "...";
        }
        String multi = multiline ? " multiline" : "";
        String base = target + " " + matchType + multi + " match=\"" + matchPreview + "\" replace=\"" + replacePreview + "\"";
        if (comment == null || comment.isBlank()) {
            return base;
        }
        return base + " (" + comment.trim() + ")";
    }

    boolean hasWildcards() {
        return hasWildcards(match);
    }

    Pattern compileRegexPattern() {
        return Pattern.compile(match, regexFlags());
    }

    Pattern compileSimplePattern() {
        // Convert simple wildcard syntax to a regex.
        String regex = wildcardToRegex(match, multiline);
        return Pattern.compile(regex, regexFlags());
    }

    private int regexFlags() {
        // Always use MULTILINE so ^/$ apply per line; DOTALL only when multiline is enabled.
        int flags = Pattern.MULTILINE;
        if (multiline) {
            flags |= Pattern.DOTALL;
        }
        return flags;
    }

    private boolean hasWildcards(String value) {
        boolean escaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '*' || c == '?') {
                return true;
            }
        }
        return false;
    }

    private String wildcardToRegex(String value, boolean multiline) {
        StringBuilder out = new StringBuilder();
        boolean escaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (escaped) {
                appendLiteral(out, c);
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '*') {
                out.append(multiline ? ".*" : "[^\\r\\n]*");
                continue;
            }
            if (c == '?') {
                out.append(multiline ? "." : "[^\\r\\n]");
                continue;
            }
            appendLiteral(out, c);
        }
        if (escaped) {
            out.append("\\\\");
        }
        return out.toString();
    }

    private void appendLiteral(StringBuilder out, char c) {
        if ("\\.^$|?*+()[]{}".indexOf(c) >= 0) {
            out.append('\\');
        }
        out.append(c);
    }
}

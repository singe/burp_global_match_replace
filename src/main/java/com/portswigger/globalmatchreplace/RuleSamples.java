package com.portswigger.globalmatchreplace;

import burp.api.montoya.core.ToolType;

import java.util.EnumSet;
import java.util.List;

final class RuleSamples {
    static List<Rule> defaultRules() {
        // Samples are disabled by default and serve as templates/examples.
        Rule removeHeader = new Rule(
            false,
            Rule.Target.RESPONSE,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "(?mi)^X-Remove-Me:.*$\\r?\\n",
            "",
            "Remove a specific response header (regex, single-line)",
            false
        );

        Rule wafBypass = new Rule(
            false,
            Rule.Target.REQUEST,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "^(\\w+)\\s+([^\\s?]+)(\\?[^\\s]*)?\\s+HTTP/",
            "$1 $2;waf_bypass$3 HTTP/",
            "Append WAF bypass string to request path (regex, single-line)",
            false
        );

        Rule userAgentIe = new Rule(
            false,
            Rule.Target.REQUEST,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.SIMPLE,
            "User-Agent:*",
            "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
            "Force IE-style User-Agent (simple wildcard)",
            false
        );

        Rule userAgentChrome = new Rule(
            false,
            Rule.Target.REQUEST,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "(?mi)^User-Agent:.*$",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Force Chrome User-Agent (regex, single-line)",
            false
        );

        Rule normalizeXff = new Rule(
            false,
            Rule.Target.REQUEST,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.SIMPLE,
            "X-Forwarded-For: 127.0.0.?",
            "X-Forwarded-For: 127.0.0.1",
            "Normalize X-Forwarded-For value (simple wildcard ?)",
            false
        );

        Rule removeDisabled = new Rule(
            false,
            Rule.Target.RESPONSE,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "(?i)\\s+disabled\\b",
            "",
            "Strip disabled attributes from HTML elements (regex, single-line)",
            false
        );

        Rule stripCache = new Rule(
            false,
            Rule.Target.RESPONSE,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "(?mi)^(Cache-Control|Pragma|Expires):.*$\\r?\\n",
            "",
            "Remove cache headers from responses (regex, single-line)",
            false
        );

        Rule addXff = new Rule(
            false,
            Rule.Target.REQUEST,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "^(\\r?\\n)",
            "X-Forwarded-For: 127.0.0.1\\r\\n$1",
            "Add X-Forwarded-For header (regex, single-line)",
            false
        );

        Rule cacheBustNoQuery = new Rule(
            false,
            Rule.Target.REQUEST,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "^(\\w+)\\s+([^\\s?]+)\\s+HTTP/",
            "$1 $2?cachebust=1 HTTP/",
            "Add cache-bust param when no query exists (regex, single-line)",
            false
        );

        Rule cacheBustWithQuery = new Rule(
            false,
            Rule.Target.REQUEST,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "^(\\w+)\\s+([^\\s?]+)(\\?[^\\s]*)\\s+HTTP/",
            "$1 $2$3&cachebust=1 HTTP/",
            "Append cache-bust param when query exists (regex, single-line)",
            false
        );

        Rule removeCsp = new Rule(
            false,
            Rule.Target.RESPONSE,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "(?mi)^Content-Security-Policy:.*$\\r?\\n",
            "",
            "Remove Content-Security-Policy header (regex, single-line)",
            false
        );

        Rule removeHsts = new Rule(
            false,
            Rule.Target.RESPONSE,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "(?mi)^Strict-Transport-Security:.*$\\r?\\n",
            "",
            "Remove HSTS header (regex, single-line)",
            false
        );

        Rule removeHtmlComments = new Rule(
            false,
            Rule.Target.RESPONSE,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.REGEX,
            "<!--.*?-->",
            "",
            "Strip HTML comments (regex, multiline)",
            true
        );

        Rule removeDebugBlock = new Rule(
            false,
            Rule.Target.RESPONSE,
            EnumSet.allOf(ToolType.class),
            Rule.MatchType.SIMPLE,
            "<!--GMR-START-->*<!--GMR-END-->",
            "",
            "Remove a marked HTML block (simple wildcard, multiline)",
            true
        );

        return List.of(
            removeHeader,
            wafBypass,
            userAgentIe,
            userAgentChrome,
            normalizeXff,
            removeDisabled,
            stripCache,
            addXff,
            cacheBustNoQuery,
            cacheBustWithQuery,
            removeCsp,
            removeHsts,
            removeHtmlComments,
            removeDebugBlock
        );
    }
}

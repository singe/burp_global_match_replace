package com.portswigger.globalmatchreplace;

import burp.api.montoya.core.ToolType;

import java.util.ArrayList;
import java.util.List;

final class RuleApplier {
    static RuleApplyResult apply(String message, boolean isRequest, ToolType toolType, List<Rule> rules) {
        String updated = message;
        List<String> appliedSummaries = new ArrayList<>();
        for (int i = 0; i < rules.size(); i++) {
            Rule rule = rules.get(i);
            if (!rule.isEnabled()) {
                continue;
            }
            if (!rule.appliesTo(isRequest)) {
                continue;
            }
            if (!rule.appliesToTool(toolType)) {
                continue;
            }
            String before = updated;
            updated = rule.apply(updated);
            if (!updated.equals(before)) {
                // Persist summary with rule index to aid debugging/history.
                appliedSummaries.add("#" + (i + 1) + " " + rule.summary());
            }
        }
        return new RuleApplyResult(updated, appliedSummaries);
    }
}

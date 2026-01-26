package com.portswigger.globalmatchreplace;

import java.util.List;

// Result of applying a rule set: updated message + summaries for UI/diff display.
record RuleApplyResult(String updated, List<String> appliedSummaries) {}

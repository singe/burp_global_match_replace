package com.portswigger.globalmatchreplace;

import burp.api.montoya.core.ToolType;

import javax.swing.table.AbstractTableModel;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

final class RuleTableModel extends AbstractTableModel {
    private static final String[] COLUMN_NAMES = {
        "Enabled", "Target", "Match Type", "Multiline", "Tools", "Match", "Replace", "Comment"
    };

    private final RuleStore ruleStore;
    private List<Rule> view = new ArrayList<>();

    RuleTableModel(RuleStore ruleStore) {
        this.ruleStore = ruleStore;
        refresh();
        // Refresh on store changes on the EDT.
        ruleStore.addListener(() -> SwingUtilities.invokeLater(this::refresh));
    }

    void refresh() {
        view = ruleStore.snapshot();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return view.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        // Only the Enabled column is directly editable in the table.
        return columnIndex == 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Rule rule = view.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return rule.isEnabled();
            case 1:
                return formatTarget(rule.getTarget());
            case 2:
                return formatMatchType(rule.getMatchType());
            case 3:
                return formatMultiline(rule.isMultiline());
            case 4:
                return toolSummary(rule.getTools());
            case 5:
                return rule.getMatch();
            case 6:
                return rule.getReplace();
            case 7:
                return rule.getComment();
            default:
                return "";
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex != 0) {
            return;
        }
        Rule rule = view.get(rowIndex).copy();
        rule.setEnabled(Boolean.TRUE.equals(aValue));
        ruleStore.update(rowIndex, rule);
    }

    private String toolSummary(Set<ToolType> tools) {
        if (tools.isEmpty()) {
            return "";
        }
        return tools.stream()
            .map(ToolType::toolName)
            .sorted()
            .collect(Collectors.joining(", "));
    }

    private String formatTarget(Rule.Target target) {
        return target == Rule.Target.REQUEST ? "Request" : "Response";
    }

    private String formatMatchType(Rule.MatchType matchType) {
        return matchType == Rule.MatchType.REGEX ? "RegEx" : "Simple";
    }

    private String formatMultiline(boolean multiline) {
        return multiline ? "On" : "";
    }
}

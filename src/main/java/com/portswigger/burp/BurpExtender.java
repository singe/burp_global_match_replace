package com.portswigger.burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.ITab;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {
    private static final String SETTING_RULES = "match_replace_rules";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel panel;

    private RulesTableModel rulesModel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Header Strip");
        callbacks.registerHttpListener(this);

        List<Rule> rules = loadRules();

        SwingUtilities.invokeLater(() -> {
            panel = buildUi(rules);
            callbacks.addSuiteTab(BurpExtender.this);
        });
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        byte[] message = messageIsRequest ? messageInfo.getRequest() : messageInfo.getResponse();
        if (message == null) {
            return;
        }

        String original = helpers.bytesToString(message);
        String updated = applyRules(original, messageIsRequest);

        if (!original.equals(updated)) {
            byte[] updatedBytes = helpers.stringToBytes(updated);
            if (messageIsRequest) {
                messageInfo.setRequest(updatedBytes);
            } else {
                messageInfo.setResponse(updatedBytes);
            }
        }
    }

    @Override
    public String getTabCaption() {
        return "Header Strip";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    private JPanel buildUi(List<Rule> rules) {
        JPanel root = new JPanel(new BorderLayout(12, 12));
        root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        rulesModel = new RulesTableModel(rules);
        JTable table = new JTable(rulesModel);
        table.setPreferredScrollableViewportSize(new Dimension(900, 260));
        table.setFillsViewportHeight(true);

        JComboBox<RuleScope> scopeCombo = new JComboBox<>(RuleScope.values());
        table.getColumnModel().getColumn(1).setCellEditor(new javax.swing.DefaultCellEditor(scopeCombo));

        JComboBox<RuleMode> modeCombo = new JComboBox<>(RuleMode.values());
        table.getColumnModel().getColumn(2).setCellEditor(new javax.swing.DefaultCellEditor(modeCombo));

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Match & Replace (system-wide)"));
        root.add(scrollPane, BorderLayout.CENTER);

        JPanel actions = new JPanel(new BorderLayout());
        JPanel buttons = new JPanel();
        JButton add = new JButton("Add Rule");
        add.addActionListener(event -> {
            rulesModel.addRule(new Rule(true, RuleScope.RESPONSE, RuleMode.LITERAL, "", "", ""));
            saveRules();
        });
        JButton remove = new JButton("Remove Selected");
        remove.addActionListener(event -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                rulesModel.removeRule(row);
                saveRules();
            }
        });
        JButton save = new JButton("Save Rules");
        save.addActionListener(event -> saveRules());

        buttons.add(add);
        buttons.add(remove);
        buttons.add(save);
        actions.add(buttons, BorderLayout.WEST);

        JLabel note = new JLabel("Applies to requests/responses from all Burp tools (including AI), not just Proxy.");
        note.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        actions.add(note, BorderLayout.SOUTH);

        root.add(actions, BorderLayout.SOUTH);

        root.setMinimumSize(new Dimension(980, 420));
        return root;
    }

    private String applyRules(String message, boolean messageIsRequest) {
        if (rulesModel == null) {
            return message;
        }

        String updated = message;
        List<Rule> rules = rulesModel.getRules();
        for (Rule rule : rules) {
            if (!rule.enabled) {
                continue;
            }
            if (!rule.scope.matches(messageIsRequest)) {
                continue;
            }
            if (rule.pattern == null || rule.pattern.isEmpty()) {
                continue;
            }

            if (rule.mode == RuleMode.REGEX) {
                try {
                    updated = Pattern.compile(rule.pattern).matcher(updated).replaceAll(rule.replacement);
                } catch (Exception ignored) {
                    // Skip invalid regex patterns.
                }
            } else {
                updated = updated.replace(rule.pattern, rule.replacement);
            }
        }

        return updated;
    }

    private List<Rule> loadRules() {
        String stored = callbacks.loadExtensionSetting(SETTING_RULES);
        if (stored == null || stored.trim().isEmpty()) {
            return defaultRules();
        }

        List<Rule> rules = new ArrayList<>();
        String[] lines = stored.split("\\n", -1);
        for (String line : lines) {
            if (line.trim().isEmpty()) {
                continue;
            }
            Rule parsed = Rule.fromStorage(line);
            if (parsed != null) {
                rules.add(parsed);
            }
        }

        return rules;
    }

    private List<Rule> defaultRules() {
        List<Rule> rules = new ArrayList<>();

        rules.add(new Rule(
            false,
            RuleScope.RESPONSE,
            RuleMode.REGEX,
            "(?im)^Content-Security-Policy:.*\\r?\\n",
            "",
            "Example: remove the Content-Security-Policy response header"
        ));

        rules.add(new Rule(
            false,
            RuleScope.REQUEST,
            RuleMode.REGEX,
            "(?m)^(\\S+\\s+)(/[^\\s\\?]*)(\\?[^\\s]*)?(\\s+HTTP/[^\\r\\n]+)",
            "$1$2;x='x/graphql/execute/json/y'$3$4",
            "Example: append ;x='x/graphql/execute/json/y' to the request path before any query"
        ));

        return rules;
    }

    private void saveRules() {
        if (rulesModel == null) {
            return;
        }
        StringBuilder builder = new StringBuilder();
        for (Rule rule : rulesModel.getRules()) {
            if (builder.length() > 0) {
                builder.append('\n');
            }
            builder.append(rule.toStorage());
        }
        callbacks.saveExtensionSetting(SETTING_RULES, builder.toString());
    }

    private enum RuleScope {
        REQUEST("Request"),
        RESPONSE("Response"),
        BOTH("Both");

        private final String label;

        RuleScope(String label) {
            this.label = label;
        }

        boolean matches(boolean messageIsRequest) {
            if (this == BOTH) {
                return true;
            }
            if (this == REQUEST) {
                return messageIsRequest;
            }
            return !messageIsRequest;
        }

        @Override
        public String toString() {
            return label;
        }

        static RuleScope fromStorage(String value) {
            for (RuleScope scope : values()) {
                if (scope.name().equals(value)) {
                    return scope;
                }
            }
            return RESPONSE;
        }
    }

    private enum RuleMode {
        LITERAL("Literal"),
        REGEX("Regex");

        private final String label;

        RuleMode(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }

        static RuleMode fromStorage(String value) {
            for (RuleMode mode : values()) {
                if (mode.name().equals(value)) {
                    return mode;
                }
            }
            return LITERAL;
        }
    }

    private static final class Rule {
        private boolean enabled;
        private RuleScope scope;
        private RuleMode mode;
        private String pattern;
        private String replacement;
        private String comment;

        Rule(boolean enabled, RuleScope scope, RuleMode mode, String pattern, String replacement, String comment) {
            this.enabled = enabled;
            this.scope = scope;
            this.mode = mode;
            this.pattern = pattern;
            this.replacement = replacement;
            this.comment = comment;
        }

        String toStorage() {
            return encode(enabled ? "1" : "0") + "|" +
                encode(scope.name()) + "|" +
                encode(mode.name()) + "|" +
                encode(pattern) + "|" +
                encode(replacement) + "|" +
                encode(comment);
        }

        static Rule fromStorage(String value) {
            String[] parts = value.split("\\|", -1);
            if (parts.length < 5) {
                return null;
            }
            boolean enabled = "1".equals(decode(parts[0]));
            RuleScope scope = RuleScope.fromStorage(decode(parts[1]));
            RuleMode mode = RuleMode.fromStorage(decode(parts[2]));
            String pattern = decode(parts[3]);
            String replacement = decode(parts[4]);
            String comment = parts.length >= 6 ? decode(parts[5]) : "";
            return new Rule(enabled, scope, mode, pattern, replacement, comment);
        }

        private static String encode(String value) {
            if (value == null) {
                return "";
            }
            return value
                .replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("|", "\\|");
        }

        private static String decode(String value) {
            if (value == null || value.isEmpty()) {
                return "";
            }
            StringBuilder decoded = new StringBuilder();
            boolean escape = false;
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (escape) {
                    if (c == 'n') {
                        decoded.append('\n');
                    } else if (c == 'r') {
                        decoded.append('\r');
                    } else {
                        decoded.append(c);
                    }
                    escape = false;
                } else if (c == '\\') {
                    escape = true;
                } else {
                    decoded.append(c);
                }
            }
            if (escape) {
                decoded.append('\\');
            }
            return decoded.toString();
        }
    }

    private static final class RulesTableModel extends AbstractTableModel {
        private final List<Rule> rules;
        private final String[] columns = {"Enabled", "Scope", "Mode", "Match", "Replace", "Comment"};

        RulesTableModel(List<Rule> rules) {
            this.rules = rules;
        }

        List<Rule> getRules() {
            return rules;
        }

        void addRule(Rule rule) {
            rules.add(rule);
            int index = rules.size() - 1;
            fireTableRowsInserted(index, index);
        }

        void removeRule(int row) {
            rules.remove(row);
            fireTableRowsDeleted(row, row);
        }

        @Override
        public int getRowCount() {
            return rules.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
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
            return true;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Rule rule = rules.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return rule.enabled;
                case 1:
                    return rule.scope;
                case 2:
                    return rule.mode;
                case 3:
                    return rule.pattern;
                case 4:
                    return rule.replacement;
                case 5:
                    return rule.comment;
                default:
                    return null;
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            Rule rule = rules.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    rule.enabled = aValue instanceof Boolean && (Boolean) aValue;
                    break;
                case 1:
                    if (aValue instanceof RuleScope) {
                        rule.scope = (RuleScope) aValue;
                    }
                    break;
                case 2:
                    if (aValue instanceof RuleMode) {
                        rule.mode = (RuleMode) aValue;
                    }
                    break;
                case 3:
                    rule.pattern = aValue != null ? aValue.toString() : "";
                    break;
                case 4:
                    rule.replacement = aValue != null ? aValue.toString() : "";
                    break;
                case 5:
                    rule.comment = aValue != null ? aValue.toString() : "";
                    break;
                default:
                    break;
            }
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }
}

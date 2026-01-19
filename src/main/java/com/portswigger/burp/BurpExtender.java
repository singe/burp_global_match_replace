package com.portswigger.burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.ITab;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Toolkit;
import java.awt.event.AWTEventListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseEvent;
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
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {
    private static final String SETTING_RULES = "match_replace_rules";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel panel;

    private RulesTableModel rulesModel;
    private JTable rulesTable;
    private JTextPane sampleInput;
    private JTextPane sampleOutput;
    private boolean previewUpdating;
    private JPanel previewPanel;
    private boolean previewExpanded;
    private final Dimension collapsedPreviewSize = new Dimension(420, 140);
    private final Dimension expandedPreviewSize = new Dimension(420, 240);

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
        rulesTable = new JTable(rulesModel);
        rulesTable.setPreferredScrollableViewportSize(new Dimension(900, 260));
        rulesTable.setFillsViewportHeight(true);

        JComboBox<RuleScope> scopeCombo = new JComboBox<>(RuleScope.values());
        rulesTable.getColumnModel().getColumn(1).setCellEditor(new javax.swing.DefaultCellEditor(scopeCombo));

        JComboBox<RuleMode> modeCombo = new JComboBox<>(RuleMode.values());
        rulesTable.getColumnModel().getColumn(2).setCellEditor(new javax.swing.DefaultCellEditor(modeCombo));
        rulesTable.getColumnModel().getColumn(0).setPreferredWidth(60);
        rulesTable.getColumnModel().getColumn(1).setPreferredWidth(90);
        rulesTable.getColumnModel().getColumn(2).setPreferredWidth(90);
        rulesTable.getColumnModel().getColumn(3).setPreferredWidth(260);
        rulesTable.getColumnModel().getColumn(4).setPreferredWidth(260);
        rulesTable.getColumnModel().getColumn(5).setPreferredWidth(300);

        JScrollPane scrollPane = new JScrollPane(rulesTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Match & Replace (system-wide)"));

        JPanel preview = buildPreviewPanel();

        JPanel center = new JPanel(new BorderLayout(8, 8));
        center.add(scrollPane, BorderLayout.CENTER);
        center.add(preview, BorderLayout.SOUTH);
        root.add(center, BorderLayout.CENTER);

        JPanel actions = new JPanel(new BorderLayout());
        JPanel buttons = new JPanel();
        JButton add = new JButton("Add Rule");
        add.addActionListener(event -> {
            rulesModel.addRule(new Rule(true, RuleScope.RESPONSE, RuleMode.LITERAL, "", "", ""));
            saveRules();
        });
        JButton remove = new JButton("Remove Selected");
        remove.addActionListener(event -> {
            int row = rulesTable.getSelectedRow();
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

    private JPanel buildPreviewPanel() {
        JPanel preview = new JPanel(new BorderLayout(8, 8));
        preview.setBorder(BorderFactory.createTitledBorder("Rule Preview"));
        previewPanel = preview;

        JPanel io = new JPanel(new GridBagLayout());
        GridBagConstraints ioConstraints = new GridBagConstraints();
        ioConstraints.gridx = 0;
        ioConstraints.gridy = 0;
        ioConstraints.weightx = 0.5;
        ioConstraints.anchor = GridBagConstraints.WEST;
        JLabel inputLabel = new JLabel("Sample Input (paste full request/response):");
        io.add(inputLabel, ioConstraints);

        sampleInput = new JTextPane();
        sampleInput.setPreferredSize(collapsedPreviewSize);
        JScrollPane inputScroll = new JScrollPane(sampleInput);
        ioConstraints.gridy = 1;
        ioConstraints.weighty = 1.0;
        ioConstraints.fill = GridBagConstraints.BOTH;
        io.add(inputScroll, ioConstraints);

        sampleOutput = new JTextPane();
        sampleOutput.setEditable(false);
        sampleOutput.setPreferredSize(collapsedPreviewSize);
        JScrollPane outputScroll = new JScrollPane(sampleOutput);
        ioConstraints.gridx = 1;
        ioConstraints.gridy = 0;
        ioConstraints.weightx = 0.5;
        ioConstraints.weighty = 0.0;
        ioConstraints.fill = GridBagConstraints.NONE;
        ioConstraints.insets = new java.awt.Insets(0, 16, 0, 0);
        JLabel outputLabel = new JLabel("Preview Output (read-only, regex groups highlighted):");
        io.add(outputLabel, ioConstraints);

        ioConstraints.gridy = 1;
        ioConstraints.weighty = 1.0;
        ioConstraints.fill = GridBagConstraints.BOTH;
        io.add(outputScroll, ioConstraints);

        preview.add(io, BorderLayout.CENTER);

        JPanel previewActions = new JPanel(new BorderLayout());
        JButton test = new JButton("Test Rule");
        test.addActionListener(event -> {
            expandPreview();
            updatePreview();
        });
        previewActions.add(test, BorderLayout.WEST);
        preview.add(previewActions, BorderLayout.SOUTH);

        setPreviewText("Click \"Test Rule\" to apply the selected rule to the sample input.");
        installPreviewBehavior();
        resizePreview(collapsedPreviewSize);

        return preview;
    }

    private void installPreviewBehavior() {
        sampleInput.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                expandPreview();
            }
        });

        Toolkit.getDefaultToolkit().addAWTEventListener(new AWTEventListener() {
            @Override
            public void eventDispatched(java.awt.AWTEvent event) {
                if (!(event instanceof MouseEvent)) {
                    return;
                }
                MouseEvent mouseEvent = (MouseEvent) event;
                if (mouseEvent.getID() != MouseEvent.MOUSE_PRESSED) {
                    return;
                }
                Object source = mouseEvent.getSource();
                if (!(source instanceof Component)) {
                    return;
                }
                Component component = (Component) source;
                if (!isDescendant(previewPanel, component)) {
                    collapsePreview();
                }
            }
        }, java.awt.AWTEvent.MOUSE_EVENT_MASK);
    }

    private boolean isDescendant(Component root, Component target) {
        if (root == null || target == null) {
            return false;
        }
        if (root == target) {
            return true;
        }
        Component parent = target.getParent();
        while (parent != null) {
            if (parent == root) {
                return true;
            }
            parent = parent.getParent();
        }
        return false;
    }

    private void expandPreview() {
        if (previewExpanded) {
            return;
        }
        previewExpanded = true;
        resizePreview(expandedPreviewSize);
    }

    private void collapsePreview() {
        if (!previewExpanded) {
            return;
        }
        previewExpanded = false;
        resizePreview(collapsedPreviewSize);
    }

    private void resizePreview(Dimension size) {
        sampleInput.setPreferredSize(size);
        sampleOutput.setPreferredSize(size);
        int width = previewPanel.getPreferredSize().width > 0 ? previewPanel.getPreferredSize().width : 900;
        int height = size.height + 80;
        previewPanel.setPreferredSize(new Dimension(width, height));
        previewPanel.revalidate();
        previewPanel.repaint();
    }

    private void updatePreview() {
        if (previewUpdating) {
            return;
        }
        if (rulesTable == null || sampleInput == null || sampleOutput == null) {
            return;
        }

        previewUpdating = true;
        try {
            int row = rulesTable.getSelectedRow();
            if (row < 0) {
                setPreviewText("Select a rule to preview.");
                clearInputHighlights();
                clearOutputHighlights();
                return;
            }

            Rule rule = rulesModel.getRules().get(row);
            String input = sampleInput.getText();
            if (input == null) {
                input = "";
            }

            if (rule.pattern == null || rule.pattern.isEmpty()) {
                setPreviewText(input);
                clearInputHighlights();
                clearOutputHighlights();
                return;
            }

            if (rule.mode == RuleMode.REGEX) {
                renderRegexPreview(input, rule.pattern, rule.replacement);
            } else {
                String replacement = rule.replacement == null ? "" : rule.replacement;
                String replaced = input.replace(rule.pattern, replacement);
                setPreviewText(replaced);
                highlightLiteralLine(input, rule.pattern, replacement, replaced);
            }
        } finally {
            previewUpdating = false;
        }
    }

    private void renderRegexPreview(String input, String patternText, String replacement) {
        try {
            Pattern pattern = Pattern.compile(patternText);
            java.util.regex.Matcher matcher = pattern.matcher(input);
            if (!matcher.find()) {
                setPreviewText(input);
                clearInputHighlights();
                clearOutputHighlights();
                return;
            }

            StringBuilder output = new StringBuilder();
            List<GroupSpan> groupSpans = new ArrayList<>();
            String replacementSafe = replacement == null ? "" : replacement;
            int groupCount = matcher.groupCount();

            String before = input.substring(0, matcher.start());
            output.append(before);

            int outputOffset = output.length();
            ReplacementResult result = applyReplacement(matcher, replacementSafe, outputOffset, groupCount);
            output.append(result.text);
            groupSpans.addAll(result.spans);

            String after = input.substring(matcher.end());
            output.append(after);

            setPreviewText(output.toString());
            clearInputHighlights();
            clearOutputHighlights();
            highlightInputLines(input, matcher.start(), matcher.end());
            highlightOutputLines(output.toString(), result.replacementStart, result.replacementEnd);
            highlightInputGroups(result.inputSpans);
            highlightOutputGroups(groupSpans);
        } catch (Exception ex) {
            setPreviewText("Invalid regex: " + ex.getMessage());
            clearInputHighlights();
            clearOutputHighlights();
        }
    }

    private ReplacementResult applyReplacement(java.util.regex.Matcher matcher, String replacement, int outputOffset, int groupCount) {
        StringBuilder result = new StringBuilder();
        List<GroupSpan> outputSpans = new ArrayList<>();
        List<GroupSpan> inputSpans = new ArrayList<>();

        for (int i = 1; i <= groupCount; i++) {
            try {
                int start = matcher.start(i);
                int end = matcher.end(i);
                if (start >= 0 && end >= 0) {
                    inputSpans.add(new GroupSpan(i, start, end));
                }
            } catch (IllegalStateException ignored) {
                // group not present
            }
        }

        for (int i = 0; i < replacement.length(); i++) {
            char c = replacement.charAt(i);
            if (c == '$' && i + 1 < replacement.length()) {
                char next = replacement.charAt(i + 1);
                if (Character.isDigit(next)) {
                    int group = next - '0';
                    String groupText = matcher.group(group);
                    if (groupText != null) {
                        int spanStart = outputOffset + result.length();
                        result.append(groupText);
                        int spanEnd = outputOffset + result.length();
                        outputSpans.add(new GroupSpan(group, spanStart, spanEnd));
                    }
                    i++;
                    continue;
                }
            }
            result.append(c);
        }

        int replacementStart = outputOffset;
        int replacementEnd = outputOffset + result.length();
        return new ReplacementResult(result.toString(), inputSpans, outputSpans, replacementStart, replacementEnd);
    }

    private void highlightInputGroups(List<GroupSpan> inputSpans) {
        StyledDocument doc = sampleInput.getStyledDocument();
        List<Color> palette = groupPalette();

        for (GroupSpan span : inputSpans) {
            if (span.start >= 0 && span.end <= doc.getLength()) {
                SimpleAttributeSet attrs = new SimpleAttributeSet();
                StyleConstants.setBackground(attrs, palette.get((span.group - 1) % palette.size()));
                doc.setCharacterAttributes(span.start, span.end - span.start, attrs, false);
            }
        }
    }

    private void highlightOutputGroups(List<GroupSpan> outputSpans) {
        StyledDocument doc = sampleOutput.getStyledDocument();
        List<Color> palette = groupPalette();
        for (GroupSpan span : outputSpans) {
            if (span.start >= 0 && span.end <= doc.getLength()) {
                SimpleAttributeSet attrs = new SimpleAttributeSet();
                StyleConstants.setBackground(attrs, palette.get((span.group - 1) % palette.size()));
                doc.setCharacterAttributes(span.start, span.end - span.start, attrs, false);
            }
        }
    }

    private void highlightInputLines(String text, int start, int end) {
        LineSpan span = lineSpanForStart(text, start);
        if (span == null) {
            return;
        }
        applyLineHighlight(sampleInput.getStyledDocument(), span.start, span.end, new Color(255, 244, 214));
    }

    private void highlightOutputLines(String text, int start, int end) {
        LineSpan span = lineSpanForStart(text, start);
        if (span == null) {
            return;
        }
        applyLineHighlight(sampleOutput.getStyledDocument(), span.start, span.end, new Color(224, 244, 255));
    }

    private LineSpan lineSpanForStart(String text, int start) {
        if (start < 0 || start >= text.length()) {
            return null;
        }
        int lineStart = text.lastIndexOf('\n', start);
        lineStart = lineStart == -1 ? 0 : lineStart + 1;
        int lineEnd = text.indexOf('\n', lineStart);
        lineEnd = lineEnd == -1 ? text.length() : lineEnd;
        return new LineSpan(lineStart, lineEnd);
    }

    private void highlightLiteralLine(String input, String pattern, String replacement, String output) {
        clearInputHighlights();
        clearOutputHighlights();

        int matchStart = pattern == null ? -1 : input.indexOf(pattern);
        if (matchStart >= 0) {
            highlightInputLines(input, matchStart, matchStart + pattern.length());
        }

        int outStart = (replacement == null || replacement.isEmpty()) ? -1 : output.indexOf(replacement);
        if (outStart >= 0) {
            highlightOutputLines(output, outStart, outStart + replacement.length());
        }
    }

    private void applyLineHighlight(StyledDocument doc, int start, int end, Color color) {
        if (start < 0 || end <= start || end > doc.getLength()) {
            return;
        }
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setBackground(attrs, color);
        doc.setCharacterAttributes(start, end - start, attrs, false);
    }

    private void clearInputHighlights() {
        StyledDocument doc = sampleInput.getStyledDocument();
        SimpleAttributeSet base = new SimpleAttributeSet();
        StyleConstants.setForeground(base, Color.BLACK);
        StyleConstants.setBackground(base, Color.WHITE);
        doc.setCharacterAttributes(0, doc.getLength(), base, true);
    }

    private void clearOutputHighlights() {
        StyledDocument doc = sampleOutput.getStyledDocument();
        SimpleAttributeSet base = new SimpleAttributeSet();
        StyleConstants.setForeground(base, Color.BLACK);
        StyleConstants.setBackground(base, Color.WHITE);
        doc.setCharacterAttributes(0, doc.getLength(), base, true);
    }

    private List<Color> groupPalette() {
        List<Color> colors = new ArrayList<>();
        colors.add(new Color(255, 235, 153));
        colors.add(new Color(204, 235, 197));
        colors.add(new Color(201, 215, 247));
        colors.add(new Color(255, 209, 220));
        return colors;
    }

    private void setPreviewText(String text) {
        StyledDocument doc = sampleOutput.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
            doc.insertString(0, text, new SimpleAttributeSet());
        } catch (BadLocationException ignored) {
            // ignore
        }
    }

    private static final class GroupSpan {
        private final int group;
        private final int start;
        private final int end;

        private GroupSpan(int group, int start, int end) {
            this.group = group;
            this.start = start;
            this.end = end;
        }
    }

    private static final class LineSpan {
        private final int start;
        private final int end;

        private LineSpan(int start, int end) {
            this.start = start;
            this.end = end;
        }
    }

    private static final class ReplacementResult {
        private final String text;
        private final List<GroupSpan> inputSpans;
        private final List<GroupSpan> spans;
        private final int replacementStart;
        private final int replacementEnd;

        private ReplacementResult(String text, List<GroupSpan> inputSpans, List<GroupSpan> spans, int replacementStart, int replacementEnd) {
            this.text = text;
            this.inputSpans = inputSpans;
            this.spans = spans;
            this.replacementStart = replacementStart;
            this.replacementEnd = replacementEnd;
        }
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

package com.portswigger.globalmatchreplace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.Window;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

final class RuleDialog extends JDialog {
    private final JCheckBox enabledCheck;
    private final JRadioButton requestRadio;
    private final JRadioButton responseRadio;
    private final JRadioButton simpleRadio;
    private final JRadioButton regexRadio;
    private final JCheckBox multilineCheck;
    private final JTextField matchField;
    private final JTextArea replaceField;
    private final JTextArea commentField;
    private final JLabel validationLabel;
    private final Map<ToolType, JCheckBox> toolChecks;
    private Rule result;

    RuleDialog(Window owner, MontoyaApi api, Rule initial) {
        super(owner, "Rule", ModalityType.APPLICATION_MODAL);
        enabledCheck = new JCheckBox("Enabled");
        requestRadio = new JRadioButton("Request");
        responseRadio = new JRadioButton("Response");
        simpleRadio = new JRadioButton("Simple");
        regexRadio = new JRadioButton("Regex");
        multilineCheck = new JCheckBox("Multiline (dot matches newlines)");
        matchField = new JTextField(30);
        replaceField = new JTextArea(4, 30);
        commentField = new JTextArea(3, 30);
        validationLabel = new JLabel(" ");
        toolChecks = new EnumMap<>(ToolType.class);

        buildUi(api, initial);
        pack();
        setLocationRelativeTo(owner);
    }

    private void buildUi(MontoyaApi api, Rule initial) {
        JPanel content = new JPanel(new BorderLayout(12, 12));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));

        JPanel enabledRow = new JPanel(new BorderLayout());
        enabledRow.add(enabledCheck, BorderLayout.WEST);
        form.add(enabledRow);
        form.add(Box.createVerticalStrut(6));

        JPanel targetRow = new JPanel(new GridLayout(1, 2, 8, 0));
        ButtonGroup targetGroup = new ButtonGroup();
        targetGroup.add(requestRadio);
        targetGroup.add(responseRadio);
        targetRow.setBorder(BorderFactory.createTitledBorder("Target"));
        targetRow.add(requestRadio);
        targetRow.add(responseRadio);
        form.add(targetRow);
        form.add(Box.createVerticalStrut(6));

        JPanel matchTypeRow = new JPanel(new GridLayout(1, 2, 8, 0));
        ButtonGroup matchTypeGroup = new ButtonGroup();
        matchTypeGroup.add(simpleRadio);
        matchTypeGroup.add(regexRadio);
        matchTypeRow.setBorder(BorderFactory.createTitledBorder("Match Type"));
        matchTypeRow.add(simpleRadio);
        matchTypeRow.add(regexRadio);
        form.add(matchTypeRow);
        form.add(Box.createVerticalStrut(6));

        JPanel multilineRow = new JPanel(new BorderLayout());
        multilineRow.add(multilineCheck, BorderLayout.WEST);
        form.add(multilineRow);
        form.add(Box.createVerticalStrut(6));

        JPanel matchRow = new JPanel(new BorderLayout());
        matchRow.setBorder(BorderFactory.createTitledBorder("Match"));
        matchRow.add(matchField, BorderLayout.CENTER);
        form.add(matchRow);
        form.add(Box.createVerticalStrut(6));

        JPanel replaceRow = new JPanel(new BorderLayout());
        replaceRow.setBorder(BorderFactory.createTitledBorder("Replace"));
        replaceRow.add(new JScrollPane(replaceField), BorderLayout.CENTER);
        form.add(replaceRow);
        form.add(Box.createVerticalStrut(6));

        JPanel commentRow = new JPanel(new BorderLayout());
        commentRow.setBorder(BorderFactory.createTitledBorder("Comment"));
        commentRow.add(new JScrollPane(commentField), BorderLayout.CENTER);
        form.add(commentRow);
        form.add(Box.createVerticalStrut(6));

        JPanel toolsRow = new JPanel();
        toolsRow.setLayout(new BoxLayout(toolsRow, BoxLayout.Y_AXIS));
        toolsRow.setBorder(BorderFactory.createTitledBorder("Tools"));
        JPanel toolGrid = new JPanel(new GridLayout(0, 3, 6, 6));
        for (ToolType toolType : ToolType.values()) {
            JCheckBox checkBox = new JCheckBox(toolType.toolName());
            toolChecks.put(toolType, checkBox);
            toolGrid.add(checkBox);
        }
        toolsRow.add(toolGrid);
        JPanel toolsButtons = new JPanel(new GridLayout(1, 2, 6, 0));
        JButton selectAll = new JButton("Select All");
        JButton selectNone = new JButton("Select None");
        selectAll.addActionListener(event -> setToolsSelected(true));
        selectNone.addActionListener(event -> setToolsSelected(false));
        toolsButtons.add(selectAll);
        toolsButtons.add(selectNone);
        toolsRow.add(Box.createVerticalStrut(6));
        toolsRow.add(toolsButtons);
        form.add(toolsRow);
        form.add(Box.createVerticalStrut(6));

        validationLabel.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
        form.add(validationLabel);

        content.add(form, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new GridLayout(1, 2, 8, 0));
        JButton save = new JButton("Save");
        JButton cancel = new JButton("Cancel");
        save.addActionListener(event -> onSave());
        cancel.addActionListener(event -> onCancel());
        buttons.add(save);
        buttons.add(cancel);
        content.add(buttons, BorderLayout.SOUTH);

        // Keep dialog styling consistent with Burp theme.
        setContentPane(content);
        api.userInterface().applyThemeToComponent(this);

        loadInitial(initial);
    }

    private void loadInitial(Rule rule) {
        enabledCheck.setSelected(rule.isEnabled());
        requestRadio.setSelected(rule.getTarget() == Rule.Target.REQUEST);
        responseRadio.setSelected(rule.getTarget() == Rule.Target.RESPONSE);
        simpleRadio.setSelected(rule.getMatchType() == Rule.MatchType.SIMPLE);
        regexRadio.setSelected(rule.getMatchType() == Rule.MatchType.REGEX);
        multilineCheck.setSelected(rule.isMultiline());
        matchField.setText(rule.getMatch());
        replaceField.setText(rule.getReplace());
        commentField.setText(rule.getComment());
        setToolsSelected(false);
        for (ToolType toolType : rule.getTools()) {
            JCheckBox box = toolChecks.get(toolType);
            if (box != null) {
                box.setSelected(true);
            }
        }
    }

    private void setToolsSelected(boolean selected) {
        for (JCheckBox checkBox : toolChecks.values()) {
            checkBox.setSelected(selected);
        }
    }

    private void onSave() {
        Rule.Target target = requestRadio.isSelected() ? Rule.Target.REQUEST : Rule.Target.RESPONSE;
        Rule.MatchType matchType = simpleRadio.isSelected() ? Rule.MatchType.SIMPLE : Rule.MatchType.REGEX;
        Set<ToolType> selectedTools = EnumSet.noneOf(ToolType.class);
        for (Map.Entry<ToolType, JCheckBox> entry : toolChecks.entrySet()) {
            if (entry.getValue().isSelected()) {
                selectedTools.add(entry.getKey());
            }
        }
        Rule candidate = new Rule(
            enabledCheck.isSelected(),
            target,
            selectedTools,
            matchType,
            matchField.getText(),
            replaceField.getText(),
            commentField.getText(),
            multilineCheck.isSelected()
        );
        if (candidate.getMatchType() == Rule.MatchType.REGEX && !candidate.hasValidPattern()) {
            validationLabel.setText("Invalid regex pattern.");
            return;
        }
        if (candidate.getMatch().isEmpty()) {
            // Allow empty match, but warn since it does nothing.
            int choice = JOptionPane.showConfirmDialog(this, "Match is empty. This rule will do nothing. Save anyway?", "Confirm", JOptionPane.YES_NO_OPTION);
            if (choice != JOptionPane.YES_OPTION) {
                return;
            }
        }
        result = candidate;
        setVisible(false);
    }

    private void onCancel() {
        result = null;
        setVisible(false);
    }

    Rule showDialog() {
        setVisible(true);
        return result;
    }
}

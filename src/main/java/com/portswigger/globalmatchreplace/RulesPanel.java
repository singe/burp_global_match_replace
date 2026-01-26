package com.portswigger.globalmatchreplace;

import burp.api.montoya.MontoyaApi;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Window;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

final class RulesPanel {
    private final MontoyaApi api;
    private final RuleStore ruleStore;
    private final JPanel panel;
    private final RuleTableModel tableModel;
    private final JTable table;
    private final RuleTestPanel testPanel;
    private int lastSelectedRow = -1;

    RulesPanel(MontoyaApi api, RuleStore ruleStore) {
        this.api = api;
        this.ruleStore = ruleStore;
        this.panel = new JPanel(new BorderLayout(8, 8));
        this.tableModel = new RuleTableModel(ruleStore);
        this.table = new JTable(tableModel);
        this.testPanel = new RuleTestPanel(api);

        buildUi();
    }

    private void buildUi() {
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(22);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setPreferredScrollableViewportSize(new Dimension(1100, 260));
        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    // Track selection to preserve row after edits.
                    lastSelectedRow = table.getSelectedRow();
                }
            }
        });
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && table.getSelectedRow() >= 0) {
                    // Double-click edits the selected rule.
                    editRule();
                }
            }
        });

        JPanel top = new JPanel(new BorderLayout(8, 8));
        top.setBorder(BorderFactory.createTitledBorder("Rules"));
        top.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel buttons = new JPanel();
        JButton add = new JButton("Add");
        JButton edit = new JButton("Edit");
        JButton duplicate = new JButton("Duplicate");
        JButton remove = new JButton("Remove");
        add.addActionListener(event -> addRule());
        edit.addActionListener(event -> editRule());
        duplicate.addActionListener(event -> duplicateRule());
        remove.addActionListener(event -> removeRule());
        buttons.add(add);
        buttons.add(edit);
        buttons.add(duplicate);
        buttons.add(remove);
        top.add(buttons, BorderLayout.SOUTH);

        testPanel.setRuleSupplier(this::selectedRule);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, testPanel);
        split.setResizeWeight(0.5);

        panel.add(split, BorderLayout.CENTER);
        api.userInterface().applyThemeToComponent(panel);

        // Restore table selection after rule store updates.
        ruleStore.addListener(() -> SwingUtilities.invokeLater(this::restoreSelection));

        table.getColumnModel().getColumn(0).setPreferredWidth(55);
        table.getColumnModel().getColumn(1).setPreferredWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(75);
        table.getColumnModel().getColumn(3).setPreferredWidth(70);
        table.getColumnModel().getColumn(4).setPreferredWidth(90);
        table.getColumnModel().getColumn(5).setPreferredWidth(260);
        table.getColumnModel().getColumn(6).setPreferredWidth(260);
        table.getColumnModel().getColumn(7).setPreferredWidth(320);
    }

    private void addRule() {
        Rule rule = Rule.defaultRule();
        RuleDialog dialog = new RuleDialog(ownerWindow(), api, rule);
        Rule result = dialog.showDialog();
        if (result != null) {
            ruleStore.add(result);
            // Keep the newly added rule selected.
            lastSelectedRow = ruleStore.size() - 1;
            restoreSelection();
        }
    }

    private void editRule() {
        int row = table.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(panel, "Select a rule to edit.");
            return;
        }
        Rule current = ruleStore.get(row);
        RuleDialog dialog = new RuleDialog(ownerWindow(), api, current);
        Rule result = dialog.showDialog();
        if (result != null) {
            ruleStore.update(row, result);
            // Preserve selection after edit for testing convenience.
            lastSelectedRow = row;
            restoreSelection();
        }
    }

    private void duplicateRule() {
        int row = table.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(panel, "Select a rule to duplicate.");
            return;
        }
        Rule copy = ruleStore.get(row).copy();
        // Duplicates are disabled to avoid accidental activation.
        copy.setEnabled(false);
        ruleStore.add(copy);
        lastSelectedRow = ruleStore.size() - 1;
        restoreSelection();
    }

    private void removeRule() {
        int row = table.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(panel, "Select a rule to remove.");
            return;
        }
        int choice = JOptionPane.showConfirmDialog(panel, "Remove selected rule?", "Confirm", JOptionPane.YES_NO_OPTION);
        if (choice == JOptionPane.YES_OPTION) {
            ruleStore.remove(row);
            // Maintain selection if possible after removal.
            if (ruleStore.size() == 0) {
                lastSelectedRow = -1;
            } else if (row >= ruleStore.size()) {
                lastSelectedRow = ruleStore.size() - 1;
            } else {
                lastSelectedRow = row;
            }
            restoreSelection();
        }
    }

    private Rule selectedRule() {
        int row = table.getSelectedRow();
        if (row < 0) {
            return null;
        }
        return ruleStore.get(row);
    }

    private void restoreSelection() {
        if (lastSelectedRow < 0 || lastSelectedRow >= ruleStore.size()) {
            return;
        }
        table.getSelectionModel().setSelectionInterval(lastSelectedRow, lastSelectedRow);
    }

    private Window ownerWindow() {
        return JOptionPane.getRootFrame();
    }

    public JPanel uiComponent() {
        return panel;
    }

}

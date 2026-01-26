package com.portswigger.globalmatchreplace;

import burp.api.montoya.MontoyaApi;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.JLabel;
import javax.swing.text.AttributeSet;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.geom.Rectangle2D;
import java.util.List;

final class DiffViewerPanel {
    private final JPanel panel;
    private final JTextArea summaryArea;
    private final JTextPane originalPane;
    private final JTextPane modifiedPane;
    private final JButton prevOriginalButton;
    private final JButton nextOriginalButton;
    private final JButton prevModifiedButton;
    private final JButton nextModifiedButton;
    private final JLabel originalCountLabel;
    private final JLabel modifiedCountLabel;
    private List<TextDiffHighlighter.Highlight> originalHighlights = List.of();
    private List<TextDiffHighlighter.Highlight> modifiedHighlights = List.of();
    private int currentOriginalIndex = -1;
    private int currentModifiedIndex = -1;

    DiffViewerPanel(MontoyaApi api, String originalLabel, String modifiedLabel) {
        this.panel = new JPanel(new BorderLayout(8, 8));
        this.summaryArea = new JTextArea(3, 80);
        this.originalPane = new JTextPane();
        this.modifiedPane = new JTextPane();
        this.prevOriginalButton = new JButton("<");
        this.nextOriginalButton = new JButton(">");
        this.prevModifiedButton = new JButton("<");
        this.nextModifiedButton = new JButton(">");
        this.originalCountLabel = new JLabel("0");
        this.modifiedCountLabel = new JLabel("0");

        int buttonWidth = 26;
        int buttonHeight = 22;
        java.awt.Dimension buttonSize = new java.awt.Dimension(buttonWidth, buttonHeight);
        Insets buttonInsets = new Insets(0, 4, 0, 4);
        nextOriginalButton.setPreferredSize(buttonSize);
        nextOriginalButton.setMaximumSize(buttonSize);
        nextOriginalButton.setMinimumSize(buttonSize);
        nextOriginalButton.setMargin(buttonInsets);
        prevOriginalButton.setPreferredSize(buttonSize);
        prevOriginalButton.setMaximumSize(buttonSize);
        prevOriginalButton.setMinimumSize(buttonSize);
        prevOriginalButton.setMargin(buttonInsets);
        nextModifiedButton.setPreferredSize(buttonSize);
        nextModifiedButton.setMaximumSize(buttonSize);
        nextModifiedButton.setMinimumSize(buttonSize);
        nextModifiedButton.setMargin(buttonInsets);
        prevModifiedButton.setPreferredSize(buttonSize);
        prevModifiedButton.setMaximumSize(buttonSize);
        prevModifiedButton.setMinimumSize(buttonSize);
        prevModifiedButton.setMargin(buttonInsets);

        // Match Burp editor font for consistency across views.
        Font font = api.userInterface().currentEditorFont();
        if (font == null) {
            font = new Font("Monospaced", Font.PLAIN, 12);
        }
        originalPane.setFont(font);
        modifiedPane.setFont(font);

        summaryArea.setEditable(false);
        summaryArea.setLineWrap(true);
        summaryArea.setWrapStyleWord(true);
        summaryArea.setBorder(BorderFactory.createTitledBorder("Applied Rules"));

        JPanel top = new JPanel(new BorderLayout(8, 8));
        top.add(summaryArea, BorderLayout.CENTER);

        JPanel originalPanel = new JPanel(new BorderLayout());
        originalPanel.setBorder(BorderFactory.createTitledBorder(originalLabel));
        JPanel originalHeader = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        originalHeader.add(originalCountLabel);
        originalHeader.add(prevOriginalButton);
        originalHeader.add(nextOriginalButton);
        JScrollPane originalScroll = new JScrollPane(originalPane);
        originalPanel.add(originalHeader, BorderLayout.NORTH);
        originalPanel.add(originalScroll, BorderLayout.CENTER);

        JPanel modifiedPanel = new JPanel(new BorderLayout());
        modifiedPanel.setBorder(BorderFactory.createTitledBorder(modifiedLabel));
        JPanel modifiedHeader = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        modifiedHeader.add(modifiedCountLabel);
        modifiedHeader.add(prevModifiedButton);
        modifiedHeader.add(nextModifiedButton);
        JScrollPane modifiedScroll = new JScrollPane(modifiedPane);
        modifiedPanel.add(modifiedHeader, BorderLayout.NORTH);
        modifiedPanel.add(modifiedScroll, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, originalPanel, modifiedPanel);
        split.setResizeWeight(0.5);

        panel.add(top, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);

        // Navigation buttons are intentionally tiny to preserve vertical space.
        prevOriginalButton.setToolTipText("Previous change in original");
        nextOriginalButton.setToolTipText("Next change in original");
        prevModifiedButton.setToolTipText("Previous change in modified");
        nextModifiedButton.setToolTipText("Next change in modified");
        prevOriginalButton.addActionListener(event -> jumpToOriginalChange(-1));
        nextOriginalButton.addActionListener(event -> jumpToOriginalChange(1));
        prevModifiedButton.addActionListener(event -> jumpToModifiedChange(-1));
        nextModifiedButton.addActionListener(event -> jumpToModifiedChange(1));
        prevOriginalButton.setEnabled(false);
        nextOriginalButton.setEnabled(false);
        prevModifiedButton.setEnabled(false);
        nextModifiedButton.setEnabled(false);

        api.userInterface().applyThemeToComponent(panel);
    }

    JPanel uiComponent() {
        return panel;
    }

    JTextPane modifiedPane() {
        return modifiedPane;
    }

    void setContents(String original, String modified, List<String> summaries) {
        String originalText = original == null ? "" : original;
        String modifiedText = modified == null ? "" : modified;
        // Diff highlights are line-based for speed and stability.
        TextDiffHighlighter.DiffResult diff = TextDiffHighlighter.diff(originalText, modifiedText);

        this.originalHighlights = diff.originalHighlights();
        this.modifiedHighlights = diff.modifiedHighlights();
        this.currentOriginalIndex = -1;
        this.currentModifiedIndex = -1;
        prevOriginalButton.setEnabled(!originalHighlights.isEmpty());
        nextOriginalButton.setEnabled(!originalHighlights.isEmpty());
        prevModifiedButton.setEnabled(!modifiedHighlights.isEmpty());
        nextModifiedButton.setEnabled(!modifiedHighlights.isEmpty());
        updateCountLabel(originalCountLabel, 0, originalHighlights.size());
        updateCountLabel(modifiedCountLabel, 0, modifiedHighlights.size());

        applyHighlights(originalPane, originalText, originalHighlights);
        applyHighlights(modifiedPane, modifiedText, modifiedHighlights);
        scrollToTop(originalPane);
        scrollToTop(modifiedPane);

        if (summaries == null || summaries.isEmpty()) {
            summaryArea.setText("No modifications recorded.");
            return;
        }
        StringBuilder builder = new StringBuilder();
        for (String summary : summaries) {
            builder.append("- ").append(summary).append('\n');
        }
        summaryArea.setText(builder.toString().trim());
    }

    private void applyHighlights(JTextPane pane, String text, List<TextDiffHighlighter.Highlight> highlights) {
        StyledDocument doc = pane.getStyledDocument();
        SwingUtilities.invokeLater(() -> {
            try {
                // Replace document content then apply highlight spans.
                doc.remove(0, doc.getLength());
                doc.insertString(0, text, null);
                for (TextDiffHighlighter.Highlight segment : highlights) {
                    if (segment.end() <= segment.start()) {
                        continue;
                    }
                    AttributeSet attrs = coloredBackground(segment.color());
                    doc.setCharacterAttributes(segment.start(), segment.end() - segment.start(), attrs, false);
                }
            } catch (Exception ex) {
                // ignore rendering errors
            }
        });
    }

    private void scrollToTop(JTextPane pane) {
        SwingUtilities.invokeLater(() -> {
            try {
                pane.setCaretPosition(0);
                Rectangle2D rect = pane.modelToView2D(0);
                if (rect != null) {
                    pane.scrollRectToVisible(rect.getBounds());
                }
            } catch (Exception ignored) {
                // ignore selection errors
            }
        });
    }

    private AttributeSet coloredBackground(java.awt.Color color) {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setBackground(attrs, color);
        return attrs;
    }

    private void jumpToOriginalChange(int direction) {
        jumpTo(originalPane, originalHighlights, false, originalCountLabel, direction);
    }

    private void jumpToModifiedChange(int direction) {
        jumpTo(modifiedPane, modifiedHighlights, true, modifiedCountLabel, direction);
    }

    private void jumpTo(JTextPane pane, List<TextDiffHighlighter.Highlight> highlights, boolean useModified, JLabel label, int direction) {
        if (highlights.isEmpty()) {
            return;
        }
        int size = highlights.size();
        int index = useModified ? currentModifiedIndex : currentOriginalIndex;
        if (index < 0) {
            index = direction < 0 ? size - 1 : 0;
        } else if (direction < 0) {
            index = (index - 1 + size) % size;
        } else {
            index = (index + 1) % size;
        }
        TextDiffHighlighter.Highlight highlight = highlights.get(index);
        if (useModified) {
            currentModifiedIndex = index;
        } else {
            currentOriginalIndex = index;
        }
        updateCountLabel(label, index + 1, size);
        int start = Math.max(0, highlight.start());
        int end = Math.max(start, highlight.end());
        try {
            pane.setCaretPosition(start);
            if (end > start) {
                pane.moveCaretPosition(end);
            }
            Rectangle2D rect = pane.modelToView2D(start);
            if (rect != null) {
                pane.scrollRectToVisible(rect.getBounds());
            }
        } catch (Exception ignored) {
            // ignore selection errors
        }
    }

    private void updateCountLabel(JLabel label, int current, int total) {
        if (total <= 0) {
            label.setText("0");
            return;
        }
        if (current <= 0) {
            label.setText(String.valueOf(total));
            return;
        }
        label.setText(current + "/" + total);
    }
}

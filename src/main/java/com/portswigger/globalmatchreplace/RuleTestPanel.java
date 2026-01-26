package com.portswigger.globalmatchreplace;

import burp.api.montoya.MontoyaApi;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.SwingConstants;
import javax.swing.text.AttributeSet;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

final class RuleTestPanel extends JPanel {
    private final JTextPane inputPane;
    private final JTextPane outputPane;
    private final JLabel statusLabel;
    private Supplier<Rule> ruleSupplier;

    RuleTestPanel(MontoyaApi api) {
        super(new BorderLayout(8, 8));
        inputPane = new JTextPane();
        outputPane = new JTextPane();
        statusLabel = new JLabel(" ");
        statusLabel.setHorizontalAlignment(SwingConstants.CENTER);

        // Match Burp editor font for consistency.
        Font font = api.userInterface().currentEditorFont();
        if (font == null) {
            font = new Font("Monospaced", Font.PLAIN, 12);
        }
        inputPane.setFont(font);
        outputPane.setFont(font);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            new JScrollPane(inputPane), new JScrollPane(outputPane));
        split.setResizeWeight(0.5);

        JPanel header = new JPanel(new BorderLayout());
        header.add(new JLabel("Sample Input"), BorderLayout.WEST);
        header.add(new JLabel("Output"), BorderLayout.EAST);

        JButton testButton = new JButton("Test Selected Rule");
        testButton.addActionListener(event -> runTest());

        JPanel controls = new JPanel(new BorderLayout());
        JPanel buttonRow = new JPanel();
        buttonRow.add(testButton);
        controls.add(buttonRow, BorderLayout.CENTER);
        controls.add(statusLabel, BorderLayout.SOUTH);

        setBorder(BorderFactory.createTitledBorder("Rule Test"));
        add(header, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(controls, BorderLayout.SOUTH);

        api.userInterface().applyThemeToComponent(this);
    }

    void setRuleSupplier(Supplier<Rule> ruleSupplier) {
        this.ruleSupplier = ruleSupplier;
    }

    private void runTest() {
        Rule rule = ruleSupplier == null ? null : ruleSupplier.get();
        if (rule == null) {
            statusLabel.setText("Select a rule to test.");
            return;
        }
        String input = inputPane.getText();
        // Rule test engine returns both updated text and highlight spans.
        RuleTestResult result = RuleTestEngine.test(rule, input);
        statusLabel.setText(result.message());
        applyHighlights(inputPane, result.inputText(), result.inputHighlights());
        applyHighlights(outputPane, result.outputText(), result.outputHighlights());
    }

    private void applyHighlights(JTextPane pane, String text, List<HighlightSegment> highlights) {
        StyledDocument doc = pane.getStyledDocument();
        SwingUtilities.invokeLater(() -> {
            try {
                doc.remove(0, doc.getLength());
                doc.insertString(0, text, null);
                for (HighlightSegment segment : highlights) {
                    if (segment.length() == 0) {
                        continue;
                    }
                    AttributeSet attrs = coloredBackground(segment.color());
                    doc.setCharacterAttributes(segment.start(), segment.length(), attrs, false);
                }
            } catch (Exception ex) {
                // ignore rendering errors
            }
        });
    }

    private AttributeSet coloredBackground(Color color) {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setBackground(attrs, color);
        return attrs;
    }

    static final class HighlightSegment {
        private final int start;
        private final int end;
        private final Color color;

        HighlightSegment(int start, int end, Color color) {
            this.start = start;
            this.end = end;
            this.color = color;
        }

        int start() {
            return start;
        }

        int length() {
            return Math.max(0, end - start);
        }

        Color color() {
            return color;
        }
    }

    static final class RuleTestResult {
        private final String inputText;
        private final String outputText;
        private final List<HighlightSegment> inputHighlights;
        private final List<HighlightSegment> outputHighlights;
        private final String message;

        RuleTestResult(String inputText, String outputText, List<HighlightSegment> inputHighlights,
                       List<HighlightSegment> outputHighlights, String message) {
            this.inputText = inputText;
            this.outputText = outputText;
            this.inputHighlights = inputHighlights;
            this.outputHighlights = outputHighlights;
            this.message = message;
        }

        String inputText() {
            return inputText;
        }

        String outputText() {
            return outputText;
        }

        List<HighlightSegment> inputHighlights() {
            return inputHighlights;
        }

        List<HighlightSegment> outputHighlights() {
            return outputHighlights;
        }

        String message() {
            return message;
        }
    }

    static final class RuleTestEngine {
        private static final Color MATCH_COLOR = new Color(255, 249, 196);
        private static final Color REPLACE_COLOR = new Color(200, 255, 200);
        private static final Color[] GROUP_COLORS = {
            new Color(255, 205, 210),
            new Color(187, 222, 251),
            new Color(200, 230, 201),
            new Color(255, 224, 178),
            new Color(225, 190, 231),
            new Color(178, 235, 242)
        };

        static RuleTestResult test(Rule rule, String input) {
            String safeInput = input == null ? "" : input;
            if (rule.getMatch().isEmpty()) {
                return new RuleTestResult(safeInput, safeInput, new ArrayList<>(), new ArrayList<>(),
                    "Match is empty; no changes made.");
            }
            if (rule.getMatchType() == Rule.MatchType.SIMPLE) {
                return testSimple(rule, safeInput);
            }
            return testRegex(rule, safeInput);
        }

        private static RuleTestResult testSimple(Rule rule, String input) {
            List<HighlightSegment> inputHighlights = new ArrayList<>();
            List<HighlightSegment> outputHighlights = new ArrayList<>();
            String match = rule.getMatch();
            String replace = rule.getReplace();

            if (rule.hasWildcards()) {
                // Simple wildcard rules are executed with a compiled regex for spans.
                java.util.regex.Pattern pattern;
                try {
                    pattern = rule.compileSimplePattern();
                } catch (Exception ex) {
                    return new RuleTestResult(input, input, inputHighlights, outputHighlights, "Invalid wildcard pattern.");
                }
                java.util.regex.Matcher matcher = pattern.matcher(input);
                StringBuilder output = new StringBuilder();
                int last = 0;
                int outPos = 0;
                int matchCount = 0;
                while (matcher.find()) {
                    matchCount++;
                    int matchStart = matcher.start();
                    int matchEnd = matcher.end();
                    inputHighlights.add(new HighlightSegment(matchStart, matchEnd, MATCH_COLOR));
                    output.append(input, last, matchStart);
                    outPos += matchStart - last;
                    int repStart = outPos;
                    output.append(replace);
                    outPos += replace.length();
                    if (!replace.isEmpty()) {
                        outputHighlights.add(new HighlightSegment(repStart, repStart + replace.length(), REPLACE_COLOR));
                    }
                    last = matchEnd;
                }
                output.append(input.substring(last));
                String message = matchCount == 0 ? "No matches found." : "Applied " + matchCount + " match(es).";
                return new RuleTestResult(input, output.toString(), inputHighlights, outputHighlights, message);
            }

            StringBuilder output = new StringBuilder();
            int last = 0;
            int outPos = 0;
            int index = input.indexOf(match, 0);
            while (index >= 0) {
                inputHighlights.add(new HighlightSegment(index, index + match.length(), MATCH_COLOR));
                output.append(input, last, index);
                outPos += index - last;
                int repStart = outPos;
                output.append(replace);
                outPos += replace.length();
                if (!replace.isEmpty()) {
                    outputHighlights.add(new HighlightSegment(repStart, repStart + replace.length(), REPLACE_COLOR));
                }
                last = index + match.length();
                index = input.indexOf(match, last);
            }
            output.append(input.substring(last));

            String message = inputHighlights.isEmpty() ? "No matches found." : "Applied " + inputHighlights.size() + " match(es).";
            return new RuleTestResult(input, output.toString(), inputHighlights, outputHighlights, message);
        }

        private static RuleTestResult testRegex(Rule rule, String input) {
            List<HighlightSegment> inputHighlights = new ArrayList<>();
            List<HighlightSegment> outputHighlights = new ArrayList<>();
            if (!rule.hasValidPattern()) {
                return new RuleTestResult(input, input, inputHighlights, outputHighlights, "Invalid regex pattern.");
            }
            // Regex tests reuse the same flags as runtime application.
            java.util.regex.Pattern pattern = rule.compileRegexPattern();
            java.util.regex.Matcher matcher = pattern.matcher(input);
            StringBuilder output = new StringBuilder();

            int last = 0;
            int outPos = 0;
            int matchCount = 0;
            while (matcher.find()) {
                matchCount++;
                int matchStart = matcher.start();
                int matchEnd = matcher.end();
                inputHighlights.add(new HighlightSegment(matchStart, matchEnd, MATCH_COLOR));
                int groupCount = matcher.groupCount();
                for (int i = 1; i <= groupCount; i++) {
                    int gStart = matcher.start(i);
                    int gEnd = matcher.end(i);
                    if (gStart >= 0 && gEnd >= 0 && gEnd > gStart) {
                        inputHighlights.add(new HighlightSegment(gStart, gEnd, groupColor(i)));
                    }
                }

                output.append(input, last, matchStart);
                outPos += matchStart - last;

                ReplacementResult replacement = ReplacementParser.expand(matcher, rule.getReplace(), outPos);
                if (!replacement.text.isEmpty()) {
                    outputHighlights.add(new HighlightSegment(outPos, outPos + replacement.text.length(), REPLACE_COLOR));
                }
                for (GroupSegment segment : replacement.groupSegments) {
                    outputHighlights.add(new HighlightSegment(segment.start, segment.end, groupColor(segment.groupIndex)));
                }
                output.append(replacement.text);
                outPos += replacement.text.length();
                last = matchEnd;
            }
            output.append(input.substring(last));

            String message = matchCount == 0 ? "No matches found." : "Applied " + matchCount + " match(es).";
            return new RuleTestResult(input, output.toString(), inputHighlights, outputHighlights, message);
        }

        private static Color groupColor(int groupIndex) {
            int idx = (groupIndex - 1) % GROUP_COLORS.length;
            return GROUP_COLORS[idx];
        }
    }

    static final class GroupSegment {
        private final int groupIndex;
        private final int start;
        private final int end;

        GroupSegment(int groupIndex, int start, int end) {
            this.groupIndex = groupIndex;
            this.start = start;
            this.end = end;
        }
    }

    static final class ReplacementResult {
        private final String text;
        private final List<GroupSegment> groupSegments;

        ReplacementResult(String text, List<GroupSegment> groupSegments) {
            this.text = text;
            this.groupSegments = groupSegments;
        }
    }

    static final class ReplacementParser {
        static ReplacementResult expand(java.util.regex.Matcher matcher, String replacement, int outputOffset) {
            String safeReplacement = replacement == null ? "" : replacement;
            StringBuilder out = new StringBuilder();
            List<GroupSegment> segments = new ArrayList<>();
            int i = 0;
            int groupCount = matcher.groupCount();
            while (i < safeReplacement.length()) {
                char c = safeReplacement.charAt(i);
                if (c == '\\' && i + 1 < safeReplacement.length()) {
                    out.append(safeReplacement.charAt(i + 1));
                    i += 2;
                    continue;
                }
                if (c == '$') {
                    if (i + 1 < safeReplacement.length() && safeReplacement.charAt(i + 1) == '$') {
                        out.append('$');
                        i += 2;
                        continue;
                    }
                    int j = i + 1;
                    while (j < safeReplacement.length() && Character.isDigit(safeReplacement.charAt(j))) {
                        j++;
                    }
                    if (j > i + 1) {
                        String digits = safeReplacement.substring(i + 1, j);
                        int groupIndex = Integer.parseInt(digits);
                        if (groupIndex >= 1 && groupIndex <= groupCount) {
                            String groupValue = matcher.group(groupIndex);
                            if (groupValue != null) {
                                int start = out.length();
                                out.append(groupValue);
                                int end = out.length();
                                segments.add(new GroupSegment(groupIndex, outputOffset + start, outputOffset + end));
                            }
                        } else {
                            out.append('$').append(digits);
                        }
                        i = j;
                        continue;
                    }
                }
                out.append(c);
                i++;
            }
            return new ReplacementResult(out.toString(), segments);
        }
    }
}

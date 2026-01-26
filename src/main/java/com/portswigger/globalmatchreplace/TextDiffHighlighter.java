package com.portswigger.globalmatchreplace;

import java.awt.Color;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class TextDiffHighlighter {
    static final Color DELETE_COLOR = new Color(255, 205, 210);
    static final Color INSERT_COLOR = new Color(200, 255, 200);

    static DiffResult diff(String original, String modified) {
        String a = original == null ? "" : original;
        String b = modified == null ? "" : modified;
        if (a.equals(b)) {
            return new DiffResult(List.of(), List.of());
        }
        // Line-based diff keeps highlights stable and fast for large HTTP messages.
        return diffByLines(a, b);
    }

    private static DiffResult diffByLines(String original, String modified) {
        String[] aTokens = splitLines(original);
        String[] bTokens = splitLines(modified);

        // Myers diff on tokenized lines.
        List<Edit> edits = myersDiff(aTokens, bTokens);
        return buildHighlights(edits, aTokens, bTokens);
    }

    private static String[] splitLines(String input) {
        if (input.isEmpty()) {
            return new String[0];
        }
        List<String> tokens = new ArrayList<>();
        int start = 0;
        int len = input.length();
        for (int i = 0; i < len; i++) {
            if (input.charAt(i) == '\n') {
                tokens.add(input.substring(start, i + 1));
                start = i + 1;
            }
        }
        if (start < len) {
            tokens.add(input.substring(start));
        }
        return tokens.toArray(new String[0]);
    }

    private static DiffResult buildHighlights(List<Edit> edits, String[] aTokens, String[] bTokens) {
        List<Highlight> originalHighlights = new ArrayList<>();
        List<Highlight> modifiedHighlights = new ArrayList<>();

        int aIndex = 0;
        int bIndex = 0;
        int aOffset = 0;
        int bOffset = 0;

        for (Edit edit : edits) {
            switch (edit.type) {
                case EQUAL -> {
                    for (int i = 0; i < edit.length; i++) {
                        aOffset += aTokens[aIndex++].length();
                        bOffset += bTokens[bIndex++].length();
                    }
                }
                case DELETE -> {
                    int start = aOffset;
                    for (int i = 0; i < edit.length; i++) {
                        aOffset += aTokens[aIndex++].length();
                    }
                    originalHighlights.add(new Highlight(start, aOffset, DELETE_COLOR));
                }
                case INSERT -> {
                    int start = bOffset;
                    for (int i = 0; i < edit.length; i++) {
                        bOffset += bTokens[bIndex++].length();
                    }
                    modifiedHighlights.add(new Highlight(start, bOffset, INSERT_COLOR));
                }
            }
        }
        return new DiffResult(originalHighlights, modifiedHighlights);
    }

    private static List<Edit> myersDiff(String[] a, String[] b) {
        int n = a.length;
        int m = b.length;
        int max = n + m;
        int size = 2 * max + 1;
        int[] v = new int[size];
        List<int[]> trace = new ArrayList<>();

        // Standard Myers diff (O((N+M)D)) for minimal edit script.
        for (int d = 0; d <= max; d++) {
            trace.add(v.clone());
            for (int k = -d; k <= d; k += 2) {
                int idx = k + max;
                int x;
                if (k == -d || (k != d && v[idx - 1] < v[idx + 1])) {
                    x = v[idx + 1];
                } else {
                    x = v[idx - 1] + 1;
                }
                int y = x - k;
                while (x < n && y < m && a[x].equals(b[y])) {
                    x++;
                    y++;
                }
                v[idx] = x;
                if (x >= n && y >= m) {
                    return backtrack(trace, a, b, max);
                }
            }
        }
        return Collections.emptyList();
    }

    private static List<Edit> backtrack(List<int[]> trace, String[] a, String[] b, int max) {
        int x = a.length;
        int y = b.length;
        List<Edit> edits = new ArrayList<>();

        for (int d = trace.size() - 1; d >= 0; d--) {
            int[] v = trace.get(d);
            int k = x - y;
            int idx = k + max;
            int prevK;
            if (k == -d || (k != d && v[idx - 1] < v[idx + 1])) {
                prevK = k + 1;
            } else {
                prevK = k - 1;
            }
            int prevX = v[prevK + max];
            int prevY = prevX - prevK;

            while (x > prevX && y > prevY) {
                edits.add(new Edit(EditType.EQUAL, 1));
                x--;
                y--;
            }

            if (d == 0) {
                break;
            }

            if (x == prevX) {
                edits.add(new Edit(EditType.INSERT, 1));
                y--;
            } else {
                edits.add(new Edit(EditType.DELETE, 1));
                x--;
            }
        }

        Collections.reverse(edits);
        return coalesce(edits);
    }

    private static List<Edit> coalesce(List<Edit> edits) {
        if (edits.isEmpty()) {
            return edits;
        }
        List<Edit> merged = new ArrayList<>();
        Edit current = edits.get(0);
        for (int i = 1; i < edits.size(); i++) {
            Edit next = edits.get(i);
            if (next.type == current.type) {
                current = new Edit(current.type, current.length + next.length);
            } else {
                merged.add(current);
                current = next;
            }
        }
        merged.add(current);
        return merged;
    }

    record DiffResult(List<Highlight> originalHighlights, List<Highlight> modifiedHighlights) {}

    record Highlight(int start, int end, Color color) {}

    private enum EditType { EQUAL, INSERT, DELETE }

    private record Edit(EditType type, int length) {}
}

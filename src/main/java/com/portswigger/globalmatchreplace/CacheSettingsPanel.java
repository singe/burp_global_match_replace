package com.portswigger.globalmatchreplace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.settings.SettingsPanel;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.Collections;
import java.util.Set;

final class CacheSettingsPanel implements SettingsPanel {
    private final JPanel panel;
    private final JTextField cacheSizeField;
    private final ChangeStore changeStore;
    private final MontoyaApi api;

    CacheSettingsPanel(MontoyaApi api, ChangeStore changeStore) {
        this.api = api;
        this.changeStore = changeStore;
        this.panel = new JPanel(new BorderLayout(8, 8));
        this.cacheSizeField = new JTextField(6);

        // Settings panel is intentionally minimal: only cache size is configurable.
        buildUi(api);
    }

    private void buildUi(MontoyaApi api) {
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row.add(new JLabel("GMR diff cache cap (MB):"));
        cacheSizeField.setText(Integer.toString(changeStore.maxBytesMb()));
        row.add(cacheSizeField);

        JButton save = new JButton("Save");
        save.addActionListener(event -> saveSettings());
        row.add(save);

        // Settings UI lives under Burp's extension settings, not the suite tab.
        panel.add(row, BorderLayout.NORTH);
        api.userInterface().applyThemeToComponent(panel);
    }

    private void saveSettings() {
        String text = cacheSizeField.getText().trim();
        try {
            int mb = Integer.parseInt(text);
            if (mb <= 0) {
                throw new NumberFormatException();
            }
            // Persists the size cap and evicts entries if the cache is too large.
            changeStore.setMaxBytesMb(mb);
            api.logging().logToOutput("[GMR] Updated cache cap to " + mb + " MB.");
        } catch (NumberFormatException ex) {
            api.logging().logToOutput("[GMR] Enter a positive integer for MB.");
        }
    }

    @Override
    public JPanel uiComponent() {
        return panel;
    }

    @Override
    public Set<String> keywords() {
        return Collections.unmodifiableSet(Set.of("match", "replace", "diff", "cache"));
    }
}

package com.portswigger.globalmatchreplace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

import javax.swing.JComponent;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.util.ArrayList;
import java.util.List;

final class SuiteTabController {
    private static final String TITLE_BASE = "Global Match & Replace";

    private final MontoyaApi api;
    private final JComponent component;
    private Registration registration;
    private boolean lastEnabled;

    SuiteTabController(MontoyaApi api, JComponent component) {
        this.api = api;
        this.component = component;
    }

    void register(boolean enabled) {
        this.lastEnabled = enabled;
        SwingUtilities.invokeLater(() -> {
            if (registration != null) {
                return;
            }
            // Register once and store the handle for later re-registers.
            registration = api.userInterface().registerSuiteTab(titleFor(enabled), component);
            api.logging().logToOutput("[GMR] suite tab registered");
        });
    }

    void refresh(boolean enabled) {
        if (registration == null) {
            register(enabled);
            return;
        }
        if (enabled == lastEnabled) {
            return;
        }
        lastEnabled = enabled;
        SwingUtilities.invokeLater(() -> {
            // Re-registering updates the title; snapshot/restore prevents Burp switching tabs.
            List<TabSelection> selections = snapshotSelections();
            registration.deregister();
            registration = api.userInterface().registerSuiteTab(titleFor(enabled), component);
            restoreSelections(selections);
        });
    }

    private String titleFor(boolean enabled) {
        // Make state visible in the tab title.
        return enabled ? TITLE_BASE + " (ON)" : TITLE_BASE + " (OFF)";
    }

    private List<TabSelection> snapshotSelections() {
        List<TabSelection> selections = new ArrayList<>();
        Component frame = api.userInterface().swingUtils().suiteFrame();
        if (frame instanceof Container container) {
            List<JTabbedPane> panes = new ArrayList<>();
            findTabbedPanes(container, panes);
            // Capture selected indexes to avoid Burp switching tabs on re-register.
            for (JTabbedPane pane : panes) {
                selections.add(new TabSelection(pane, pane.getSelectedIndex()));
            }
        }
        return selections;
    }

    private void restoreSelections(List<TabSelection> selections) {
        for (TabSelection selection : selections) {
            if (!selection.pane.isDisplayable()) {
                continue;
            }
            if (selection.index >= 0 && selection.index < selection.pane.getTabCount()) {
                selection.pane.setSelectedIndex(selection.index);
            }
        }
    }

    private void findTabbedPanes(Container container, List<JTabbedPane> panes) {
        for (Component child : container.getComponents()) {
            if (child instanceof JTabbedPane tabbedPane) {
                panes.add(tabbedPane);
            }
            if (child instanceof Container childContainer) {
                findTabbedPanes(childContainer, panes);
            }
        }
    }

    private record TabSelection(JTabbedPane pane, int index) {}
}

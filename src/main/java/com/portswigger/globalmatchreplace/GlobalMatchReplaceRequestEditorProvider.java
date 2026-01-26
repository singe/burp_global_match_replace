package com.portswigger.globalmatchreplace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;

import java.awt.Component;
import java.util.Optional;

final class GlobalMatchReplaceRequestEditorProvider implements HttpRequestEditorProvider {
    private final MontoyaApi api;
    private final ChangeStore changeStore;
    private final RuleStore ruleStore;

    GlobalMatchReplaceRequestEditorProvider(MontoyaApi api, ChangeStore changeStore, RuleStore ruleStore) {
        this.api = api;
        this.changeStore = changeStore;
        this.ruleStore = ruleStore;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new DiffRequestEditor(api, changeStore, ruleStore, creationContext.toolSource().toolType());
    }

    private static final class DiffRequestEditor implements ExtensionProvidedHttpRequestEditor {
        private final ChangeStore changeStore;
        private final DiffViewerPanel panel;
        private final RuleStore ruleStore;
        private final ToolType toolType;
        private HttpRequestResponse current;

        DiffRequestEditor(MontoyaApi api, ChangeStore changeStore, RuleStore ruleStore, ToolType toolType) {
            this.changeStore = changeStore;
            this.panel = new DiffViewerPanel(api, "Original Request", "Modified Request");
            this.ruleStore = ruleStore;
            this.toolType = toolType;
        }

        @Override
        public HttpRequest getRequest() {
            return current == null ? null : current.request();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.current = requestResponse;
            if (requestResponse == null) {
                panel.setContents("", "", java.util.List.of());
                return;
            }
            String modified = requestResponse.request().toString();
            Optional<ChangeStore.ChangeRecord> record = changeStore.requestChangeFor(modified);
            if (record.isPresent()) {
                ChangeStore.ChangeRecord change = record.get();
                String viewModified = modified;
                // If Burp shows the original request, swap in stored modified to keep historical diffs stable.
                if (viewModified.equals(change.original()) && !change.modified().isEmpty()) {
                    viewModified = change.modified();
                }
                panel.setContents(change.original(), viewModified, change.summaries());
                return;
            }
            // No stored diff record: show plain content and keep the tab disabled.
            panel.setContents(modified, modified, java.util.List.of());
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            if (requestResponse == null) {
                return false;
            }
            String request = requestResponse.request().toString();
            return changeStore.requestChangeFor(request).isPresent();
        }

        @Override
        public String caption() {
            return "GMR Diff";
        }

        @Override
        public Component uiComponent() {
            return panel.uiComponent();
        }

        @Override
        public Selection selectedData() {
            int start = panel.modifiedPane().getSelectionStart();
            int end = panel.modifiedPane().getSelectionEnd();
            if (start >= 0 && end > start) {
                String selected = panel.modifiedPane().getSelectedText();
                if (selected != null && !selected.isEmpty()) {
                    return Selection.selection(ByteArray.byteArray(selected));
                }
            }
            return Selection.selection(ByteArray.byteArray(""), 0, 0);
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }
}

package com.portswigger.globalmatchreplace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;

import java.awt.Component;
import java.util.Optional;

final class GlobalMatchReplaceResponseEditorProvider implements HttpResponseEditorProvider {
    private final MontoyaApi api;
    private final ChangeStore changeStore;

    GlobalMatchReplaceResponseEditorProvider(MontoyaApi api, ChangeStore changeStore) {
        this.api = api;
        this.changeStore = changeStore;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new DiffResponseEditor(api, changeStore);
    }

    private static final class DiffResponseEditor implements ExtensionProvidedHttpResponseEditor {
        private final ChangeStore changeStore;
        private final DiffViewerPanel panel;
        private HttpRequestResponse current;

        DiffResponseEditor(MontoyaApi api, ChangeStore changeStore) {
            this.changeStore = changeStore;
            this.panel = new DiffViewerPanel(api, "Original Response", "Modified Response");
        }

        @Override
        public HttpResponse getResponse() {
            return current == null ? null : current.response();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.current = requestResponse;
            if (requestResponse == null || !requestResponse.hasResponse()) {
                panel.setContents("", "", java.util.List.of());
                return;
            }
            String modified = requestResponse.response().toString();
            Optional<ChangeStore.ChangeRecord> record = changeStore.responseChangeFor(modified);
            if (record.isPresent()) {
                ChangeStore.ChangeRecord change = record.get();
                panel.setContents(change.original(), modified, change.summaries());
                return;
            }
            // No stored diff record: show plain content and keep the tab disabled.
            panel.setContents(modified, modified, java.util.List.of());
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            if (requestResponse == null || !requestResponse.hasResponse()) {
                return false;
            }
            return changeStore.responseChangeFor(requestResponse.response().toString()).isPresent();
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

package com.portswigger.globalmatchreplace;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;

import java.util.List;

final class GlobalMatchReplaceHttpHandler implements HttpHandler {
    private final RuleStore ruleStore;
    private final ChangeStore changeStore;

    GlobalMatchReplaceHttpHandler(RuleStore ruleStore, ChangeStore changeStore) {
        this.ruleStore = ruleStore;
        this.changeStore = changeStore;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        String original = requestToBeSent.toString();
        // Apply rules in order and track summaries for later diff display.
        RuleApplyResult result = RuleApplier.apply(original, true, requestToBeSent.toolSource().toolType(), ruleStore.snapshot());
        String updated = result.updated();
        if (updated.equals(original)) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        // Store original+modified for GMR diff tabs.
        changeStore.storeRequest(original, updated, result.appliedSummaries());
        HttpRequest modified = HttpRequest.httpRequest(requestToBeSent.httpService(), updated);
        // Use a yellow highlight and note to make modifications visible in Burp.
        return RequestToBeSentAction.continueWith(modified, modifiedAnnotations("Global Match & Replace"));
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        String original = responseReceived.toString();
        // Apply rules in order and track summaries for later diff display.
        RuleApplyResult result = RuleApplier.apply(original, false, responseReceived.toolSource().toolType(), ruleStore.snapshot());
        String updated = result.updated();
        if (updated.equals(original)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        // Store original+modified for GMR diff tabs.
        changeStore.storeResponse(original, updated, result.appliedSummaries());
        HttpResponse modified = HttpResponse.httpResponse(updated);
        // Use a yellow highlight and note to make modifications visible in Burp.
        return ResponseReceivedAction.continueWith(modified, modifiedAnnotations("Global Match & Replace"));
    }

    private Annotations modifiedAnnotations(String note) {
        return Annotations.annotations(note, HighlightColor.YELLOW);
    }

}

package com.portswigger.globalmatchreplace;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class GlobalMatchReplaceExtension implements BurpExtension {
    private static volatile boolean settingsRegistered = false;
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Global Match & Replace");

        RuleStore ruleStore = new RuleStore();
        RulePersistence persistence = new RulePersistence(api);
        java.util.List<Rule> loadedRules = persistence.load();
        if (loadedRules.isEmpty()) {
            // Populate with sample rules on first run.
            ruleStore.setAll(RuleSamples.defaultRules());
            persistence.save(ruleStore.snapshot());
        } else {
            ruleStore.setAll(loadedRules);
        }

        ChangeStore changeStore = new ChangeStore(api, 100);
        // Global HTTP handler performs rule application across tools.
        api.http().registerHttpHandler(new GlobalMatchReplaceHttpHandler(ruleStore, changeStore));

        if (!settingsRegistered) {
            try {
                api.userInterface().registerSettingsPanel(new CacheSettingsPanel(api, changeStore));
                settingsRegistered = true;
            } catch (IllegalStateException ex) {
                api.logging().logToError("[GMR] Settings panel already registered: " + ex.getMessage());
                settingsRegistered = true;
            }
        } else {
            api.logging().logToOutput("[GMR] Settings panel registration skipped (already registered).");
        }

        RulesPanel suiteTabPanel = new RulesPanel(api, ruleStore);
        SuiteTabController suiteTabController = new SuiteTabController(api, suiteTabPanel.uiComponent());
        suiteTabController.register(ruleStore.hasEnabledRules());

        api.userInterface().registerHttpRequestEditorProvider(new GlobalMatchReplaceRequestEditorProvider(api, changeStore, ruleStore));
        api.userInterface().registerHttpResponseEditorProvider(new GlobalMatchReplaceResponseEditorProvider(api, changeStore));

        ruleStore.addListener(() -> {
            // Persist rules and update suite tab title whenever rules change.
            persistence.save(ruleStore.snapshot());
            suiteTabController.refresh(ruleStore.hasEnabledRules());
        });
    }
}

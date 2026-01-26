package com.portswigger.globalmatchreplace;

import java.util.ArrayList;
import java.util.List;

final class RuleStore {
    private final List<Rule> rules = new ArrayList<>();
    private final List<Runnable> listeners = new ArrayList<>();

    synchronized List<Rule> snapshot() {
        // Return copies to avoid external mutation of internal state.
        List<Rule> copy = new ArrayList<>(rules.size());
        for (Rule rule : rules) {
            copy.add(rule.copy());
        }
        return copy;
    }

    synchronized Rule get(int index) {
        return rules.get(index).copy();
    }

    synchronized int size() {
        return rules.size();
    }

    void add(Rule rule) {
        synchronized (this) {
            rules.add(rule.copy());
        }
        // Notify outside the synchronized block to avoid re-entrancy.
        notifyListeners();
    }

    void update(int index, Rule rule) {
        synchronized (this) {
            rules.set(index, rule.copy());
        }
        // Notify outside the synchronized block to avoid re-entrancy.
        notifyListeners();
    }

    void remove(int index) {
        synchronized (this) {
            rules.remove(index);
        }
        // Notify outside the synchronized block to avoid re-entrancy.
        notifyListeners();
    }

    void setAll(List<Rule> newRules) {
        synchronized (this) {
            rules.clear();
            for (Rule rule : newRules) {
                rules.add(rule.copy());
            }
        }
        // Notify outside the synchronized block to avoid re-entrancy.
        notifyListeners();
    }

    synchronized boolean hasEnabledRules() {
        for (Rule rule : rules) {
            if (rule.isEnabled()) {
                return true;
            }
        }
        return false;
    }

    synchronized void addListener(Runnable listener) {
        listeners.add(listener);
    }

    private void notifyListeners() {
        List<Runnable> snapshot;
        synchronized (this) {
            snapshot = List.copyOf(listeners);
        }
        // Iterate a snapshot to avoid concurrent modification during callbacks.
        for (Runnable listener : snapshot) {
            listener.run();
        }
    }
}

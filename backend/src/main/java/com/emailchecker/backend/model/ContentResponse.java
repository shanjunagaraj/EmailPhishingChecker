package com.emailchecker.backend.model;

import java.util.List;

/**
 * ContentResponse represents the JSON sent back after analyzing email
 * content. Field names are chosen to line up with the pattern used on
 * the Email ID Checker (status, riskScore, reasons) plus one new field:
 *
 *   highlightedHtml - the original content, HTML-escaped for safety,
 *   with suspicious words/phrases wrapped in <mark> tags so the frontend
 *   can display it directly (e.g. via element.innerHTML = data.highlightedHtml)
 *   instead of a plain <textarea>, giving the "highlight suspicious words"
 *   feature from your task list.
 */
public class ContentResponse {

    private String status;       // "Safe", "Low Risk", "Suspicious", "High Risk"
    private int riskScore;       // 0-100
    private List<String> reasons;
    private String highlightedHtml;

    public ContentResponse() {
    }

    public ContentResponse(String status, int riskScore, List<String> reasons, String highlightedHtml) {
        this.status = status;
        this.riskScore = riskScore;
        this.reasons = reasons;
        this.highlightedHtml = highlightedHtml;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public List<String> getReasons() {
        return reasons;
    }

    public void setReasons(List<String> reasons) {
        this.reasons = reasons;
    }

    public String getHighlightedHtml() {
        return highlightedHtml;
    }

    public void setHighlightedHtml(String highlightedHtml) {
        this.highlightedHtml = highlightedHtml;
    }
}
package com.emailchecker.backend.model;

import java.util.List;

/**
 * EmailResponse represents the JSON sent back to the frontend.
 *
 * IMPORTANT: the field names here must match what script.js reads:
 *   data.status      -> document.getElementById("status").textContent
 *   data.riskScore   -> document.getElementById("risk").textContent (or "N/A" if -1)
 *   data.reasons     -> looped into <li> elements
 *
 * If you rename a field here, you must also update script.js, or the page
 * will silently show "undefined" instead of throwing an error.
 */
public class EmailResponse {

    private String email;

    // NEW: the part before @ and the part after @, split out separately so
    // the frontend can display them on their own (e.g. "Username: selva1123!"
    // and "Domain: gmail.com") instead of the user having to spot them
    // inside the reason sentences.
    private String username;
    private String domain;

    // "Safe", "Low Risk", "Suspicious", "High Risk", or "Invalid Email"
    private String status;

    // 0-100 normally. -1 specifically means "we couldn't score this because
    // the email format itself was invalid" - script.js checks for -1 and
    // shows "N/A" instead of a percentage.
    private int riskScore;

    private List<String> reasons;

    public EmailResponse() {
    }

    public EmailResponse(String email, String username, String domain, String status,
                          int riskScore, List<String> reasons) {
        this.email = email;
        this.username = username;
        this.domain = domain;
        this.status = status;
        this.riskScore = riskScore;
        this.reasons = reasons;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
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
}
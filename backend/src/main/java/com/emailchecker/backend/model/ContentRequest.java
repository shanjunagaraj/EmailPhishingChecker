package com.emailchecker.backend.model;

/**
 * ContentRequest represents the JSON the frontend sends when the user
 * clicks "Analyze Content" on email-content.html.
 *
 * Example JSON from the browser:
 * { "content": "Dear user, your account has been suspended..." }
 */
public class ContentRequest {

    private String content;

    public ContentRequest() {
    }

    public ContentRequest(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}
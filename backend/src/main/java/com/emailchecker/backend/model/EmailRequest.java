package com.emailchecker.backend.model;

/**
 * EmailRequest represents the JSON data the FRONTEND sends to the backend
 * when the user clicks "Check Email" (see script.js: body: JSON.stringify({ email: email })).
 *
 * Spring Boot automatically converts that JSON into an object of this class
 * ("deserialization").
 */
public class EmailRequest {

    private String email;

    // Spring needs a no-argument constructor to create an empty object
    // before filling it in with the setter below.
    public EmailRequest() {
    }

    public EmailRequest(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
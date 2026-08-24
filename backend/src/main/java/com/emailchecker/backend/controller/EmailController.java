package com.emailchecker.backend.controller;

import com.emailchecker.backend.model.EmailRequest;
import com.emailchecker.backend.model.EmailResponse;
import com.emailchecker.backend.service.EmailService;
import org.springframework.web.bind.annotation.*;

/**
 * EmailController is the "front door" for email-checking requests.
 * It holds NO detection logic itself - it just:
 *   1. Receives the HTTP request from script.js
 *   2. Passes the data to EmailService
 *   3. Returns the service's result as JSON
 */
@RestController // every method here returns data (JSON), not an HTML view
@RequestMapping("/api") // all endpoints in this class start with /api
@CrossOrigin(origins = "*") // allows your HTML/JS frontend to call this API from a different origin/port
public class EmailController {

    private final EmailService emailService;

    // Constructor injection: Spring automatically supplies the EmailService
    // Bean here. You never write "new EmailService()" yourself.
    public EmailController(EmailService emailService) {
        this.emailService = emailService;
    }

    /**
     * Handles: POST http://localhost:8080/api/check-email
     * Request body: { "email": "someone@example.com" }
     * Response body: { "email", "status", "riskScore", "reasons" }
     */
    @PostMapping("/check-email")
    public EmailResponse checkEmail(@RequestBody EmailRequest request) {
        return emailService.checkEmail(request.getEmail());
    }
}
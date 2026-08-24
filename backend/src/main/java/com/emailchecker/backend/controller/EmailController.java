package com.emailchecker.backend.controller;

import com.emailchecker.backend.model.EmailRequest;
import com.emailchecker.backend.model.EmailResponse;
import com.emailchecker.backend.service.EmailService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class EmailController {

    private final EmailService emailService;

    public EmailController(EmailService emailService) {
        this.emailService = emailService;
    }

    @GetMapping("/test")
    public String test() {
        return "Email Phishing Checker Backend is working!";
    }

    @PostMapping("/check-email")
    public EmailResponse checkEmail(@RequestBody EmailRequest request) {
        return emailService.checkEmail(request.getEmail());
    }
}
package com.emailchecker.backend.controller;

import com.emailchecker.backend.model.ContentRequest;
import com.emailchecker.backend.model.ContentResponse;
import com.emailchecker.backend.service.ContentService;
import org.springframework.web.bind.annotation.*;

/**
 * ContentController handles requests from email-content.html.
 * Same shape as EmailController: no logic here, just routing.
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ContentController {

    private final ContentService contentService;

    public ContentController(ContentService contentService) {
        this.contentService = contentService;
    }

    /**
     * Handles: POST http://localhost:8080/api/check-content
     * Request body: { "content": "the pasted email text..." }
     * Response body: { status, riskScore, reasons, highlightedHtml }
     */
    @PostMapping("/check-content")
    public ContentResponse checkContent(@RequestBody ContentRequest request) {
        return contentService.analyzeContent(request.getContent());
    }
}
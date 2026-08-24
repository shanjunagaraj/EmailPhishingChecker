package com.emailchecker.backend.service;

import com.emailchecker.backend.model.ContentResponse;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ContentService analyzes pasted email BODY TEXT (not the sender address -
 * that's EmailService's job) for phishing indicators.
 *
 * Unlike the old plain JavaScript version (flat "10 points per keyword"),
 * this uses several DIFFERENT kinds of signals, each contributing a
 * different weight, which is closer to how real spam/phishing filters work.
 */
@Service
public class ContentService {

    // ---------------------------------------------------------------
    // Reference data: three severity tiers of suspicious phrases.
    // Using a Map<phrase, points> lets each phrase carry its own weight
    // instead of a single flat number for everything.
    // ---------------------------------------------------------------

    // Phrases that almost always indicate a real scam attempt if present -
    // asking directly for money movement or highly sensitive credentials.
    private static final Map<String, Integer> HIGH_SEVERITY_PHRASES = Map.ofEntries(
            Map.entry("wire transfer", 20),
            Map.entry("social security number", 20),
            Map.entry("bank account number", 20),
            Map.entry("credit card number", 20),
            Map.entry("one time password", 18),
            Map.entry("otp", 15),
            Map.entry("cvv", 18),
            Map.entry("routing number", 18),
            Map.entry("account has been suspended", 15),
            Map.entry("verify your identity immediately", 15)
    );

    // Phrases that are common in phishing but also appear in plenty of
    // legitimate emails, so they get a smaller weight on their own.
    private static final Map<String, Integer> MEDIUM_SEVERITY_PHRASES = Map.ofEntries(
            Map.entry("password", 8),
            Map.entry("login", 6),
            Map.entry("verify", 8),
            Map.entry("account", 5),
            Map.entry("bank", 6),
            Map.entry("click here", 10),
            Map.entry("update your information", 10),
            Map.entry("billing information", 8),
            Map.entry("could not be delivered", 8),
            Map.entry("security alert", 10),
            Map.entry("confirm", 6)
    );

    // Mild urgency/marketing-style words - weak signals on their own, but
    // worth a small nudge, especially when several appear together.
    private static final Map<String, Integer> LOW_SEVERITY_PHRASES = Map.ofEntries(
            Map.entry("free", 4),
            Map.entry("gift", 4),
            Map.entry("winner", 5),
            Map.entry("congratulations", 5),
            Map.entry("urgent", 6),
            Map.entry("act now", 6),
            Map.entry("limited time", 5),
            Map.entry("claim now", 6)
    );

    // URL shortener domains - phishing links are frequently hidden behind
    // these so the real destination isn't visible at a glance.
    private static final Set<String> URL_SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"
    );

    // Popular domains attackers imitate via typo-squatting (near-identical
    // spelling, e.g. gmall.com) - same list used by EmailService for the
    // sender address. Duplicated here rather than shared because
    // ContentService and EmailService are independent services; if this
    // list needs to change, remember to update both (a good future
    // refactor would be a shared PhishingReferenceData class).
    private static final List<String> POPULAR_DOMAINS = List.of(
            "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
            "paypal.com", "amazon.com", "microsoft.com", "apple.com", "facebook.com",
            "bankofamerica.com", "netflix.com", "linkedin.com", "google.com"
    );

    // Brand names (without the .com) used to catch "combosquatting" -
    // domains that BURY a real brand name inside extra words, e.g.
    // "amazon-support-verify.tk". This is different from typo-squatting:
    // the brand name is spelled correctly, just wrapped in a domain that
    // isn't actually owned by that company.
    private static final List<String> BRAND_NAMES = List.of(
            "gmail", "yahoo", "outlook", "hotmail", "icloud", "paypal", "amazon",
            "microsoft", "apple", "facebook", "bankofamerica", "netflix", "linkedin", "google"
    );

    // Phrases suggesting the email wants the reader to install/sideload an
    // application - a common malware-delivery technique distinct from
    // credential phishing. Uses a regex (not a plain phrase map entry)
    // because wording varies a lot: "install the app", "install this APK",
    // "download the MVB.app", etc.
    private static final Pattern APP_INSTALL_PATTERN = Pattern.compile(
            "\\b(install|download|sideload)\\b[\\s\\S]{0,25}?\\b(app|apk|application)\\b",
            Pattern.CASE_INSENSITIVE);

    // Matches links, WITH or WITHOUT an http(s):// prefix, e.g. both
    // "http://bit.ly/x" and a bare "bit.ly/order-fix" typed in plain text.
    // Requiring the final segment to be 2-6 LETTERS (not digits) is what
    // keeps this from misfiring on things like "e.g." or "3.5 stars" -
    // those don't look like real domain suffixes.
    private static final Pattern URL_PATTERN = Pattern.compile(
            "\\b(?:https?://)?(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,6}(?:/[\\w./?%&=-]*)?\\b",
            Pattern.CASE_INSENSITIVE);

    // Matches a raw IP address used as a link host, WITH or WITHOUT the
    // http(s):// prefix, e.g. both "http://192.168.1.5/login" and a bare
    // "192.168.1.5/login". Legitimate companies essentially never link to
    // a bare IP address.
    private static final Pattern IP_URL_PATTERN =
            Pattern.compile("(?:https?://)?\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b",
                    Pattern.CASE_INSENSITIVE);

    /**
     * Analyzes the given email body content and returns the full result,
     * including HTML with suspicious phrases highlighted.
     */
    public ContentResponse analyzeContent(String content) {

        if (content == null || content.isBlank()) {
            return new ContentResponse("Invalid Content", -1,
                    List.of("No content was provided."), "");
        }

        List<String> reasons = new ArrayList<>();
        int score = 0;

        // We'll collect every matched phrase here (across all severities)
        // so we can highlight them all in one pass at the end.
        Set<String> matchedPhrases = new LinkedHashSet<>();

        score += scanPhraseMap(content, HIGH_SEVERITY_PHRASES, "high-severity", reasons, matchedPhrases);
        score += scanPhraseMap(content, MEDIUM_SEVERITY_PHRASES, "medium-severity", reasons, matchedPhrases);
        score += scanPhraseMap(content, LOW_SEVERITY_PHRASES, "low-severity", reasons, matchedPhrases);

        score += analyzeUrls(content, reasons, matchedPhrases);
        score += analyzeShouting(content, reasons);
        score += analyzeAppInstallRequest(content, reasons, matchedPhrases);
        score += analyzeBrandAppMismatch(content, reasons, matchedPhrases);
        score += analyzeBrandLinkMismatch(content, reasons, matchedPhrases);

        score = Math.max(0, Math.min(100, score));

        if (reasons.isEmpty()) {
            reasons.add("No suspicious indicators were found in the content.");
        }

        String status = mapScoreToStatus(score);
        String highlightedHtml = buildHighlightedHtml(content, matchedPhrases);

        return new ContentResponse(status, score, reasons, highlightedHtml);
    }

    // ---------------------------------------------------------------
    // Keyword/phrase scanning
    // ---------------------------------------------------------------

    /**
     * Scans the content for every phrase in the given map. For each phrase
     * found, adds its weight to the running score, records a reason, and
     * adds the phrase to matchedPhrases so it can be highlighted later.
     * Returns the total points contributed by this map.
     */
    private int scanPhraseMap(String content, Map<String, Integer> phraseMap, String severityLabel,
                               List<String> reasons, Set<String> matchedPhrases) {
        String lowerContent = content.toLowerCase();
        int points = 0;

        for (Map.Entry<String, Integer> entry : phraseMap.entrySet()) {
            String phrase = entry.getKey();
            int weight = entry.getValue();

            if (lowerContent.contains(phrase)) {
                points += weight;
                matchedPhrases.add(phrase);
                reasons.add("Found " + severityLabel + " phrase: \"" + phrase + "\" (+" + weight + ")");
            }
        }

        return points;
    }

    // ---------------------------------------------------------------
    // URL analysis
    // ---------------------------------------------------------------

    /**
     * Looks at every link in the content (with or without http(s)://) and
     * flags:
     *   - links using a known URL-shortener domain (hides the real destination)
     *   - links pointing straight at a raw IP address instead of a domain name
     *   - links whose domain is a near-identical misspelling of a popular
     *     domain (typo-squatting), e.g. "gmall.com"
     *   - links whose domain buries a real brand name inside extra words
     *     it doesn't legitimately own (combosquatting), e.g.
     *     "amazon-support-verify.tk"
     */
    private int analyzeUrls(String content, List<String> reasons, Set<String> matchedPhrases) {
        int points = 0;
        Matcher matcher = URL_PATTERN.matcher(content);

        String shortenerUrl = null;
        String typosquattedDomain = null;
        String combosquattedDomain = null;
        String typosquattedAs = null;
        String combosquattedBrand = null;

        while (matcher.find()) {
            String url = matcher.group();

            if (shortenerUrl == null) {
                for (String shortener : URL_SHORTENERS) {
                    if (url.toLowerCase().contains(shortener)) {
                        shortenerUrl = url;
                        break;
                    }
                }
            }

            // Pull out just the domain part of this link to check it
            // against our popular-domain and brand-name lists.
            String linkDomain = extractDomain(url);
            if (linkDomain != null) {

                if (typosquattedAs == null) {
                    String result = findTyposquattedDomain(linkDomain);
                    if (result != null) {
                        typosquattedAs = result;
                        typosquattedDomain = linkDomain;
                    }
                }

                if (combosquattedBrand == null) {
                    String result = findCombosquattedBrand(linkDomain);
                    if (result != null) {
                        combosquattedBrand = result;
                        combosquattedDomain = linkDomain;
                    }
                }
            }
        }

        // Checked separately against the raw content (not the URL_PATTERN
        // matches above) because a bare IP like "192.168.1.5" has a final
        // segment of digits, which URL_PATTERN's letters-only TLD rule
        // deliberately excludes to avoid false positives elsewhere.
        Matcher ipMatcher = IP_URL_PATTERN.matcher(content);
        boolean ipUrlFound = ipMatcher.find();
        String ipUrlText = ipUrlFound ? ipMatcher.group() : null;

        if (shortenerUrl != null) {
            points += 15;
            reasons.add("Content contains a shortened URL, which can hide the real destination of a link.");
            matchedPhrases.add(shortenerUrl);
        }
        if (typosquattedAs != null) {
            points += 25;
            reasons.add("Content contains a link whose domain closely resembles \"" + typosquattedAs +
                    "\" - a common phishing trick called typo-squatting.");
            matchedPhrases.add(typosquattedDomain);
        }
        if (combosquattedBrand != null) {
            points += 25;
            reasons.add("Content contains a link whose domain includes the brand name \"" + combosquattedBrand +
                    "\" but is not that company's real domain - a technique called combosquatting, " +
                    "often used to look trustworthy at a glance.");
            matchedPhrases.add(combosquattedDomain);
        }
        if (ipUrlFound) {
            points += 20;
            reasons.add("Content contains a link pointing directly to an IP address instead of a normal domain name, " +
                    "which is highly unusual for legitimate emails.");
            matchedPhrases.add(ipUrlText);
        }

        return points;
    }

    /**
     * Pulls just the domain (host) portion out of a matched link string,
     * stripping any protocol and any path/query after the first slash.
     * e.g. "http://amazon-support-verify.tk/reset" -> "amazon-support-verify.tk"
     */
    private String extractDomain(String url) {
        String noProtocol = url.replaceFirst("(?i)^https?://", "");
        int slashIndex = noProtocol.indexOf('/');
        return slashIndex >= 0 ? noProtocol.substring(0, slashIndex) : noProtocol;
    }

    /**
     * Same typo-squatting check used in EmailService: compares the domain
     * against each popular domain using Levenshtein (edit) distance.
     * A distance of 1-2, but not an exact match, means the spelling is
     * suspiciously close to a well-known domain.
     */
    private String findTyposquattedDomain(String domain) {
        for (String popular : POPULAR_DOMAINS) {
            if (domain.equalsIgnoreCase(popular)) {
                continue; // exact match is not typo-squatting, it just IS that domain
            }
            int distance = calculateLevenshteinDistance(domain.toLowerCase(), popular);
            if (distance > 0 && distance <= 2) {
                return popular;
            }
        }
        return null;
    }

    /**
     * Combosquatting check: does this domain BURY a real brand name inside
     * extra words/hyphens, while NOT actually being that brand's domain?
     * e.g. "amazon-support-verify.tk" contains "amazon" mixed with other
     * words - suspicious.
     *
     * IMPORTANT: this deliberately does NOT flag a domain whose core name
     * simply IS the brand, like "amazon.in" or "www.amazon.in" - those are
     * legitimate regional Amazon domains, not impersonations. The
     * distinction is: does the brand name stand ALONE as the domain's
     * core name, or is it buried inside other words?
     */
    private String findCombosquattedBrand(String domain) {
        String coreName = extractCoreName(domain);

        for (String brand : BRAND_NAMES) {
            if (coreName.equals(brand)) {
                // The core name IS the brand, e.g. "amazon.in" - a
                // legitimate regional domain, not an impersonation.
                return null;
            }
            if (coreName.contains(brand)) {
                // The brand is buried inside extra words/hyphens, e.g.
                // "amazon-support-verify" - suspicious.
                return brand;
            }
        }
        return null;
    }

    /**
     * Extracts the "core name" of a domain - the label right before the
     * TLD, with any leading "www." stripped first. e.g.:
     *   "www.amazon.in" -> "amazon"
     *   "amazon-support-verify.tk" -> "amazon-support-verify"
     * Shared by findCombosquattedBrand and analyzeBrandLinkMismatch so
     * both use the exact same definition of "core name".
     */
    private String extractCoreName(String domain) {
        String lowerDomain = domain.toLowerCase();
        if (lowerDomain.startsWith("www.")) {
            lowerDomain = lowerDomain.substring(4);
        }
        String[] parts = lowerDomain.split("\\.");
        return parts.length >= 2 ? parts[parts.length - 2] : parts[0];
    }

    /**
     * A broader, simpler check than typo-squatting or combosquatting:
     * does the content MENTION a well-known brand by name, while every
     * link in the content points somewhere that has NOTHING to do with
     * that brand at all - not a lookalike, not a combosquat, just a
     * completely unrelated domain (e.g. mentions "Amazon" but the link
     * goes to "bing.com")?
     *
     * This catches a case the other checks miss: a link that isn't
     * disguised in any clever way, it's simply irrelevant to the brand
     * the message claims to be from - which is exactly what happens when
     * a phishing email links to a generic search results page instead of
     * the real company site.
     */
    private int analyzeBrandLinkMismatch(String content, List<String> reasons, Set<String> matchedPhrases) {
        String lowerContent = content.toLowerCase();

        List<String> mentionedBrands = new ArrayList<>();
        for (String brand : BRAND_NAMES) {
            if (lowerContent.contains(brand)) {
                mentionedBrands.add(brand);
            }
        }
        if (mentionedBrands.isEmpty()) {
            return 0; // no brand mentioned, nothing to compare against
        }

        List<String> linkCoreNames = new ArrayList<>();
        Matcher matcher = URL_PATTERN.matcher(content);
        while (matcher.find()) {
            String domain = extractDomain(matcher.group());
            if (domain != null) {
                linkCoreNames.add(extractCoreName(domain));
            }
        }
        if (linkCoreNames.isEmpty()) {
            return 0; // no links to compare against - nothing to flag here
        }

        // Check each mentioned brand: does AT LEAST ONE link relate to it
        // (either IS that brand, or buries that brand's name inside it)?
        for (String brand : mentionedBrands) {
            boolean relatedLinkFound = linkCoreNames.stream()
                    .anyMatch(coreName -> coreName.equals(brand) || coreName.contains(brand));

            if (!relatedLinkFound) {
                reasons.add("Content mentions the brand \"" + brand + "\" but none of the links in this message " +
                        "go to \"" + brand + "\"'s actual domain - a common phishing tactic where a trusted " +
                        "brand name is used to disguise a link to an unrelated site.");
                matchedPhrases.add(brand);
                // Only report once even if multiple brands mismatch, so
                // one message with several brand names doesn't stack this
                // particular check's points repeatedly.
                return 25;
            }
        }
        return 0;
    }

    /**
     * Levenshtein Distance: minimum number of single-character edits
     * (insert/delete/substitute) to turn string a into string b.
     */
    private int calculateLevenshteinDistance(String a, String b) {
        int[][] dp = new int[a.length() + 1][b.length() + 1];

        for (int i = 0; i <= a.length(); i++) dp[i][0] = i;
        for (int j = 0; j <= b.length(); j++) dp[0][j] = j;

        for (int i = 1; i <= a.length(); i++) {
            for (int j = 1; j <= b.length(); j++) {
                if (a.charAt(i - 1) == b.charAt(j - 1)) {
                    dp[i][j] = dp[i - 1][j - 1];
                } else {
                    dp[i][j] = 1 + Math.min(dp[i - 1][j - 1],
                            Math.min(dp[i - 1][j], dp[i][j - 1]));
                }
            }
        }
        return dp[a.length()][b.length()];
    }

    // ---------------------------------------------------------------
    // App install / sideload request detection
    // ---------------------------------------------------------------

    /**
     * Flags content that asks the reader to install, download, or sideload
     * an app - a malware-delivery technique separate from credential
     * phishing. Uses a regex instead of a fixed phrase list because the
     * wording varies a lot ("install the app", "download this APK",
     * "install the MVB.app").
     */
    private int analyzeAppInstallRequest(String content, List<String> reasons, Set<String> matchedPhrases) {
        Matcher matcher = APP_INSTALL_PATTERN.matcher(content);
        if (matcher.find()) {
            reasons.add("Content asks the reader to install or download an application, " +
                    "a technique sometimes used to deliver malware rather than steal a password directly.");
            matchedPhrases.add(matcher.group());
            return 12;
        }
        return 0;
    }

    /**
     * Flags a specific combination: the email mentions a well-known brand
     * by name (e.g. "Amazon"), AND also asks the reader to install/download
     * an app. This pattern is common in fake delivery/account notification
     * scams that borrow a trusted brand's name to convince someone to
     * sideload a malicious app that has nothing to do with that brand.
     *
     * NOTE: this is a heuristic, not proof - a real Amazon marketing email
     * legitimately promoting the real Amazon app would also match this
     * pattern. It contributes a moderate score bump, not an automatic
     * "High Risk" verdict, for exactly that reason.
     */
    private int analyzeBrandAppMismatch(String content, List<String> reasons, Set<String> matchedPhrases) {
        String lowerContent = content.toLowerCase();
        boolean mentionsBrand = false;
        String mentionedBrand = null;

        for (String brand : BRAND_NAMES) {
            if (lowerContent.contains(brand)) {
                mentionsBrand = true;
                mentionedBrand = brand;
                break;
            }
        }

        boolean asksToInstallApp = APP_INSTALL_PATTERN.matcher(content).find();

        if (mentionsBrand && asksToInstallApp) {
            reasons.add("Content mentions the brand \"" + mentionedBrand + "\" while also asking the reader " +
                    "to install an app - a combination often used in fake delivery or account " +
                    "notification scams to get a malicious app installed.");
            matchedPhrases.add(mentionedBrand);
            return 20;
        }
        return 0;
    }

    // ---------------------------------------------------------------
    // "SHOUTING" (excessive capitals) detection
    // ---------------------------------------------------------------

    /**
     * Counts words that are entirely uppercase and at least 4 letters long
     * (e.g. "URGENT", "SUSPENDED") - short all-caps like "USA" or "ATM"
     * are ignored since those are normal.
     */
    private int analyzeShouting(String content, List<String> reasons) {
        String[] words = content.split("\\s+");
        int shoutingWordCount = 0;

        for (String word : words) {
            String cleaned = word.replaceAll("[^A-Za-z]", "");
            if (cleaned.length() >= 4 && cleaned.equals(cleaned.toUpperCase())
                    && !cleaned.equals(cleaned.toLowerCase())) {
                shoutingWordCount++;
            }
        }

        if (shoutingWordCount >= 3) {
            reasons.add("Content contains " + shoutingWordCount +
                    " fully capitalized words, a pressure tactic often used in phishing emails.");
            return 10;
        }
        return 0;
    }

    // ---------------------------------------------------------------
    // Highlighting - safely turns content into HTML with <mark> tags
    // ---------------------------------------------------------------

    /**
     * Builds an HTML-safe version of the content with every matched
     * phrase wrapped in a <mark> tag so the frontend can render it
     * directly and visually highlight the suspicious parts.
     *
     * IMPORTANT SECURITY NOTE: we escape the raw content FIRST (turning
     * "<" into "&lt;" etc.) before doing anything else. If we skipped
     * this step, someone could paste content containing real HTML/script
     * tags, and the frontend would execute it when rendering the response -
     * this is called an XSS (Cross-Site Scripting) vulnerability. Escaping
     * first, then inserting our own <mark> tags afterward, keeps this safe.
     */
    private String buildHighlightedHtml(String content, Set<String> matchedPhrases) {
        String escaped = escapeHtml(content);

        // Highlight longer phrases first so a short phrase contained
        // inside a longer one (e.g. "account" inside "account has been
        // suspended") doesn't break the longer phrase's highlighting.
        List<String> sortedPhrases = new ArrayList<>(matchedPhrases);
        sortedPhrases.sort((a, b) -> b.length() - a.length());

        for (String phrase : sortedPhrases) {
            Pattern pattern = Pattern.compile(Pattern.quote(phrase), Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(escaped);
            escaped = matcher.replaceAll("<mark>$0</mark>");
        }

        return escaped;
    }

    /** Escapes the 5 characters that matter for safe HTML text content. */
    private String escapeHtml(String text) {
        return text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private String mapScoreToStatus(int score) {
        if (score >= 70) return "High Risk";
        if (score >= 40) return "Suspicious";
        if (score >= 15) return "Low Risk";
        return "Safe";
    }
}
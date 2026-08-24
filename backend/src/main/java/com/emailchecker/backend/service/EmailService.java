package com.emailchecker.backend.service;

import com.emailchecker.backend.model.EmailResponse;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

/**
 * EmailService contains ALL the "brain" logic for deciding whether an
 * email address looks suspicious. The Controller does NOT contain any
 * logic itself - it just receives requests and calls this service.
 * Controller -> Service -> (later) Repository/Database.
 *
 * @Service tells Spring: "create ONE instance of this class (a Bean) and
 * manage it for me." Spring hands that Bean to EmailController automatically
 * through constructor injection.
 */
@Service
public class EmailService {

    // ---------------------------------------------------------------
    // Reference data used for our checks. In-memory for now; later these
    // could move into MySQL tables you can edit without touching code.
    // ---------------------------------------------------------------

    // Basic structural validation: name@domain.tld
    // The username part now accepts the wider range of special characters
    // real email systems technically allow (like ! # $ % & etc.) - not
    // because they're common, but because REJECTING them here would mean
    // we never even get a chance to flag them as suspicious below. A
    // strict validator and a suspicious-pattern detector are different
    // jobs: this one just confirms "is this shaped like an email at all".
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    // Free/public email providers. Not proof of phishing alone, but a
    // "business support" email from a free Gmail address is a red flag.
    private static final Set<String> FREE_PROVIDERS = Set.of(
            "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
            "aol.com", "live.com", "mail.com", "protonmail.com"
    );

    // Known disposable / temporary email providers.
    private static final Set<String> DISPOSABLE_PROVIDERS = Set.of(
            "mailinator.com", "tempmail.com", "temp-mail.org", "guerrillamail.com",
            "10minutemail.com", "throwawaymail.com", "yopmail.com", "fakeinbox.com",
            "trashmail.com", "sharklasers.com", "dispostable.com", "getnada.com"
    );

    // Popular domains attackers frequently imitate with small spelling
    // tricks ("typo-squatting"), e.g. gmail.com -> gmall.com.
    private static final List<String> POPULAR_DOMAINS = List.of(
            "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
            "paypal.com", "amazon.com", "microsoft.com", "apple.com", "facebook.com",
            "bankofamerica.com", "netflix.com", "linkedin.com", "google.com"
    );

    // Words commonly seen in phishing/fake account usernames. This is your
    // exact requested list, plus a few extra words kept from the earlier
    // version so nothing that worked before stops working.
    private static final Set<String> PHISHING_KEYWORDS = Set.of(
            "admin", "support", "verify", "secure", "bank", "paypal", "amazon",
            "microsoft", "update", "login", "account", "winner", "free", "gift", "password",
            // kept from the previous version:
            "security", "confirm", "billing", "alert", "suspended", "unlock", "recovery"
    );

    // The exact special-character set from the new scoring rules:
    // ! @ # $ % ^ & * _ - .
    // (Note: "@" can never actually appear INSIDE a username, since it's
    // the separator between username and domain - it's harmless to leave
    // it in this set, it just never matches anything.)
    private static final Set<Character> SPECIAL_CHARS_RULE = Set.of(
            '!', '@', '#', '$', '%', '^', '&', '*', '_', '-', '.'
    );

    /**
     * Analyzes a single email address and returns the full EmailResponse.
     */
    public EmailResponse checkEmail(String email) {

        if (email == null || email.isBlank()) {
            return new EmailResponse(email, null, null, "Invalid Email", -1,
                    List.of("Email address is empty."));
        }

        email = email.trim();

        // --- Format validation ---
        boolean isFormatValid = EMAIL_PATTERN.matcher(email).matches();
        if (!isFormatValid) {
            return new EmailResponse(email, null, null, "Invalid Email", -1,
                    List.of("Email format is invalid (does not match name@domain.com pattern)."));
        }

        // Split into username (before @) and domain (after @).
        String[] parts = email.split("@");
        String username = parts[0].toLowerCase();
        String domain = parts[1].toLowerCase();

        List<String> reasons = new ArrayList<>();
        int score = 0; // additive scoring model: starts safe, adds points per red flag

        // --- CHECK 1: Suspicious username patterns ---
        // Moved to run FIRST (before the domain checks below) so username
        // reasons appear at the top of the list, matching how results are
        // meant to read: "what's wrong with the username" before
        // "what's wrong with the domain".
        score += analyzeUsername(username, reasons);

        // --- CHECK 2: Disposable email provider ---
        if (DISPOSABLE_PROVIDERS.contains(domain)) {
            score += 40;
            reasons.add("Domain \"" + domain + "\" is a known disposable/temporary email provider.");
        }
        // --- CHECK 3: Free email provider (only if not already disposable) ---
        // Point value lowered from 15 to 10 per the updated scoring rules -
        // being on a free provider is a weaker signal than a suspicious
        // username, so it now contributes less to the total.
        else if (FREE_PROVIDERS.contains(domain)) {
            score += 10;
            reasons.add("Domain \"" + domain + "\" is a free public email provider, " +
                    "which is common for phishing but not proof by itself.");
        }

        // --- CHECK 4: Typo-squatting detection ---
        String impersonatedDomain = findTyposquattedDomain(domain);
        if (impersonatedDomain != null) {
            score += 35;
            reasons.add("Domain \"" + domain + "\" closely resembles \"" + impersonatedDomain +
                    "\" - a common phishing trick called typo-squatting.");
        }

        // --- CHECK 5: Domain structure randomness ---
        // Catches auto-generated domains like "wise-bear-hyrcmz.com" that
        // aren't on any blocklist and aren't typo-squats, but structurally
        // look machine-generated rather than a real business chose them.
        int domainStructurePoints = analyzeDomainStructure(domain, reasons);
        score += domainStructurePoints;

        // --- CHECK 6: Small trust bonus for a clean business domain ---
        // Only given if NOTHING else was flagged, including the new
        // structure check - a domain that looks randomly generated should
        // not also get a "looks legitimate" bonus.
        if (!FREE_PROVIDERS.contains(domain)
                && !DISPOSABLE_PROVIDERS.contains(domain)
                && impersonatedDomain == null
                && domainStructurePoints == 0) {
            score -= 10;
            reasons.add("Domain \"" + domain + "\" appears to be a dedicated business/organization domain.");
        }

        // Keep score within 0-100.
        score = Math.max(0, Math.min(100, score));

        if (reasons.isEmpty()) {
            reasons.add("No suspicious indicators were found.");
        }

        String status = mapScoreToStatus(score);

        return new EmailResponse(email, username, domain, status, score, reasons);
    }

    /**
     * Looks at the username (before @) using the NEW, heavier-weighted
     * rule set. Each rule is independent - several can fire on the same
     * username, and their points simply add up. Order here matches the
     * order reasons should appear in the result (suspicious words first,
     * since that's the strongest single signal).
     */
    private int analyzeUsername(String username, List<String> reasons) {
        int points = 0;

        boolean hasDigits = username.chars().anyMatch(Character::isDigit);
        boolean hasSpecialChars = username.chars()
                .anyMatch(c -> SPECIAL_CHARS_RULE.contains((char) c));

        // --- RULE 4: Suspicious/phishing-related word ---
        // Checked first so its reason appears at the top of the list,
        // matching the example outputs where this comes before the
        // numbers/special-character reasons.
        boolean hasSuspiciousWord = PHISHING_KEYWORDS.stream().anyMatch(username::contains);
        if (hasSuspiciousWord) {
            points += 30;
            reasons.add("Username \"" + username + "\" contains suspicious words.");
        }

        // --- RULE 1: Contains numbers ---
        if (hasDigits) {
            points += 15;
            reasons.add("Username \"" + username + "\" contains numbers.");
        }

        // --- RULE 2: Contains special characters ---
        // Limited to exactly this set: ! @ # $ % ^ & * _ - .
        if (hasSpecialChars) {
            points += 25;
            reasons.add("Username \"" + username + "\" contains special characters.");
        }

        // --- RULE 3: Contains BOTH numbers AND special characters ---
        // This is an ADDITIONAL bonus on top of rules 1 and 2 above - all
        // three reasons can appear together for a username like "abc123!".
        if (hasDigits && hasSpecialChars) {
            points += 20;
            reasons.add("Username \"" + username + "\" contains both numbers and special characters.");
        }

        // --- RULE 5: Random-looking character combination ---
        // Same "long consonant cluster" / "low vowel ratio" idea used for
        // detecting random-looking DOMAIN names (see analyzeDomainStructure
        // below) - applied here to the username's letters instead.
        String lettersOnly = username.replaceAll("[^a-zA-Z]", "");
        boolean looksRandom = false;

        if (lettersOnly.length() >= 5) {
            if (hasLongConsonantCluster(lettersOnly, 4)) {
                looksRandom = true;
            } else {
                long vowelCount = lettersOnly.chars()
                        .filter(c -> "aeiou".indexOf(Character.toLowerCase(c)) >= 0)
                        .count();
                double vowelRatio = (double) vowelCount / lettersOnly.length();
                if (vowelRatio < 0.2) {
                    looksRandom = true;
                }
            }
        }

        if (looksRandom) {
            points += 25;
            reasons.add("Username \"" + username + "\" looks like a randomly generated string " +
                    "(e.g. \"x7k2p9qz\") rather than a real name or word.");
        }

        // --- RULE 6: Username length less than 3 ---
        if (username.length() < 3) {
            points += 20;
            reasons.add("Username \"" + username + "\" is very short (less than 3 characters).");
        }

        // --- RULE 7: Username length greater than 20 ---
        if (username.length() > 20) {
            points += 15;
            reasons.add("Username \"" + username + "\" is unusually long (more than 20 characters).");
        }

        // --- RULE 8: Repeated characters ---
        // e.g. "aaaa1111" - the same character repeated many times in a
        // row, common in randomly generated or bot-created logins.
        if (hasRepeatedCharacterRun(username, 4)) {
            points += 15;
            reasons.add("Username \"" + username + "\" uses repeated characters.");
        }

        return points;
    }

    /**
     * Returns true if the given text contains the SAME character repeated
     * `minLength` or more times in a row, e.g. "aaaa" or "1111".
     */
    private boolean hasRepeatedCharacterRun(String text, int minLength) {
        if (text.isEmpty()) return false;

        int currentRun = 1;
        for (int i = 1; i < text.length(); i++) {
            if (text.charAt(i) == text.charAt(i - 1)) {
                currentRun++;
                if (currentRun >= minLength) {
                    return true;
                }
            } else {
                currentRun = 1;
            }
        }
        return false;
    }

    /**
     * Looks at the SLD (Second-Level Domain - the meaningful part of the
     * domain name, e.g. "wise-bear-hyrcmz" from "wise-bear-hyrcmz.com")
     * for structural patterns common in machine-generated domains:
     *   - multiple hyphens joining unrelated word-like chunks
     *   - a long run of consonants with no vowels (a random-looking suffix)
     *   - an overall very low vowel ratio across the whole name
     * Returns the risk points contributed, and adds explanations to reasons.
     */
    private int analyzeDomainStructure(String domain, List<String> reasons) {
        int points = 0;

        // Take the part right before the TLD, e.g. "wise-bear-hyrcmz" from
        // "wise-bear-hyrcmz.com", or "sub.wise-bear-hyrcmz.co.uk" style
        // domains still land on "wise-bear-hyrcmz".
        String[] domainParts = domain.split("\\.");
        String sld = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : domainParts[0];

        // --- Multiple hyphens ---
        // Two or more hyphens (three or more word-like chunks) is unusual
        // for a genuine company domain and common in bulk-registered
        // phishing domains, e.g. "secure-login-verify-account.com".
        long hyphenCount = sld.chars().filter(c -> c == '-').count();
        if (hyphenCount >= 2) {
            points += 15;
            reasons.add("Domain name \"" + sld + "\" is split into several hyphen-separated chunks, " +
                    "a pattern common in auto-generated or bulk-registered domains.");
        }

        // --- Long consonant cluster ---
        // Look for 4+ consonants in a row anywhere in the name, e.g. "hyrcmz".
        // Real words rarely do this; randomly generated suffixes often do.
        if (hasLongConsonantCluster(sld, 4)) {
            points += 15;
            reasons.add("Domain name \"" + sld + "\" contains a long run of consonants with no vowels, " +
                    "which looks like a randomly generated string rather than a real word.");
        }

        // --- Overall low vowel ratio ---
        // Only checked for reasonably long names (short names naturally
        // have noisier ratios, e.g. "nyc.com" would be unfairly penalized).
        String lettersOnly = sld.replace("-", "");
        if (lettersOnly.length() >= 8) {
            long vowelCount = lettersOnly.chars()
                    .filter(c -> "aeiou".indexOf(Character.toLowerCase(c)) >= 0)
                    .count();
            double vowelRatio = (double) vowelCount / lettersOnly.length();
            if (vowelRatio < 0.2) {
                points += 15;
                reasons.add("Domain name \"" + sld + "\" has an unusually low ratio of vowels to consonants, " +
                        "suggesting a randomly generated string.");
            }
        }

        return points;
    }

    /**
     * Returns true if the given text contains `minLength` or more
     * consonant letters in a row (no vowels in between).
     */
    private boolean hasLongConsonantCluster(String text, int minLength) {
        int currentRun = 0;
        for (char c : text.toLowerCase().toCharArray()) {
            boolean isLetter = Character.isLetter(c);
            boolean isVowel = "aeiou".indexOf(c) >= 0;

            if (isLetter && !isVowel) {
                // consonant - extend the current run
                currentRun++;
                if (currentRun >= minLength) {
                    return true;
                }
            } else {
                // vowel, hyphen, or digit - the consonant run breaks here
                currentRun = 0;
            }
        }
        return false;
    }

    /**
     * Checks the domain against popular domains using Levenshtein (edit)
     * distance. Distance 1-2 but not an exact match = likely typo-squatting.
     * Returns the popular domain it resembles, or null.
     */
    private String findTyposquattedDomain(String domain) {
        for (String popular : POPULAR_DOMAINS) {
            if (domain.equals(popular)) {
                continue; // exact match is not typo-squatting, it just IS that domain
            }
            int distance = calculateLevenshteinDistance(domain, popular);
            if (distance > 0 && distance <= 2) {
                return popular;
            }
        }
        return null;
    }

    /**
     * Levenshtein Distance: minimum number of single-character edits
     * (insert/delete/substitute) to turn string a into string b.
     * Classic dynamic-programming table build.
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

    /**
     * Converts the final numeric score into one of the 5 status labels.
     * 0-20 Safe, 21-40 Low Risk, 41-60 Medium Risk, 61-80 High Risk,
     * 81-100 Very High Risk.
     */
    private String mapScoreToStatus(int score) {
        if (score >= 81) return "Very High Risk";
        if (score >= 61) return "High Risk";
        if (score >= 41) return "Medium Risk";
        if (score >= 21) return "Low Risk";
        return "Safe";
    }
}
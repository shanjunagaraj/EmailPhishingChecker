// =========================
// Navigation
// =========================

function goToEmailID() {
    window.location.href = "email-id.html";
}

function goToContent() {
    window.location.href = "email-content.html";
}

// =========================
// Shared helper
// =========================

/**
 * Converts a backend status string like "High Risk" into a CSS class
 * name like "high-risk", so we can style each risk level differently.
 * Example: "Low Risk" -> "low-risk", "Safe" -> "safe".
 */
function statusToClass(status) {
    return status.toLowerCase().replace(/\s+/g, "-");
}

// =========================
// Email ID Checker
// =========================

const checkBtn = document.getElementById("checkBtn");

if (checkBtn) {

    checkBtn.addEventListener("click", async function () {

        const email = document.getElementById("email").value.trim();

        if (email === "") {
            alert("Please enter an email address.");
            return;
        }

        try {

            const response = await fetch("http://localhost:8080/api/check-email", {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    email: email
                })

            });

            if (!response.ok) {
                throw new Error("Server Error : " + response.status);
            }

            const data = await response.json();

            document.getElementById("result").style.display = "block";

            // NEW: show the parsed username and domain separately.
            // For an invalid email, the backend sends these as null since
            // it couldn't safely split the address - we show "-" instead
            // of the literal word "null" in that case.
            document.getElementById("usernamePart").textContent = data.username || "-";
            document.getElementById("domainPart").textContent = data.domain || "-";

            const statusSpan = document.getElementById("status");
            statusSpan.textContent = data.status;
            // className replaces any previous risk-level class before
            // applying the new one, so colors don't stack up between checks.
            statusSpan.className = statusToClass(data.status);

            // Show N/A for invalid email (backend sends riskScore: -1)
            if (data.riskScore === -1) {
                document.getElementById("risk").textContent = "N/A";
            } else {
                document.getElementById("risk").textContent = data.riskScore + "%";
            }

            const reasonList = document.getElementById("reasonList");
            reasonList.innerHTML = "";

            data.reasons.forEach(function (reason) {
let formattedReason = reason
    .replace(/numbers/gi, "<span class='highlight-orange'>numbers</span>")
    .replace(/special characters/gi, "<span class='highlight-red'>special characters</span>")
    .replace(/personal name/gi, "<span class='highlight-blue'>personal name</span>")
    .replace(/gmail\.com/gi, "<span class='highlight-domain'>gmail.com</span>")
    .replace(/High Risk/gi, "<span class='highlight-high'>High Risk</span>")
    .replace(/Medium Risk/gi, "<span class='highlight-medium'>Medium Risk</span>");

reasonList.innerHTML += `<li>${formattedReason}</li>`;            });

        }

        catch (error) {

            console.error(error);
            alert("Cannot connect to Spring Boot backend.");

        }

    });

}


// =========================
// Email Content Checker
// =========================

const analyzeBtn = document.getElementById("analyzeBtn");

if (analyzeBtn) {

    analyzeBtn.addEventListener("click", async function () {

        const content = document.getElementById("emailContent").value.trim();

        if (content === "") {
            alert("Please paste the email content.");
            return;
        }

        const result = document.getElementById("contentResult");
        const statusSpan = document.getElementById("contentStatus");
        const risk = document.getElementById("contentRisk");
        const reasonList = document.getElementById("contentReasonList");
        const highlightedContent = document.getElementById("highlightedContent");

        try {

            const response = await fetch("http://localhost:8080/api/check-content", {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    content: content
                })

            });

            if (!response.ok) {
                throw new Error("Server Error : " + response.status);
            }

            const data = await response.json();

            result.style.display = "block";

            statusSpan.textContent = data.status;
            statusSpan.className = statusToClass(data.status);

            if (data.riskScore === -1) {
                risk.textContent = "N/A";
            } else {
                risk.textContent = data.riskScore + "%";
            }

            reasonList.innerHTML = "";
            data.reasons.forEach(function (reason) {
                reasonList.innerHTML += `<li>${reason}</li>`;
            });

            // The backend already HTML-escaped the content and wrapped
            // suspicious phrases in <mark> tags, so we can render it
            // directly. We trust this because WE control the backend -
            // never do this with HTML received from an untrusted source
            // that hasn't been escaped first.
            highlightedContent.innerHTML = data.highlightedHtml;

        }

        catch (error) {

            console.error(error);
            alert("Cannot connect to Spring Boot backend.");

        }

    });

}
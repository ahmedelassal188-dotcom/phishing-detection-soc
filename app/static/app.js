const form = document.getElementById("upload-form");
const fileInput = document.getElementById("email-file");
const analyzeButton = document.getElementById("analyze-button");
const uploadStatus = document.getElementById("upload-status");
const reportDownload = document.getElementById("report-download");
function setText(id, value) {
    document.getElementById(id).textContent = String(value);
}

function showFindings(reasons) {
    const list = document.getElementById("detection-findings");
    list.replaceChildren();

    if (!reasons.length) {
        const item = document.createElement("li");
        item.textContent = "No suspicious indicators detected.";
        list.appendChild(item);
        return;
    }

    reasons.forEach(reason => {
        const item = document.createElement("li");
        item.textContent = reason;
        list.appendChild(item);
    });
}

function showURLs(urls) {
    const container = document.getElementById("url-results");
    container.replaceChildren();

    if (!urls.length) {
        container.textContent = "No URLs detected.";
        return;
    }

    urls.forEach(result => {
        const entry = document.createElement("p");

        entry.textContent =
            `${result.url} | Risk Score: ${result.risk_score}/100`;

        container.appendChild(entry);
    });
}
function showThreatIntelligence(results) {
    const container = document.getElementById(
        "threat-intelligence-results"
    );

    container.replaceChildren();

    if (!results || results.length === 0) {
        container.textContent = "No URLs to check.";
        return;
    }

    results.forEach(result => {
        const entry = document.createElement("p");

        let status;

        if (result.listed === true) {
            status = "LISTED - Malware URL detected";
        } else if (result.listed === false) {
            status = "NOT LISTED";
        } else {
            status = result.status.toUpperCase();
        }

        entry.textContent =
            `${result.provider} | ${status} | ${result.url}`;

        container.appendChild(entry);
    });
}
function displayResults(data) {
    const rules = data.rule_based;
    const ml = data.machine_learning;

    setText("risk-score", `${rules.risk_score}/100`);
    setText("risk-level", rules.risk_level);

    setText(
        "ml-probability",
        `${(ml.phishing_probability * 100).toFixed(2)}%`
    );

    setText("final-assessment", data.final_assessment);

    setText("email-sender", data.sender);
    setText("email-subject", data.subject);

    showFindings(rules.reasons || []);
    showURLs(rules.url_analysis || []);
    showThreatIntelligence(data.threat_intelligence || []);
    const auth = rules.auth_results || {};

    setText("spf-status", auth.spf || "not_found");
    setText("dkim-status", auth.dkim || "not_found");
    setText("dmarc-status", auth.dmarc || "not_found");

    setText(
        "auth-trust",
        rules.auth_trusted
            ? "Authentication source: Trusted"
            : "Authentication source: Unverified"
    );
}

form.addEventListener("submit", async function(event) {
    event.preventDefault();
reportDownload.hidden = true;
reportDownload.removeAttribute("href");

    const file = fileInput.files[0];

    if (!file) {
        uploadStatus.textContent = "Please select an EML file.";
        return;
    }

    if (!file.name.toLowerCase().endsWith(".eml")) {
        uploadStatus.textContent = "Only EML files are supported.";
        return;
    }

    if (file.size > 5 * 1024 * 1024) {
        uploadStatus.textContent = "File exceeds 5 MB limit.";
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    analyzeButton.disabled = true;
    uploadStatus.textContent = "Analyzing email...";

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                typeof data.detail === "string"
                    ? data.detail
                    : `HTTP Error ${response.status}`
            );
        }

        displayResults(data);
   if (data.report_filename) {
    reportDownload.href =
        `/reports/${encodeURIComponent(data.report_filename)}`;

    reportDownload.download = data.report_filename;
    reportDownload.hidden = false;
}
        uploadStatus.textContent =
            "Email analysis completed successfully.";

    } catch (error) {
        uploadStatus.textContent =
            `Analysis failed: ${error.message}`;

    } finally {
        analyzeButton.disabled = false;
    }
});

// =======================================
// DevGuardAI - Frontend Logic (Final)
// Matches: filename, files_scanned, issues_found
// (each with type, severity, file, line, code,
// ai_explanation, secure_fix), security_recommendations,
// security_score
// =======================================

const API_BASE = "https://devguardai.onrender.com";

// -------- Screens --------
const uploadScreen = document.getElementById("upload-screen");
const loadingScreen = document.getElementById("loading-screen");
const resultsScreen = document.getElementById("results-screen");

// -------- Upload --------
const uploadForm = document.getElementById("upload-form");
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
const fileName = document.getElementById("file-name");

// -------- Stage animation --------
const stages = Array.from(document.querySelectorAll("#stage-list .stage"));

// -------- Results --------
const projectName = document.getElementById("project-name");
const scoreValue = document.getElementById("score");
const scoreRingFill = document.getElementById("score-ring-fill");
const scoreText = document.getElementById("score-text");

const filesScanned = document.getElementById("files-scanned");
const issuesFound = document.getElementById("issues-found");
const highRisk = document.getElementById("high-risk");
const mediumRisk = document.getElementById("medium-risk");
const lowRisk = document.getElementById("low-risk");

const barHigh = document.getElementById("bar-high");
const barMedium = document.getElementById("bar-medium");
const barLow = document.getElementById("bar-low");

const scannerFindingsList = document.getElementById("scanner-findings-list");
const scannerFindingsCount = document.getElementById("scanner-findings-count");
const aiFindingsList = document.getElementById("ai-findings-list");
const aiFindingsCount = document.getElementById("ai-findings-count");
const recommendationsList = document.getElementById("recommendations-list");
const recommendationsCount = document.getElementById("recommendations-count");

const scanAgainBtn = document.getElementById("scan-again");
const toast = document.getElementById("toast");

const SCORE_RING_CIRCUMFERENCE = 2 * Math.PI * 52;

let currentReportId = null;

// =======================================
// Screen switch
// =======================================

function showScreen(screen) {
    uploadScreen.classList.remove("active");
    loadingScreen.classList.remove("active");
    resultsScreen.classList.remove("active");
    screen.classList.add("active");
}

// =======================================
// Browse file
// =======================================

dropzone.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
    if (fileInput.files.length) {
        selectFile(fileInput.files[0]);
    }
});

function selectFile(file) {
    fileName.textContent = `Ready to scan: ${file.name}`;
    document.getElementById("dz-title").hidden = true;
    dropzone.classList.add("has-file");
}

// =======================================
// Drag & drop
// =======================================

["dragenter", "dragover"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.add("drag-active");
    });
});

["dragleave", "drop"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.remove("drag-active");
    });
});

dropzone.addEventListener("drop", (e) => {
    const files = e.dataTransfer.files;
    if (files.length) {
        fileInput.files = files;
        selectFile(files[0]);
    }
});

// =======================================
// Stage animation
// -----------------------------------------
// The backend returns one response at the end, not progress
// events, so these stages are a paced narration of the real
// pipeline order (upload -> extract -> scan -> AI explain ->
// score) rather than a real progress stream.
// =======================================

async function runStageAnimation(responsePromise) {
    for (const stage of stages) stage.classList.remove("active", "done");

    // Upload/extract/scan are paced narration (backend doesn't stream
    // progress for these). AI audit is different: it stays active and
    // pulsing for as long as the real Gemini call takes, rather than a
    // guessed fixed duration.
    const preTimings = [800, 900, 1000]; // upload, extract, scan

    for (let i = 0; i < preTimings.length; i++) {
        stages[i].classList.add("active");
        await delay(preTimings[i]);
        stages[i].classList.remove("active");
        stages[i].classList.add("done");
    }

    const reviewStage = stages[3];
    reviewStage.classList.add("active");
    await responsePromise.catch(() => {}); // let the caller handle the actual error
    reviewStage.classList.remove("active");
    reviewStage.classList.add("done");

    const reportStage = stages[4];
    reportStage.classList.add("active");
    await delay(700);
    reportStage.classList.remove("active");
    reportStage.classList.add("done");
}

// =======================================
// Upload + scan
// =======================================

uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    if (!fileInput.files.length) {
        showToast("Choose a ZIP or source file first.");
        return;
    }

    showScreen(loadingScreen);

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    try {
        const fetchPromise = fetch(`${API_BASE}/upload`, {
            method: "POST",
            body: formData,
        });
        const animation = runStageAnimation(fetchPromise);

        const response = await fetchPromise;

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || `Server responded ${response.status}`);
        }

        const data = await response.json();
        await animation;
        renderDashboard(data);
    } catch (error) {
        console.error(error);
        showScreen(uploadScreen);
        showToast(error.message || "Backend not connected.");
    }
});

// =======================================
// Dashboard rendering
// =======================================

function renderDashboard(data) {
    showScreen(resultsScreen);

    const issues = data.issues_found || [];
    const recommendations = data.security_recommendations || [];
    const score = typeof data.security_score === "number" ? data.security_score : 100;
    const aiAuditAvailable = data.ai_audit_available !== false; // default true for older backends

    projectName.textContent = data.filename || "";
    currentReportId = data.report_id || null;

    const allClear = document.getElementById("all-clear");
    const issuesView = document.getElementById("issues-view");
    const aiUnavailableBanner = document.getElementById("ai-unavailable-banner");

    aiUnavailableBanner.hidden = aiAuditAvailable;

    // Zero scanner hits only counts as "all clear" if the AI audit
    // actually ran — otherwise this isn't a verified clean result,
    // it's an incomplete one, and showing the reassuring all-clear
    // screen would be actively misleading for a security tool.
    if (issues.length === 0 && aiAuditAvailable) {
        allClear.hidden = false;
        issuesView.hidden = true;
        document.getElementById("clear-files-count").textContent = data.files_scanned || 0;
        return;
    }

    allClear.hidden = true;
    issuesView.hidden = false;

    scoreValue.textContent = score;
    filesScanned.textContent = data.files_scanned || 0;
    issuesFound.textContent = issues.length;

    updateScore(score);
    renderSummary(issues);
    // Scanner Findings shows only pattern-matched results — that's
    // its whole point. AI Security Findings shows everything,
    // including issues only Gemini caught (source: "ai").
    const scannerOnly = issues.filter((i) => i.source !== "ai");
    renderScannerFindings(scannerOnly);
    renderAIFindings(issues);
    renderRecommendations(recommendations);
}

// =======================================
// Score ring
// =======================================

function updateScore(value) {
    const clamped = Math.max(0, Math.min(100, value));
    const offset = SCORE_RING_CIRCUMFERENCE * (1 - clamped / 100);

    let label, color;
    if (value >= 90) { label = "Excellent security"; color = "#4FAE72"; }
    else if (value >= 70) { label = "Good security"; color = "#E8A33D"; }
    else if (value >= 50) { label = "Moderate risk"; color = "#EA580C"; }
    else { label = "High risk project"; color = "#E5484D"; }

    scoreText.textContent = label;
    scoreText.style.color = color;
    scoreRingFill.style.stroke = color;
    scoreRingFill.style.strokeDashoffset = SCORE_RING_CIRCUMFERENCE;

    requestAnimationFrame(() => requestAnimationFrame(() => {
        scoreRingFill.style.strokeDashoffset = offset;
    }));
}

// =======================================
// Summary + distribution graph
// =======================================

function renderSummary(issues) {
    let high = 0, medium = 0, low = 0;

    issues.forEach((issue) => {
        const sev = (issue.severity || "").toLowerCase();
        if (sev === "high") high++;
        else if (sev === "medium") medium++;
        else low++;
    });

    highRisk.textContent = high;
    mediumRisk.textContent = medium;
    lowRisk.textContent = low;

    const maxCount = Math.max(high, medium, low, 1);

    // Reset to 0 first, then set the real height on the next frame so
    // the CSS transition on .bar actually animates the grow-in instead
    // of snapping straight to the final height on first paint.
    [barHigh, barMedium, barLow].forEach((bar) => { bar.style.height = "4px"; });

    requestAnimationFrame(() => requestAnimationFrame(() => {
        barHigh.style.height = barHeight(high, maxCount);
        barMedium.style.height = barHeight(medium, maxCount);
        barLow.style.height = barHeight(low, maxCount);
    }));
}

function barHeight(count, maxCount) {
    if (count === 0) return "4px";
    return Math.round((count / maxCount) * 130 + 20) + "px";
}

function sortBySeverity(issues) {
    const order = { High: 0, Medium: 1, Low: 2 };
    return issues.slice().sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3));
}

// Groups issues by file, preserving first-seen file order, and sorts
// each file's issues by severity. This is what makes a big multi-file
// ZIP scan clear about exactly which file(s) have a problem.
function groupByFile(issues) {
    const order = [];
    const groups = new Map();

    issues.forEach((issue) => {
        const key = issue.file || "Unknown file";
        if (!groups.has(key)) {
            groups.set(key, []);
            order.push(key);
        }
        groups.get(key).push(issue);
    });

    return order.map((key) => [key, sortBySeverity(groups.get(key))]);
}

function fileGroupHeader(filename, count) {
    return `
        <div class="file-group-header">
            <svg class="file-icon" width="14" height="14" viewBox="0 0 14 14" fill="none">
                <path d="M3 1.5H8L11 4.5V12.5H3V1.5Z" stroke="currentColor" stroke-width="1.2"/>
                <path d="M8 1.5V4.5H11" stroke="currentColor" stroke-width="1.2"/>
            </svg>
            <b>${escapeHTML(filename)}</b>
            <span>&middot; ${count} issue${count === 1 ? "" : "s"}</span>
        </div>
    `;
}

// =======================================
// Scanner findings view — raw, deterministic
// (same issues_found array, scanner-facing fields only)
// =======================================

function renderScannerFindings(issues) {
    scannerFindingsList.innerHTML = "";
    scannerFindingsCount.textContent = `${issues.length} issue${issues.length === 1 ? "" : "s"}`;

    if (issues.length === 0) {
        scannerFindingsList.innerHTML = `
            <div class="no-findings">
                <svg width="32" height="32" viewBox="0 0 32 32" fill="none" aria-hidden="true">
                    <circle cx="16" cy="16" r="14" stroke="#4FAE72" stroke-width="1.6"/>
                    <path d="M10 16.5L14 20.5L22 12" stroke="#4FAE72" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <h3>Rule-based scanner found no predefined vulnerabilities.</h3>
            </div>
        `;
        return;
    }

    groupByFile(issues).forEach(([filename, fileIssues]) => {
        const group = document.createElement("div");
        group.className = "file-group";
        group.innerHTML = fileGroupHeader(filename, fileIssues.length);
        fileIssues.forEach((issue) => group.appendChild(createScannerRow(issue)));
        scannerFindingsList.appendChild(group);
    });
}

function createScannerRow(issue) {
    const row = document.createElement("div");
    row.className = `scanner-row ${issue.severity || "Low"}`;

    const severityClass = (issue.severity || "low").toLowerCase();
    const location = issue.line ? `line ${issue.line}` : "";

    row.innerHTML = `
        <span class="severity severity-${severityClass}">${issue.severity || "Low"}</span>
        <div class="row-main">
            <div class="row-top">
                <span class="row-type">${escapeHTML(issue.type || "Issue")}</span>
                ${location ? `<span class="row-loc">${escapeHTML(location)}</span>` : ""}
            </div>
            ${issue.code ? `<pre class="code-block">${escapeHTML(issue.code)}</pre>` : ""}
        </div>
    `;

    return row;
}

// =======================================
// AI security findings view — Gemini's
// explanation + secure fix for each issue
// =======================================

function renderAIFindings(issues) {
    aiFindingsList.innerHTML = "";
    aiFindingsCount.textContent = `${issues.length} finding${issues.length === 1 ? "" : "s"}`;

    if (issues.length === 0) {
        aiFindingsList.innerHTML = `
            <div class="no-findings">
                <h3>Nothing flagged by Gemini.</h3>
                <p>No scanner findings needed explaining, and Gemini's independent audit of each file didn't surface anything either.</p>
            </div>
        `;
        return;
    }

    groupByFile(issues).forEach(([filename, fileIssues]) => {
        const group = document.createElement("div");
        group.className = "file-group";
        group.innerHTML = fileGroupHeader(filename, fileIssues.length);
        fileIssues.forEach((issue) => group.appendChild(createAICard(issue)));
        aiFindingsList.appendChild(group);
    });
}

function createAICard(issue) {
    const card = document.createElement("div");
    card.className = "ai-card";

    const severityClass = (issue.severity || "low").toLowerCase();
    const location = issue.line ? `line ${issue.line}` : "";

    const explanation = issue.ai_explanation
        ? escapeHTML(issue.ai_explanation)
        : "No explanation returned for this finding.";

    const fix = issue.secure_fix
        ? `<span class="fix-label">SECURE FIX</span><pre class="code-block fix-block">${escapeHTML(issue.secure_fix)}</pre>`
        : "";

    const aiOnlyBadge = issue.source === "ai"
        ? `<span class="ai-only-badge">AI-detected</span>`
        : "";

    card.innerHTML = `
        <div class="row-top">
            <span class="severity severity-${severityClass}">${issue.severity || "Low"}</span>
            <span class="row-type">${escapeHTML(issue.type || "Finding")}</span>
            ${location ? `<span class="row-loc">${escapeHTML(location)}</span>` : ""}
            ${aiOnlyBadge}
        </div>
        <p>${explanation}</p>
        ${fix}
    `;

    return card;
}

// =======================================
// Recommendations (deduped prevention tips)
// =======================================

function renderRecommendations(recommendations) {
    recommendationsList.innerHTML = "";
    recommendationsCount.textContent = `${recommendations.length} item${recommendations.length === 1 ? "" : "s"}`;

    if (recommendations.length === 0) {
        recommendationsList.innerHTML = `<li>No additional recommendations for this scan.</li>`;
        return;
    }

    recommendations.forEach((text) => {
        const li = document.createElement("li");
        li.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M3 8.5L6.2 11.5L13 4.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span>${escapeHTML(text)}</span>
        `;
        recommendationsList.appendChild(li);
    });
}

// =======================================
// Scan another
// =======================================

scanAgainBtn.addEventListener("click", () => {
    uploadForm.reset();
    fileName.textContent = ".zip · .java · .py · .js · .cpp";
    document.getElementById("dz-title").hidden = false;
    dropzone.classList.remove("has-file");
    scannerFindingsList.innerHTML = "";
    aiFindingsList.innerHTML = "";
    recommendationsList.innerHTML = "";
    document.getElementById("ai-unavailable-banner").hidden = true;
    currentReportId = null;
    showScreen(uploadScreen);
});

// =======================================
// Download report
// =======================================

document.getElementById("download-report").addEventListener("click", async () => {
    if (!currentReportId) {
        showToast("No report available for this scan.");
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/report/download/${currentReportId}`);
        if (!response.ok) throw new Error(`Server responded ${response.status}`);

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "devguard-report.pdf";
        a.click();
        URL.revokeObjectURL(url);
        showToast("Security report downloaded successfully.");
    } catch (error) {
        showToast(`Report download failed: ${error.message}`);
    }
});

// =======================================
// Toast
// =======================================

function showToast(message) {
    toast.textContent = message;
    toast.style.display = "block";
    setTimeout(() => { toast.style.display = "none"; }, 3200);
}

// =======================================
// Helpers
// =======================================

function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function escapeHTML(text = "") {
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

// =======================================
// Initial screen
// =======================================

showScreen(uploadScreen);
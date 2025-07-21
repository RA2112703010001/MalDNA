// Logging function for the frontend
function log(message, level = "info") {
    const levels = ["info", "warn", "error"];
    if (levels.includes(level)) {
        console[level](`${new Date().toISOString()} - ${level.toUpperCase()} - ${message}`);
    }
}

// Fetch Dashboard Stats Function
async function fetchDashboardStats() {
    try {
        const response = await fetch('http://127.0.0.1:5000/api/dashboard/stats', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include'
        });

        if (response.ok) {
            const stats = await response.json();
            window.latestDashboardStats = stats; // Store for report generation
            displayStats(stats);
        } else {
            const error = await response.json();
            log(`❌ Error fetching dashboard stats: ${error.error}`, "error");
        }
    } catch (error) {
        log(`❌ Error fetching dashboard stats: ${error.message}`, "error");
    }
}

// Display stats in the frontend
function displayStats(stats) {
    log("Dashboard stats fetched successfully.");
    const statsContainer = document.getElementById("stats-container");

    if (statsContainer) {
        statsContainer.innerHTML = `
            <div class="stat-card block-form-section">
                <h3>🦠 Total Malware</h3>
                <p>${stats.total_malware}</p>
            </div>
            <div class="stat-card block-form-section">
                <h3>🧬 DNA Sequences</h3>
                <p>${stats.dna_sequences}</p>
            </div>
            <div class="stat-card block-form-section">
                <h3>🧬 Active Threats</h3>
                <p>${stats.active_threats}</p>
            </div>
            <div class="stat-card block-form-section">
                <h3>🧷 Forensic Evidence</h3>
                <p>${stats.forensic_evidence}</p>
            </div>
            <div class="stat-card block-form-section">
                <h3>🔗 Blockchain Entries</h3>
                <p>${stats.blockchain_verified}</p>
            </div>
            <div class="stat-card block-form-section">
                <h3>📈 High Risk Threats</h3>
                <p>${stats.highRiskThreats}</p>
            </div>
            <div class="stat-card block-form-section">
                <h3>🦠 Unique Malware Families</h3>
                <p>${stats.uniqueFamilies}</p>
            </div>
            <div class="stat-card block-form-section">
                <h3>💾 Blockchain Transactions</h3>
                <p>${stats.blockchain_tx_entries}</p>
            </div>
        `;
    } else {
        log("❌ Stats container not found!", "error");
    }
}

// Generate Dashboard Report (Download functionality)
function generateDashboardReport(outputFormat) {
    const stats = window.latestDashboardStats;

    if (!stats) {
        log("❌ No stats available. Fetch stats before generating report.", "error");
        return;
    }

    let reportData = "";
    let mimeType = "";
    let filename = "";

    if (outputFormat === 'json') {
        reportData = JSON.stringify(stats, null, 4);
        mimeType = 'application/json';
        filename = 'dashboard_report.json';
    } else if (outputFormat === 'txt') {
        const flatText = [
            `Total Malware: ${stats.total_malware}`,
            `DNA Sequences: ${stats.dna_sequences}`,
            `Active Threats: ${stats.active_threats}`,
            `Forensic Evidence: ${stats.forensic_evidence}`,
            `Predictions:`,
            `  - Benign: ${stats.predictions.benign}`,
            `  - Malicious: ${stats.predictions.malicious}`,
            `  - Suspicious: ${stats.predictions.suspicious}`,
            `Unique Families: ${stats.uniqueFamilies}`,
            `Blockchain Verified: ${stats.blockchain_verified}`,
            `Blockchain Transactions: ${stats.blockchain_tx_entries}`
        ].join('\n');

        reportData = flatText;
        mimeType = 'text/plain';
        filename = 'dashboard_report.txt';
    } else {
        log("❌ Unsupported format! Use 'json' or 'txt'.", "error");
        return;
    }

    downloadFile(reportData, filename, mimeType);
}

// Helper function to trigger file download
function downloadFile(data, filename, mimeType) {
    const blob = new Blob([data], { type: mimeType });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Ensure DOM is fully loaded before attaching event listeners
document.addEventListener('DOMContentLoaded', function () {
    const statsContainer = document.getElementById("stats-container");
    if (!statsContainer) {
        log("❌ Stats container not found in DOM!", "error");
    }

    const fetchStatsBtn = document.getElementById("fetch-stats-btn");
    if (fetchStatsBtn) {
        fetchStatsBtn.addEventListener("click", fetchDashboardStats);
    } else {
        log("❌ Button for fetching stats not found!", "error");
    }

    const generateReportBtn = document.getElementById("generate-report-btn");
    if (generateReportBtn) {
        generateReportBtn.addEventListener("click", () => {
            const formatEl = document.querySelector('input[name="report-format"]:checked');
            if (formatEl) {
                generateDashboardReport(formatEl.value);
            } else {
                log("❌ No report format selected!", "error");
            }
        });
    } else {
        log("❌ Button for generating report not found!", "error");
    }

    // Optional: Fetch stats on page load
    fetchDashboardStats();
});


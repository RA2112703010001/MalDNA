// scripts/utils.js — Shared frontend utilities for MalDNA platform

// ---------------------
// ✅ UI & Component Utilities
// ---------------------

// Load global layout components: header, footer, sidebar
export async function loadHeaderFooter() {
    try {
        const [header, footer, sidebar] = await Promise.all([ 
            fetch("/templates/header.html").then(res => res.text()), 
            fetch("/templates/footer.html").then(res => res.text()), 
            fetch("/templates/sidebar.html").then(res => res.text()) 
        ]);

        document.getElementById("header").innerHTML = header;
        document.getElementById("footer").innerHTML = footer;
        document.getElementById("sidebar").innerHTML = sidebar;
    } catch (err) {
        console.error("❌ Failed to load layout components:", err);
    }
}

// Show global loader
export function showLoader(loaderId = 'global-loader') {
    const loader = document.getElementById(loaderId);
    if (loader) {
        loader.style.display = 'flex';
    } else {
        console.warn(`[MalDNA] Loader element not found: ${loaderId}`);
    }
}

// Hide global loader
export function hideLoader(loaderId = 'global-loader') {
    const loader = document.getElementById(loaderId);
    if (loader) {
        loader.style.display = 'none';
    } else {
        console.warn(`[MalDNA] Loader element not found: ${loaderId}`);
    }
}

// Show alert message (type: 'success' | 'error')
export function showAlert(message, type = 'success') {
    const alertBox = document.getElementById('alert-box');
    if (!alertBox) {
        console.warn("[MalDNA] Alert box not found.");
        return;
    }

    const alertClass = type === 'error' ? 'alert-danger' : 'alert-success';
    alertBox.innerHTML = `
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
            <strong>${type.toUpperCase()}:</strong> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
    alertBox.style.display = 'block';

    setTimeout(() => {
        alertBox.style.display = 'none';
    }, 5000);
}

// ---------------------
// ✅ Data & Error Handling
// ---------------------

// Format JavaScript Date object or string to YYYY-MM-DD
export function formatDate(date) {
    const d = new Date(date);
    return d.toISOString().split("T")[0];
}

// Parse JSON response safely
export function parseJSON(response) {
    try {
        return JSON.parse(response);
    } catch (error) {
        console.error("[MalDNA] Error parsing JSON:", error);
        return null;
    }
}

// Handle API or logic errors gracefully
export function handleAPIError(error, message = "An error occurred.") {
    console.error(`[MalDNA ERROR] ${message}`, error);
    const friendlyMsg = error?.response?.data?.detail || error?.message || message;
    showAlert(friendlyMsg, "error");
}

// ---------------------
// ✅ API Call Utilities
// ---------------------

// API Fetch Utility — Ensures no Authorization header is added unintentionally
export async function fetchAPI(url, options = {}) {
    try {
        // Ensure no Authorization header is included by default
        if (options.headers && options.headers['Authorization']) {
            delete options.headers['Authorization'];
        }

        const response = await fetch(url, options);
        
        // Handle non-200 responses gracefully
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        return await response.json(); // Return the JSON response
    } catch (error) {
        console.error("[MalDNA] API Fetch Error:", error);
        handleAPIError(error, "Failed to fetch data from the API.");
    }
}

// Example usage of fetchAPI
export async function getDashboardStats() {
    try {
        const data = await fetchAPI('http://127.0.0.1:5000/api/dashboard/stats', {
            method: 'GET',
            headers: { "Content-Type": "application/json" }
        });
        console.log("Dashboard Stats:", data);
    } catch (error) {
        console.error("[MalDNA] Failed to get dashboard stats:", error);
    }
}

// ---------------------
// ✅ API Call Functions for Malware Sample Analysis
// ---------------------

// Upload Malware Sample
export async function uploadFile(formData) {
    try {
        const response = await fetchAPI('/api/upload', {
            method: 'POST',
            body: formData,
        });
        return response; // Expected to return { filename: "sampleId" }
    } catch (error) {
        handleAPIError(error, "Failed to upload malware sample.");
    }
}

// Run Static Analysis
export async function runStaticAnalysis(sampleId) {
    return fetchAPI(`/api/analyze/static/${sampleId}`, {
        method: 'GET',
    });
}

// Run Dynamic Analysis
export async function runDynamicAnalysis(sampleId) {
    return fetchAPI(`/api/analyze/dynamic/${sampleId}`, {
        method: 'GET',
    });
}

// Run Hybrid Analysis
export async function runHybridAnalysis(sampleId) {
    return fetchAPI(`/api/analyze/hybrid/${sampleId}`, {
        method: 'GET',
    });
}

// Store Sample on Blockchain
export async function storeOnBlockchain({ filename }) {
    return fetchAPI(`/api/blockchain/store`, {
        method: 'POST',
        body: JSON.stringify({ filename }),
        headers: { 'Content-Type': 'application/json' }
    });
}

// Classify Malware
export async function classifyMalware(sampleId) {
    return fetchAPI(`/api/classify/${sampleId}`, {
        method: 'GET',
    });
}


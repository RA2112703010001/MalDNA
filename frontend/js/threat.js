import API from "./api.js";
import { handleAPIError, showLoader, hideLoader, showAlert } from "./utils.js";

document.addEventListener("DOMContentLoaded", () => {
    console.log("🚀 MalDNA DNA Module Initialized");

    const api = new API();

    const displayResult = (elementId, result) => {
        const el = document.getElementById(elementId);
        if (el) el.textContent = JSON.stringify(result, null, 2);
    };

    // Analyze Malware DNA
    document.getElementById("analyze-dna-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const sampleId = document.getElementById("dna-sample-id").value.trim();
        if (!sampleId) return showAlert("Please enter a Sample ID", "error");

        try {
            showLoader();
            const response = await api.post("/api/threat/analyze_dna", { sample_id: sampleId });
            displayResult("dna-analysis-result", response);
            showAlert("DNA analysis completed successfully.");
        } catch (error) {
            handleAPIError(error, "Error analyzing DNA.");
        } finally {
            hideLoader();
        }
    });

    // Correlate Malware DNA
    document.getElementById("correlate-dna-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const id1 = document.getElementById("correlate-sample-id-1").value.trim();
        const id2 = document.getElementById("correlate-sample-id-2").value.trim();
        if (!id1 || !id2) return showAlert("Both sample IDs are required", "error");

        try {
            showLoader();
            const response = await api.post("/api/threat/correlate_dna", {
                sample_id_1: id1,
                sample_id_2: id2,
            });
            displayResult("dna-correlation-result", response);
            showAlert("Correlation successful.");
        } catch (error) {
            handleAPIError(error, "Error correlating DNA.");
        } finally {
            hideLoader();
        }
    });

    // Enrich IoCs
    document.getElementById("enrich-ioc-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const iocValue = document.getElementById("ioc-value").value.trim();
        if (!iocValue) return showAlert("Enter a valid IOC value.", "error");

        try {
            showLoader();
            const response = await api.post("/api/threat/enrich_ioc", { ioc_value: iocValue });
            displayResult("ioc-enrichment-result", response);
            showAlert("IOC enrichment complete.");
        } catch (error) {
            handleAPIError(error, "Error enriching IoC.");
        } finally {
            hideLoader();
        }
    });

    // AI-Driven Correlation
    document.getElementById("ai-correlate-btn")?.addEventListener("click", async () => {
        try {
            showLoader();
            const response = await api.post("/api/threat/ai_correlate");
            displayResult("ai-correlation-result", response);
            showAlert("AI correlation executed successfully.");
        } catch (error) {
            handleAPIError(error, "Error running AI correlation.");
        } finally {
            hideLoader();
        }
    });

    // Store Data on Blockchain
    document.getElementById("store-blockchain-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const dataId = document.getElementById("blockchain-data-id").value.trim();
        if (!dataId) return showAlert("Please enter a Data ID to store.", "error");

        try {
            showLoader();
            const response = await api.post("/api/threat/store_blockchain", { data_id: dataId });
            displayResult("blockchain-store-result", response);
            showAlert("Threat data stored on blockchain successfully.");
        } catch (error) {
            handleAPIError(error, "Error storing threat data.");
        } finally {
            hideLoader();
        }
    });

    // VirusTotal Threat Intelligence
    document.getElementById("threat-intelligence-btn")?.addEventListener("click", async () => {
        const fileHash = document.getElementById("file-hash").value.trim();
        if (!fileHash) return showAlert("Please enter a file hash!", "error");

        try {
            showLoader();
            const result = await api.get(`/api/threat/intelligence/virustotal/${fileHash}`);
            displayResult("virustotal-result", result);
            showAlert("VirusTotal data fetched.");
        } catch (error) {
            handleAPIError(error, "Error fetching VirusTotal data.");
        } finally {
            hideLoader();
        }
    });

    // Hybrid Analysis Threat Intel
    document.getElementById("hybrid-analysis-btn")?.addEventListener("click", async () => {
        const fileHash = document.getElementById("file-hash").value.trim();
        if (!fileHash) return showAlert("Please enter a file hash!", "error");

        try {
            showLoader();
            const result = await api.get(`/api/threat/intelligence/hybrid_analysis/${fileHash}`);
            displayResult("hybrid-analysis-result", result);
            showAlert("Hybrid Analysis data fetched.");
        } catch (error) {
            handleAPIError(error, "Error fetching Hybrid Analysis data.");
        } finally {
            hideLoader();
        }
    });
});


import { showLoader, hideLoader, showAlert, handleAPIError } from './utils.js';
import axios from 'https://cdn.skypack.dev/axios';

// Constants and helper functions
const API_BASE_URL = "http://localhost:5000/api/lineage";  // Update your base URL accordingly

const handleApiRequest = async (endpoint, method = "GET", data = null) => {
  try {
    const response = await axios({
      url: `${API_BASE_URL}${endpoint}`,
      method,
      data,
      headers: {
        "Content-Type": "application/json",
      },
    });
    return response.data;
  } catch (error) {
    console.error("API Request Error:", error);
    throw new Error(error.response?.data?.error || "An error occurred");
  }
};

document.addEventListener("DOMContentLoaded", () => {
  // List All IDs
  document.getElementById("listIdsBtn")?.addEventListener("click", async () => {
    try {
      showLoader();
      const response = await handleApiRequest('/list_ids', "GET");
      const { lineage_ids, dna_ids } = response.all_ids;
      console.log('Lineage IDs:', lineage_ids);
      console.log('DNA IDs:', dna_ids);
      document.getElementById("resultBox").innerHTML = `<strong>List All IDs</strong><pre>${JSON.stringify({ lineage_ids, dna_ids }, null, 2)}</pre>`;
    } catch (error) {
      handleAPIError(error, "Error fetching IDs");
      document.getElementById("resultBox").innerHTML = "Fetching IDs failed.";
    } finally {
      hideLoader();
    }
  });

  // Reconstruct Malware Lineage
  document.getElementById("lineage-reconstruct-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("sample-id").value;

    try {
      showLoader();
      const response = await handleApiRequest(`/reconstruct/${sampleId}`, "POST");
      document.getElementById("lineage-reconstruct-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      handleAPIError(error, "Error reconstructing malware lineage");
      document.getElementById("lineage-reconstruct-result").innerText = "Reconstruction failed.";
    } finally {
      hideLoader();
    }
  });

  // Predict Malware Lineage using AI
  document.getElementById("predict-lineage-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const dnaId = document.getElementById("dna-id").value;

    try {
      showLoader();
      const response = await handleApiRequest(`/ai_predict?dna_id=${dnaId}`, "POST");
      document.getElementById("predict-lineage-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      handleAPIError(error, "Error predicting lineage with AI");
      document.getElementById("predict-lineage-result").innerText = "Prediction failed.";
    } finally {
      hideLoader();
    }
  });

  // Verify Lineage on Blockchain
  document.getElementById("blockchain-verify-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const lineageId = document.getElementById("lineage-id").value;

    try {
      showLoader();
      const response = await handleApiRequest(`/blockchain_verify?lineage_id=${lineageId}`, "GET");
      document.getElementById("blockchain-verify-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      handleAPIError(error, "Error verifying blockchain data");
      document.getElementById("blockchain-verify-result").innerText = "Verification failed.";
    } finally {
      hideLoader();
    }
  });

  // Get Mutation History
  document.getElementById("mutation-history-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("history-sample-id").value;

    try {
      showLoader();
      const response = await handleApiRequest(`/history/${sampleId}`, "GET");
      if (response.history && response.history.length > 0) {
        document.getElementById("mutation-history-result").innerText = JSON.stringify(response.history, null, 2);
      } else {
        document.getElementById("mutation-history-result").innerText = "No mutation history found.";
      }
    } catch (error) {
      handleAPIError(error, "Error retrieving mutation history");
      document.getElementById("mutation-history-result").innerText = "History retrieval failed.";
    } finally {
      hideLoader();
    }
  });

  // Predict Future Mutations
  document.getElementById("predict-future-mutations-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("predict-future-sample-id").value;

    try {
      showLoader();
      const requestBody = { sample_id: sampleId };
      const response = await handleApiRequest(`/predict`, "POST", requestBody);
      document.getElementById("predict-future-mutations-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      handleAPIError(error, "Error predicting future mutations");
      document.getElementById("predict-future-mutations-result").innerText = "Prediction failed.";
    } finally {
      hideLoader();
    }
  });
});


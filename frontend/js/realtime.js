import { showLoader, hideLoader, showAlert } from './utils.js';
import API from './api.js';

document.addEventListener("DOMContentLoaded", () => {
  const api = new API();

  // Fetch Real-Time Detection Status
  async function fetchDetectionStatus() {
    try {
      showLoader();
      const response = await api.get("/api/realtime/status");
      document.getElementById("detection-status-container").innerHTML = `
        <p><strong>Status:</strong> ${response.status}</p>
        <p><strong>Active Scanners:</strong> ${response.active_scanners}</p>
        <p><strong>Last Scan Time:</strong> ${response.last_scan_time}</p>
      `;
    } catch (error) {
      console.error("Error fetching detection status:", error);
      showAlert("Error fetching detection status.", "error");
      document.getElementById("detection-status-container").innerText = "Unavailable.";
    } finally {
      hideLoader();
    }
  }

  // Fetch Active Threats
  async function fetchActiveThreats() {
    try {
      showLoader();
      const response = await api.get("/api/realtime/detect");

      const container = document.getElementById("active-threats-container");
      if (!response.threats || response.threats.length === 0) {
        container.innerHTML = "<p>No active threats detected.</p>";
        return;
      }

      const threatsList = response.threats.map(threat => `
        <div class="threat-item">
          <p><strong>Threat ID:</strong> ${threat.id}</p>
          <p><strong>Type:</strong> ${threat.type}</p>
          <p><strong>Severity:</strong> ${threat.severity}</p>
          <p><strong>Description:</strong> ${threat.description}</p>
        </div><hr>
      `).join("");

      container.innerHTML = threatsList;
    } catch (error) {
      console.error("Error fetching active threats:", error);
      showAlert("Error fetching active threats.", "error");
      document.getElementById("active-threats-container").innerText = "Unable to load threats.";
    } finally {
      hideLoader();
    }
  }

  // Predict Future Threats
  document.getElementById("predict-threats-btn").addEventListener("click", async () => {
    try {
      showLoader();
      const response = await api.post("/api/realtime/predict");
      document.getElementById("threat-prediction-result").innerText = JSON.stringify(response, null, 2);
      showAlert("Threat prediction generated.");
    } catch (error) {
      console.error("Error predicting threats:", error);
      showAlert("Threat prediction failed.", "error");
      document.getElementById("threat-prediction-result").innerText = "Unable to predict threats.";
    } finally {
      hideLoader();
    }
  });

  // Trigger Automated Incident Response
  document.getElementById("incident-response-btn").addEventListener("click", async () => {
    try {
      showLoader();
      const response = await api.post("/api/realtime/incident-response");
      document.getElementById("incident-response-result").innerText = JSON.stringify(response, null, 2);
      showAlert("Incident response triggered.");
    } catch (error) {
      console.error("Error triggering incident response:", error);
      showAlert("Incident response failed.", "error");
      document.getElementById("incident-response-result").innerText = "Incident response unavailable.";
    } finally {
      hideLoader();
    }
  });

  // Initialize Real-Time Updates (polling)
  setInterval(fetchDetectionStatus, 5000);  // Every 5 seconds
  setInterval(fetchActiveThreats, 10000);   // Every 10 seconds

  // Initial fetch
  fetchDetectionStatus();
  fetchActiveThreats();
});


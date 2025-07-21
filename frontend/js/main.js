import API from "../js/api.js";
import {
  formatDate,
  handleAPIError,
  showLoader,
  hideLoader,
  showAlert
} from "../js/utils.js";

// Hardcode the environment variables directly for frontend use (or use a build tool to inject them)
const jwtSecretKey = "2d6328dfaf508705a8e924db10973c2bbb47a2028fb75448e437b72dd8e69cf5";
const jwtExpiresIn = "3600";
const bcryptRounds = 14;

document.addEventListener("DOMContentLoaded", async () => {
  console.log(`🚀 MalDNA Frontend Initialized @ ${formatDate(new Date())}`);
  
  await loadTemplates();
  initSidebarNavigation();
  setupGlobalListeners();
  fetchDashboardStats();
});

async function loadTemplates() {
  const templates = [
    { id: "header", path: "../templates/header.html" },
    { id: "footer", path: "../templates/footer.html" },
    { id: "sidebar", path: "../templates/sidebar.html" }
  ];

  for (let { id, path } of templates) {
    try {
      const response = await fetch(path);
      if (!response.ok) throw new Error(`Failed to load ${path}`);
      const html = await response.text();
      const element = document.getElementById(id);
      if (element) {
        element.innerHTML = html;
        console.log(`✅ Loaded template: ${path}`);
      } else {
        console.warn(`⚠️ Element with id '${id}' not found.`);
      }
    } catch (error) {
      handleAPIError(error, `Error loading template ${path}`);
    }
  }
}

function initSidebarNavigation() {
  document.querySelectorAll(".sidebar-link").forEach(link => {
    link.addEventListener("click", function (event) {
      event.preventDefault();
      loadPage(this.getAttribute("href"));
    });
  });
}

async function loadPage(page) {
  try {
    showLoader();
    const response = await fetch(page);
    if (!response.ok) throw new Error(`Failed to load ${page}`);
    document.querySelector("#content").innerHTML = await response.text();
    console.log(`✅ Loaded Page: ${page}`);
  } catch (error) {
    handleAPIError(error, "Error loading page");
  } finally {
    hideLoader();
  }
}

async function fetchDashboardStats() {
  const total = document.getElementById("total-malware");
  const active = document.getElementById("active-threats");
  const dna = document.getElementById("dna-sequences");

  if (!total || !active || !dna) {
    console.warn("🚫 Skipping fetchDashboardStats() – target elements not found.");
    return;
  }

  try {
    showLoader();
    const stats = await API.getDashboardStats();

    total.textContent = stats.total_malware || "0";
    active.textContent = stats.active_threats || "0";
    dna.textContent = stats.dna_sequences || "0";
  } catch (error) {
    handleAPIError(error, "Failed to fetch dashboard statistics");
  } finally {
    hideLoader();
  }
}

function setupGlobalListeners() {
  document.querySelector("#malware-upload-form")?.addEventListener("submit", uploadMalwareSample);
  document.querySelector("#static-analysis-btn")?.addEventListener("click", () => runAnalysis("static"));
  document.querySelector("#dynamic-analysis-btn")?.addEventListener("click", () => runAnalysis("dynamic"));
  document.querySelector("#blockchain-verify-btn")?.addEventListener("click", verifyBlockchainDNA);
  document.querySelector("#realtime-detect-btn")?.addEventListener("click", detectRealTimeThreats);
  document.querySelector("#dark-mode-toggle")?.addEventListener("click", toggleDarkMode);
}

async function uploadMalwareSample(event) {
  event.preventDefault();

  const fileInput = document.querySelector("#malware-file");
  const uploadPathInput = document.querySelector("#upload-path");
  const uploadedFileName = document.querySelector("#uploaded-file-name");

  if (!fileInput?.files.length) {
    showAlert("❌ Please select a file before uploading.", "error");
    return;
  }

  try {
    showLoader();

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append("file", file);
    formData.append("upload_path", uploadPathInput.value || "/home/kali/MalDNA/dataset/");

    const result = await API.uploadFile(formData); // ✅ Updated from window.api

    uploadedFileName.textContent = `✅ Uploaded: ${result.filename} to ${result.file_path}`;
    uploadedFileName.style.color = "green";
    showAlert("✅ Upload Successful!", "success");

    fileInput.value = "";
    uploadPathInput.value = "";
  } catch (error) {
    uploadedFileName.textContent = `❌ Upload Failed! ${error.message}`;
    uploadedFileName.style.color = "red";
    handleAPIError(error, "Upload Failed");
  } finally {
    hideLoader();
  }
}

async function runAnalysis(type) {
  const fileName = document.querySelector("#analysis-file-name")?.value;
  if (!fileName) {
    showAlert("❌ Please enter a file name for analysis.", "error");
    return;
  }

  try {
    showLoader();
    let result;
    if (type === "static") {
      result = await API.runStaticAnalysis(fileName);  // ✅
    } else if (type === "dynamic") {
      result = await API.runDynamicAnalysis(fileName); // ✅
    }

    document.querySelector("#analysis-result").textContent =
      `✅ ${type} analysis result: ${JSON.stringify(result, null, 2)}`;
  } catch (error) {
    handleAPIError(error, `${type} analysis failed`);
  } finally {
    hideLoader();
  }
}

async function verifyBlockchainDNA() {
  const sampleId = document.querySelector("#blockchain-sample-id")?.value;
  if (!sampleId) {
    showAlert("❌ Enter a Sample ID!", "error");
    return;
  }

  try {
    showLoader();
    const data = await API.verifyDNAOnChain(sampleId); // ✅

    document.querySelector("#blockchain-status").textContent =
      data.verification_status ? "✅ Verified on Blockchain" : "❌ Not Found on Blockchain";
  } catch (error) {
    handleAPIError(error, "Blockchain verification failed");
  } finally {
    hideLoader();
  }
}

async function detectRealTimeThreats() {
  try {
    showLoader();
    const result = await API.detectRealTime({}); // ✅
    document.querySelector("#threat-alert").textContent = `🚨 ${result.detection_status}`;
  } catch (error) {
    handleAPIError(error, "Real-time threat detection failed");
  } finally {
    hideLoader();
  }
}

function toggleDarkMode() {
  document.body.classList.toggle("dark-mode");
  localStorage.setItem("darkMode", document.body.classList.contains("dark-mode"));
}


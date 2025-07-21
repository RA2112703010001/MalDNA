document.addEventListener("DOMContentLoaded", () => {
  const api = new API(); // Assuming API class is defined in api.js
  let uploadedEvidenceId = null;

  // Upload Forensic Evidence
  document.getElementById("upload-evidence-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById("evidence-file");
    const file = fileInput.files[0];

    if (!file) {
      alert("Please select a file to upload.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await api.post("/api/forensics/forensic/evidence", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      uploadedEvidenceId = response.evidence_id;
      document.getElementById("upload-result").innerText = `Evidence uploaded successfully. Evidence ID: ${uploadedEvidenceId}`;
    } catch (error) {
      console.error("Error uploading evidence:", error);
      document.getElementById("upload-result").innerText = "Error uploading evidence.";
    }
  });

  // Analyze Memory Dump
  document.getElementById("analyze-memory-btn").addEventListener("click", async () => {
    if (!uploadedEvidenceId) {
      alert("Please upload forensic evidence first.");
      return;
    }

    try {
      const response = await api.post("/api/forensics/forensic/analyze_memory", { evidence_id: uploadedEvidenceId });
      document.getElementById("analysis-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error analyzing memory dump:", error);
      document.getElementById("analysis-result").innerText = "Error analyzing memory dump.";
    }
  });

  // Analyze Disk Image
  document.getElementById("analyze-disk-btn").addEventListener("click", async () => {
    if (!uploadedEvidenceId) {
      alert("Please upload forensic evidence first.");
      return;
    }

    try {
      const response = await api.post("/api/forensics/forensic/analyze_disk", { evidence_id: uploadedEvidenceId });
      document.getElementById("analysis-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error analyzing disk image:", error);
      document.getElementById("analysis-result").innerText = "Error analyzing disk image.";
    }
  });

  // Generate Forensic Report
  document.getElementById("generate-report-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("report-sample-id").value;

    try {
      const response = await api.post("/api/forensics/forensic/report", { sample_id: sampleId });
      document.getElementById("report-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error generating forensic report:", error);
      document.getElementById("report-result").innerText = "Error generating forensic report.";
    }
  });

  // Verify Evidence Integrity
  document.getElementById("verify-integrity-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const evidenceId = document.getElementById("integrity-evidence-id").value;

    try {
      const response = await api.get(`/api/forensics/forensic/verify_integrity?evidence_id=${evidenceId}`);
      document.getElementById("verify-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error verifying evidence integrity:", error);
      document.getElementById("verify-result").innerText = "Error verifying evidence integrity.";
    }
  });

  // Retrieve Blockchain Evidence History
  document.getElementById("retrieve-history-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const evidenceId = document.getElementById("history-evidence-id").value;

    try {
      const response = await api.get(`/api/blockchain/blockchain/evidence_history/${evidenceId}`);
      document.getElementById("history-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error retrieving evidence history:", error);
      document.getElementById("history-result").innerText = "Error retrieving evidence history.";
    }
  });
});

document.addEventListener("DOMContentLoaded", () => {
  const api = new API(); // Assumes API class from api.js handles GET/POST

  // 1️⃣ Store DNA on Blockchain
  document.getElementById("store-dna-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("dna-sample-id").value;

    try {
      const response = await api.post("/api/blockchain/store", {
        sample_id: sampleId,
        type: "dna"
      });
      document.getElementById("dna-store-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error storing DNA:", error);
      document.getElementById("dna-store-result").innerText = "❌ Error storing DNA on blockchain.";
    }
  });

  // 2️⃣ Verify DNA on Blockchain
  document.getElementById("verify-dna-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("verify-dna-sample-id").value;

    try {
      const response = await api.get(`/api/blockchain/verify_dna/${sampleId}`);
      document.getElementById("dna-verify-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error verifying DNA:", error);
      document.getElementById("dna-verify-result").innerText = "❌ Error verifying DNA on blockchain.";
    }
  });

  // 3️⃣ Store Forensic Evidence on Blockchain
  document.getElementById("store-forensic-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const evidenceId = document.getElementById("forensic-evidence-id").value;

    try {
      const response = await api.post("/api/blockchain/store", {
        evidence_id: evidenceId,
        type: "forensic"
      });
      document.getElementById("forensic-store-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error storing forensic evidence:", error);
      document.getElementById("forensic-store-result").innerText = "❌ Error storing forensic evidence.";
    }
  });

  // 4️⃣ Retrieve Forensic History from Blockchain
  document.getElementById("retrieve-history-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const evidenceId = document.getElementById("history-evidence-id").value;

    try {
      const response = await api.get(`/api/blockchain/forensic_history/${evidenceId}`);
      document.getElementById("history-retrieve-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error retrieving forensic history:", error);
      document.getElementById("history-retrieve-result").innerText = "❌ Error retrieving forensic history.";
    }
  });

  // 5️⃣ Retrieve Blockchain Evidence History (Block Records)
  document.getElementById("verify-integrity-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const evidenceId = document.getElementById("integrity-evidence-id").value;

    try {
      const response = await api.get(`/api/blockchain/blockchain/evidence_history/${evidenceId}`);
      document.getElementById("integrity-verify-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error retrieving blockchain evidence history:", error);
      document.getElementById("integrity-verify-result").innerText = "❌ Error verifying evidence integrity.";
    }
  });
});


document.addEventListener("DOMContentLoaded", () => {
  const api = new API(); // Assuming API class is defined in api.js

  // Extract Features
  document.getElementById("extract-features-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("sample-id").value;

    try {
      const response = await api.get(`/api/features/extract/${sampleId}`);
      document.getElementById("feature-extraction-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error extracting features:", error);
      document.getElementById("feature-extraction-result").innerText = "Error extracting features.";
    }
  });

  // List Datasets
  document.getElementById("list-datasets-btn").addEventListener("click", async () => {
    try {
      const response = await api.get("/api/dataset/list");
      const datasetsList = response.datasets.map(dataset => `
        <div>
          <strong>ID:</strong> ${dataset.id}<br>
          <strong>Name:</strong> ${dataset.name}<br>
          <strong>Samples:</strong> ${dataset.sample_count}<br>
        </div>
        <hr>
      `).join("");
      document.getElementById("datasets-container").innerHTML = datasetsList || "No datasets available.";
    } catch (error) {
      console.error("Error listing datasets:", error);
      document.getElementById("datasets-container").innerText = "Error listing datasets.";
    }
  });

  // Add Sample to Dataset
  document.getElementById("add-sample-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const datasetId = document.getElementById("dataset-id-add").value;
    const sampleId = document.getElementById("sample-id-add").value;

    try {
      const response = await api.post("/api/dataset/add_sample", { dataset_id: datasetId, sample_id: sampleId });
      document.getElementById("add-sample-result").innerText = "Sample added successfully.";
    } catch (error) {
      console.error("Error adding sample:", error);
      document.getElementById("add-sample-result").innerText = "Error adding sample.";
    }
  });

  // Remove Sample from Dataset
  document.getElementById("remove-sample-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const datasetId = document.getElementById("dataset-id-remove").value;
    const sampleId = document.getElementById("sample-id-remove").value;

    try {
      const response = await api.post("/api/dataset/remove_sample", { dataset_id: datasetId, sample_id: sampleId });
      document.getElementById("remove-sample-result").innerText = "Sample removed successfully.";
    } catch (error) {
      console.error("Error removing sample:", error);
      document.getElementById("remove-sample-result").innerText = "Error removing sample.";
    }
  });

  // Label Sample
  document.getElementById("label-sample-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("sample-id-label").value;
    const label = document.getElementById("label").value;

    try {
      const response = await api.post("/api/dataset/label_sample", { sample_id: sampleId, label });
      document.getElementById("label-sample-result").innerText = "Sample labeled successfully.";
    } catch (error) {
      console.error("Error labeling sample:", error);
      document.getElementById("label-sample-result").innerText = "Error labeling sample.";
    }
  });

  // Export Dataset
  document.getElementById("export-dataset-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const datasetId = document.getElementById("dataset-id-export").value;

    try {
      const response = await api.get(`/api/dataset/export/${datasetId}`);
      const blob = new Blob([response], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `dataset_${datasetId}.json`;
      link.click();
      document.getElementById("export-dataset-result").innerText = "Dataset exported successfully.";
    } catch (error) {
      console.error("Error exporting dataset:", error);
      document.getElementById("export-dataset-result").innerText = "Error exporting dataset.";
    }
  });
});

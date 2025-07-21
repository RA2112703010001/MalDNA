import { showLoader, hideLoader, handleAPIError, formatDate } from './utils.js';
import { API } from './api.js'; // Assuming API class is defined and exported properly

document.addEventListener("DOMContentLoaded", () => {
  const api = new API();

  const mutationForm = document.getElementById("mutation-track-form");
  const mutationResult = document.getElementById("mutation-track-result");
  const predictionForm = document.getElementById("predict-mutations-form");
  const predictionResult = document.getElementById("predict-mutations-result");

  /**
   * Submit handler: Track mutation history over time
   */
  mutationForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("mutation-sample-id").value.trim();

    if (!sampleId) {
      mutationResult.innerText = "Please enter a valid Sample ID.";
      return;
    }

    showLoader();

    try {
      const response = await api.get(`/api/lineage/history/${sampleId}`);

      if (!response?.history || response.history.length === 0) {
        mutationResult.innerText = "No mutation history available for the given Sample ID.";
        return;
      }

      mutationResult.innerText = JSON.stringify(response, null, 2);
      renderMutationHistoryChart(response.history);
    } catch (error) {
      handleAPIError(error, "Error tracking mutations.");
      mutationResult.innerText = "Error retrieving mutation history.";
    } finally {
      hideLoader();
    }
  });

  /**
   * Submit handler: Predict future mutations
   */
  predictionForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("predict-sample-id").value.trim();

    if (!sampleId) {
      predictionResult.innerText = "Please enter a valid Sample ID.";
      return;
    }

    showLoader();

    try {
      const response = await api.post("/api/lineage/predict", { sample_id: sampleId });

      if (!response?.predictions || response.predictions.length === 0) {
        predictionResult.innerText = "No predictions available for this sample.";
        return;
      }

      predictionResult.innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      handleAPIError(error, "Error predicting mutations.");
      predictionResult.innerText = "Error retrieving mutation predictions.";
    } finally {
      hideLoader();
    }
  });

  /**
   * Renders a line chart for mutation history using Chart.js
   * @param {Array} history - Array of objects with `date` and `mutation_count`
   */
  function renderMutationHistoryChart(history) {
    const ctx = document.getElementById("mutation-history-chart")?.getContext("2d");

    if (!ctx || !Array.isArray(history)) return;

    const labels = history.map(entry => formatDate(entry.date));
    const data = history.map(entry => entry.mutation_count);

    new Chart(ctx, {
      type: "line",
      data: {
        labels: labels,
        datasets: [{
          label: "Mutation Count Over Time",
          data: data,
          borderColor: "#007bff",
          backgroundColor: "rgba(0, 123, 255, 0.2)",
          borderWidth: 2,
          fill: true,
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            display: true,
          },
        },
        scales: {
          x: {
            title: {
              display: true,
              text: 'Date'
            },
            ticks: {
              autoSkip: true,
              maxTicksLimit: 10
            }
          },
          y: {
            title: {
              display: true,
              text: 'Mutation Count'
            },
            beginAtZero: true,
          },
        },
      },
    });
  }
});


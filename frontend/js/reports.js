import { handleAPIError, showAlert, formatDate } from './utils.js';
import { API } from './api.js';

document.addEventListener("DOMContentLoaded", () => {
  const api = new API();

  // 📄 List all available reports
  document.getElementById("list-reports-btn").addEventListener("click", async () => {
    try {
      const response = await api.get("/api/report/reports/list");

      const reportsList = response.reports.map(report => `
        <div class="report-card">
          <strong>ID:</strong> ${report.id}<br>
          <strong>Type:</strong> ${report.type}<br>
          <strong>Date:</strong> ${formatDate(report.date)}<br>
        </div>
        <hr>
      `).join("");

      document.getElementById("reports-list-container").innerHTML = reportsList || "No reports available.";
    } catch (error) {
      handleAPIError(error, "Failed to list reports.");
      document.getElementById("reports-list-container").innerText = "Error listing reports.";
    }
  });

  // 🧬 Generate a new report (malware/dna/forensic/threat)
  document.getElementById("generate-report-form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const reportType = document.getElementById("report-type").value;
    const criteria = document.getElementById("report-criteria").value;

    if (!reportType || !criteria) {
      showAlert("Report type and criteria are required.", "error");
      return;
    }

    try {
      const response = await api.post(`/api/report/reports/${reportType}`, { criteria });

      const msg = `✅ Report generated successfully. Report ID: ${response.report_id}`;
      document.getElementById("generate-report-result").innerText = msg;
      showAlert(msg, "success");
    } catch (error) {
      handleAPIError(error, "Report generation failed.");
      document.getElementById("generate-report-result").innerText = "Error generating report.";
    }
  });

  // ⬇️ Download a report by ID and format
  document.getElementById("download-report-form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const reportId = document.getElementById("report-id").value;
    const format = document.getElementById("download-format").value;

    if (!reportId || !format) {
      showAlert("Report ID and format are required.", "error");
      return;
    }

    try {
      const response = await api.get(`/api/report/reports/download/${reportId}?format=${format}`, {
        responseType: 'blob'
      });

      const blob = new Blob([response], { type: `application/${format}` });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `report_${reportId}.${format}`;
      link.click();

      document.getElementById("download-report-result").innerText = "✅ Report downloaded successfully.";
    } catch (error) {
      handleAPIError(error, "Failed to download report.");
      document.getElementById("download-report-result").innerText = "Error downloading report.";
    }
  });

  // 📊 Fetch Report Generation Analytics
  document.getElementById("fetch-analytics-btn").addEventListener("click", async () => {
    try {
      const response = await api.get("/api/report/reports/analytics");
      const labels = response.analytics.map(entry => entry.month);
      const data = response.analytics.map(entry => entry.count);

      const ctx = document.getElementById("analytics-chart").getContext("2d");
      new Chart(ctx, {
        type: "bar",
        data: {
          labels: labels,
          datasets: [{
            label: "Reports Generated Per Month",
            data: data,
            backgroundColor: "#28a745",
            borderColor: "#218838",
            borderWidth: 1,
          }],
        },
        options: {
          responsive: true,
          plugins: {
            legend: { display: true },
            tooltip: { enabled: true }
          },
          scales: {
            x: { beginAtZero: true },
            y: { beginAtZero: true }
          }
        }
      });
    } catch (error) {
      handleAPIError(error, "Error loading analytics data.");
      document.getElementById("analytics-chart").innerText = "Analytics load error.";
    }
  });
});


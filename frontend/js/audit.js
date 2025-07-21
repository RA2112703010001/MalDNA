document.addEventListener("DOMContentLoaded", () => {
  const api = new API(); // Make sure API class is properly implemented

  // Function to get the JWT token from localStorage or sessionStorage
  function getAuthToken() {
    return localStorage.getItem("access_token"); // You can also use sessionStorage depending on your use case
  }

  // Method to include JWT token in the API requests
  api.get = async function (url) {
    const token = getAuthToken(); // Retrieve the JWT token
    const headers = {
      "Authorization": token ? `Bearer ${token}` : "", // Add token to the Authorization header
      "Content-Type": "application/json"
    };

    const response = await fetch(url, { headers });
    return await response.json(); // Parse and return the JSON response
  };

  // 🔍 Filter Audit Logs
  document.getElementById("filter-logs-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const startDate = document.getElementById("start-date").value;
    const endDate = document.getElementById("end-date").value;
    const userFilter = document.getElementById("user-filter").value || "";
    const activityType = document.getElementById("activity-type").value || "";

    try {
      const queryParams = new URLSearchParams({
        start_date: startDate,
        end_date: endDate,
        user_id: userFilter,
        activity_type: activityType,
      }).toString();

      const response = await api.get(`/api/audit/logs?${queryParams}`);

      const logsList = response.logs.map(log => `
        <div class="log-entry">
          <img src="/assets/icons/log.png" class="log-icon" alt="Log Icon">
          <div><strong>📅 Date:</strong> ${log.timestamp}</div>
          <div><strong>👤 User:</strong> ${log.user_id}</div>
          <div><strong>🔍 Activity:</strong> ${log.activity_type}</div>
          <div><strong>📝 Details:</strong> ${log.details}</div>
        </div>
        <hr>
      `).join("");

      document.getElementById("logs-container").innerHTML = logsList || "<p>No logs found for this filter.</p>";
    } catch (error) {
      console.error("Error fetching logs:", error);
      document.getElementById("logs-container").innerText = "❌ Error fetching logs.";
    }
  });

  // 📤 Export Audit Logs
  document.getElementById("export-logs-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const format = document.getElementById("export-format").value;

    try {
      const blob = await api.exportAuditLogs(format); // should call /api/audit/logs/export?format=...
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `audit_logs.${format}`;
      link.click();
      document.getElementById("export-result").innerText = "✅ Logs exported successfully.";
    } catch (error) {
      console.error("Error exporting logs:", error);
      document.getElementById("export-result").innerText = "❌ Error exporting logs.";
    }
  });

  // 📊 Fetch System Activity Analytics
  document.getElementById("fetch-analytics-btn").addEventListener("click", async () => {
    try {
      const response = await api.get("/api/audit/logs/analytics");
      const labels = response.analytics.map(entry => entry.date);
      const data = response.analytics.map(entry => entry.count);

      const ctx = document.getElementById("activity-trends-chart").getContext("2d");
      new Chart(ctx, {
        type: "line",
        data: {
          labels: labels,
          datasets: [{
            label: "🔁 System Activity Over Time",
            data: data,
            borderColor: "#00c853",
            backgroundColor: "rgba(0, 200, 83, 0.2)",
            borderWidth: 2,
            fill: true,
          }],
        },
        options: {
          responsive: true,
          plugins: {
            legend: { display: true },
          },
          scales: {
            x: { title: { display: true, text: 'Date' } },
            y: { beginAtZero: true, title: { display: true, text: 'Events' } }
          },
        },
      });
    } catch (error) {
      console.error("Error fetching analytics:", error);
      document.getElementById("chart-error").innerText = "❌ Error fetching analytics.";
    }
  });
});


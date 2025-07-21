<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Hybrid Analysis - MalDNA</title>
  <link rel="stylesheet" href="../css/styles.css" />
  <link rel="stylesheet" href="../css/responsive.css" />
</head>
<body>
  <!-- Header -->
  <header>
    <h1>Hybrid Analysis Engine: Static + Dynamic + AI</h1>
    <nav>
      <ul>
        <li><a href="../index.html">Home</a></li>
        <li><a href="dashboard.html">Dashboard</a></li>
      </ul>
    </nav>
  </header>

  <main>
    <!-- Visual Highlight -->
    <section class="hybrid-section">
      <img src="../assets/Hybrid Analysis Engine.png" alt="Hybrid Analysis Engine" style="width: 100%; max-width: 800px; display: block; margin: 0 auto; border-radius: 12px; box-shadow: 0 0 20px #00e5ff33;" />
    </section>

    <!-- Upload Sample -->
    <section class="hybrid-section">
      <h2>📤 Upload Sample for Hybrid Analysis</h2>
      <form id="upload-sample-form">
        <label for="file-upload">Select File:</label>
        <input type="file" id="file-upload" required />
        <button type="submit">Upload & Analyze</button>
      </form>
      <div id="upload-result" class="dna-result-block"></div>
    </section>

    <!-- Analyze Existing Sample -->
    <section class="hybrid-section">
      <h2>🔍 Analyze Existing Sample (Auto-Classify)</h2>
      <form id="analyze-sample-form">
        <label for="sample-id">Sample ID:</label>
        <input type="text" id="sample-id" placeholder="Enter Sample ID" required />
        <button type="submit">Analyze</button>
      </form>
      <div id="analysis-result" class="dna-result-block"></div>
    </section>

    <!-- Generate Report -->
    <section class="hybrid-section">
      <h2>📄 Generate Hybrid Analysis Report</h2>
      <form id="generate-report-form">
        <label for="report-sample-id">Sample ID:</label>
        <input type="text" id="report-sample-id" placeholder="Enter Sample ID" required />
        <button type="submit">Generate Report</button>
      </form>
      <div id="report-result" class="dna-result-block"></div>
    </section>

    <!-- Feature Extraction -->
    <section class="hybrid-section">
      <h2>🧬 Extract AI Features</h2>
      <label for="extract-sample-id">Sample ID:</label>
      <input type="text" id="extract-sample-id" placeholder="Enter Sample ID" required />
      <button id="extract-features-btn">Extract Features</button>
      <div id="feature-result" class="dna-result-block"></div>
    </section>
  </main>

  <!-- Footer -->
  <footer>
    <p>&copy; 2025 Malware DNA Analysis Platform</p>
  </footer>

  <!-- JavaScript Modules -->
  <script type="module" src="../js/api.js"></script>
  <script type="module" src="../js/hybrid.js"></script>
  <script type="module" src="../js/main.js"></script>
</body>
</html>


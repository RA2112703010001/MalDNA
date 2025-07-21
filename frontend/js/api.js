const BASE_URL = "http://127.0.0.1:5000";

// ✅ Utility: Centralized Header Generator
function getHeaders(isFormData = false) {
  // Don't set Content-Type for FormData; browser will set it with boundaries
  return isFormData ? undefined : { "Content-Type": "application/json" };
}

class API {
  constructor(baseURL = BASE_URL) {
    this.baseURL = baseURL;
    this.cache = new Map();
  }

  async get(endpoint, useCache = false) {
    const url = `${this.baseURL}${endpoint}`;
    if (useCache && this.cache.has(url)) return this.cache.get(url);

    const response = await fetch(url, { method: "GET", headers: getHeaders() });

    if (!response.ok) throw new Error(await response.text());
    const result = await response.json();

    if (useCache) this.cache.set(url, { result, timestamp: Date.now() });
    return result;
  }

  async post(endpoint, data, isFormData = false) {
    const options = {
      method: "POST",
      body: isFormData ? data : JSON.stringify(data)
    };

    const headers = getHeaders(isFormData);
    if (headers) options.headers = headers;

    const response = await fetch(`${this.baseURL}${endpoint}`, options);

    if (!response.ok) throw new Error(await response.text());
    return await response.json();
  }

  // --- 🦠 Malware ---
  async uploadFile(file, sampleId = null) {
    const formData = new FormData();
    formData.append("file", file);
    if (sampleId) {
      formData.append("sample_id", sampleId);
    }
    return this.post("/api/malware/upload", formData, true);
  }

  async runStaticAnalysis(filename) {
    return this.post("/api/malware/static_analysis", { filename });
  }

  async runDynamicAnalysis(filename) {
    return this.post("/api/malware/dynamic_analysis", { filename });
  }

  async runHybridAnalysis(filename) {
    return this.post("/api/malware/hybrid_analysis", { filename });
  }

  async classifyMalware(filename) {
    return this.get(`/api/malware/classify/${filename}`);
  }

  // --- 🧬 DNA ---
  generateDNA(data) {
    return this.post("/api/dna/dna/generate", data);
  }

  compareDNAPair(sampleId1, sampleId2) {
    return this.get(`/api/dna/dna/similarity/${sampleId1}/${sampleId2}`);
  }

  detectMutations(sampleId) {
    return this.get(`/api/dna/dna/mutations/${sampleId}`);
  }

  getFamilyLineage(familyName) {
    return this.get(`/api/dna/dna/family/${familyName}`);
  }

  visualizeSimilarity(sampleId) {
    return this.get(`/api/dna/dna/similarity/${sampleId}`);
  }

  batchCompareDNA(data) {
    return this.post("/api/dna/dna/batch_compare", data);
  }

  // --- 🌿 Lineage ---
  reconstructLineage(sampleId) {
    return this.get(`/api/lineage/reconstruct/${sampleId}`);
  }

  predictLineageAI(data) {
    return this.post("/api/lineage/ai_predict", data);
  }

  verifyLineageBlockchain(data) {
    return this.post("/api/lineage/blockchain_verify", data);
  }

  getMutationHistory(sampleId) {
    return this.get(`/api/lineage/history/${sampleId}`);
  }

  predictFutureMutations(data) {
    return this.post("/api/lineage/predict", data);
  }

  // --- 🕵️‍♀️ Forensics ---
  collectForensicEvidence(data) {
    return this.post("/api/forensics/evidence", data);
  }

  analyzeMemory(data) {
    return this.post("/api/forensics/analyze_memory", data);
  }

  analyzeDisk(data) {
    return this.post("/api/forensics/analyze_disk", data);
  }

  generateForensicReport(data) {
    return this.post("/api/forensics/report", data);
  }

  verifyEvidenceIntegrity(data) {
    return this.post("/api/forensics/verify_integrity", data);
  }

  // --- 🔴 Realtime ---
  detectRealTime(data) {
    return this.post("/api/realtime/detect", data);
  }

  getRealtimeStatus() {
    return this.get("/api/realtime/status");
  }

  predictRealtimeThreat(data) {
    return this.post("/api/realtime/predict", data);
  }

  triggerAutoIncidentResponse(data) {
    return this.post("/api/realtime/incident-response", data);
  }

  // --- 🧠 Threat Intelligence ---
  apiVirusTotal(fileHash) {
    return this.get(`/api/threat/intelligence/virustotal/${fileHash}`);
  }

  apiHybridAnalysis(fileHash) {
    return this.get(`/api/threat/intelligence/hybrid_analysis/${fileHash}`);
  }

  apiMaltiverse(fileHash) {
    return this.get(`/api/threat/intelligence/maltiverse/${fileHash}`);
  }

  apiIBM(fileHash) {
    return this.get(`/api/threat/intelligence/ibmxforce/${fileHash}`);
  }

  analyzeMalwareDNA(data) {
    return this.post("/api/threat/analyze_dna", data);
  }

  correlateMalwareDNA(data) {
    return this.post("/api/threat/correlate_dna", data);
  }

  enrichIOC(data) {
    return this.post("/api/threat/enrich_ioc", data);
  }

  aiCorrelate(data) {
    return this.post("/api/threat/ai_correlate", data);
  }

  storeThreatOnBlockchain(data) {
    return this.post("/api/threat/store_blockchain", data);
  }

  fetchThreatReports() {
    return this.get("/api/threat/fetch_reports");
  }

  // --- 📄 Reports ---
  generateMalwareReport(data) {
    return this.post("/api/report/reports/malware", data);
  }

  generateDNAReport(data) {
    return this.post("/api/report/reports/dna", data);
  }

  generateForensicReportAPI(data) {
    return this.post("/api/report/reports/forensic", data);
  }

  generateThreatIntelReport(data) {
    return this.post("/api/report/reports/threat", data);
  }

  listReports() {
    return this.get("/api/report/reports/list");
  }

  downloadReport(reportId) {
    return this.get(`/api/report/reports/download/${reportId}`);
  }

  fetchReportAnalytics() {
    return this.get("/api/report/reports/analytics");
  }

  // --- 📝 Audit Logs ---
  getAuditLogs() {
    return this.get("/api/audit/logs");
  }

  exportAuditLogs() {
    return this.get("/api/audit/logs/export");
  }

  getAuditAnalytics() {
    return this.get("/api/audit/logs/analytics");
  }

  // --- 🌟 Features ---
  getFeatures() {
    return this.get("/api/features/");
  }

  getFeatureDetails(featureId) {
    return this.get(`/api/features/${featureId}`);
  }

  getFeatureSummary() {
    return this.get("/api/features/summary");
  }

  uploadProcessedFeatures(data) {
    return this.post("/api/features/upload", data);
  }

  // --- 🧪 Hybrid Analysis ---
  analyzeHybrid(data) {
    return this.post("/api/hybrid-analysis/analyze", data);
  }

  getHybridReport(sampleId) {
    return this.get(`/api/hybrid-analysis/report/${sampleId}`);
  }

  autoClassify() {
    return this.post("/api/hybrid-analysis/auto_classify", {});
  }

  extractHybridFeatures(data) {
    return this.post("/api/hybrid-analysis/extract_features", data);
  }

  // --- ⛓ Blockchain ---
  verifyDNAOnChain(sampleId) {
    return this.get(`/api/blockchain/verify_dna/${sampleId}`);
  }

  getForensicHistory(evidenceId) {
    return this.get(`/api/blockchain/forensic_history/${evidenceId}`);
  }

  unifiedStoreBlockchain(data) {
    return this.post("/api/blockchain/store", data);
  }

  getEvidenceBlockchainHistory(data) {
    return this.get(`/api/blockchain/evidence_history/${data}`);
  }

  // --- 🧪 CLI-based Analysis ---
  cliAnalyzeByHash(sampleHash) {
    return this.post("/api/hybrid-analysis/cli_analyze", { sample_hash: sampleHash });
  }

  cliGetAnalysisStatus(sampleHash) {
    return this.get(`/api/hybrid-analysis/cli_status/${sampleHash}`);
  }

  cliGetFinalReport(sampleHash) {
    return this.get(`/api/hybrid-analysis/cli_report/${sampleHash}`);
  }

  cliFallbackToVirusTotal(sampleHash) {
    return this.get(`/api/threat/intelligence/virustotal/${sampleHash}`);
  }

  cliFallbackToMaltiverse(sampleHash) {
    return this.get(`/api/threat/intelligence/maltiverse/${sampleHash}`);
  }
}

const api = new API();
export default api;


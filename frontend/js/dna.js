import { v4 as uuidv4 } from 'https://cdn.skypack.dev/uuid';
import axios from 'https://cdn.skypack.dev/axios';

// Constants and helper functions
const API_BASE_URL = "http://localhost:5000/api/dna";  // Update your base URL accordingly

const handleApiRequest = async (endpoint, method = "GET", data = null) => {
  try {
    const response = await axios({
      url: `${API_BASE_URL}${endpoint}`,
      method,
      data,
      headers: {
        "Content-Type": "application/json",
      },
    });
    return response.data;
  } catch (error) {
    console.error("API Request Error:", error);
    throw new Error(error.response?.data?.error || "An error occurred");
  }
};

document.addEventListener("DOMContentLoaded", () => {
  const resultBox = document.getElementById("dna-generate-result");
  
  // Generate DNA Sequence
  document.getElementById("dna-generate-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById("file-input");
    const sampleId = document.getElementById("sample-id").value;

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('sample_id', sampleId);

    try {
      const response = await axios.post(`${API_BASE_URL}/dna/generate`, formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });
      resultBox.innerText = JSON.stringify(response.data, null, 2);
    } catch (error) {
      console.error("Error generating DNA:", error);
      resultBox.innerText = "Error generating DNA.";
    }
  });

  // Compare DNA Sequences
  document.getElementById("dna-compare-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId1 = document.getElementById("sample-id-1").value;
    const sampleId2 = document.getElementById("sample-id-2").value;

    try {
      const response = await handleApiRequest(`/dna/similarity/${sampleId1}/${sampleId2}`);
      document.getElementById("dna-compare-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error comparing DNA:", error);
      document.getElementById("dna-compare-result").innerText = "Error comparing DNA.";
    }
  });

  // Detect Mutations
  document.getElementById("mutation-detect-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("mutation-sample-id").value;

    try {
      const response = await handleApiRequest(`/dna/mutations/${sampleId}`);
      document.getElementById("mutation-detect-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error detecting mutations:", error);
      document.getElementById("mutation-detect-result").innerText = "Error detecting mutations.";
    }
  });

  // Retrieve DNA Family
  document.getElementById("family-retrieve-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const familyName = document.getElementById("family-name").value;

    try {
      const response = await handleApiRequest(`/dna/family/${familyName}`);
      document.getElementById("family-retrieve-result").innerText = JSON.stringify(response, null, 2);
    } catch (error) {
      console.error("Error retrieving DNA family:", error);
      document.getElementById("family-retrieve-result").innerText = "Error retrieving DNA family.";
    }
  });

  // Visualize DNA Graph
  document.getElementById("dna-visualization-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleFilename = document.getElementById("dna-sample-name").value;
    try {
      const response = await handleApiRequest(`/dna/similarity/${sampleFilename}`);
      document.getElementById("dna-visualization-result").innerText = JSON.stringify(response, null, 2);

      if (response.graph_data) {
        renderDNAGraph(response.graph_data);
      }
    } catch (error) {
      console.error("Error visualizing DNA:", error);
      document.getElementById("dna-visualization-result").innerText = "Error visualizing DNA.";
    }
  });

  // Render DNA Graph using D3.js
  function renderDNAGraph(graphData) {
    d3.select("#dna-graph-container").selectAll("*").remove();

    const svg = d3.select("#dna-graph-container")
      .append("svg")
      .attr("width", 800)
      .attr("height", 500);

    const simulation = d3.forceSimulation(graphData.nodes)
      .force("link", d3.forceLink(graphData.links).id(d => d.id))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(400, 250));

    const link = svg.append("g")
      .selectAll("line")
      .data(graphData.links)
      .enter()
      .append("line")
      .attr("stroke", "#ccc")
      .attr("stroke-width", 2);

    const node = svg.append("g")
      .selectAll("circle")
      .data(graphData.nodes)
      .enter()
      .append("circle")
      .attr("r", 10)
      .attr("fill", "#007bff")
      .call(drag(simulation));

    node.append("title")
      .text(d => `Node: ${d.id}\nLabel: ${d.label}`);

    simulation.on("tick", () => {
      link
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);

      node
        .attr("cx", d => d.x)
        .attr("cy", d => d.y);
    });
  }

  // Node drag functionality
  function drag(simulation) {
    function dragstarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    return d3.drag()
      .on("start", dragstarted)
      .on("drag", dragged)
      .on("end", dragended);
  }
});



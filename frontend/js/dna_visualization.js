document.addEventListener("DOMContentLoaded", () => {
  const api = new API(); // Assuming API class is defined in api.js

  // Visualize DNA Sequence
  document.getElementById("dna-visualization-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const sampleId = document.getElementById("dna-sample-id").value.trim();

    if (!sampleId) {
      document.getElementById("dna-visualization-result").innerText = "Please enter a valid Sample ID.";
      return;
    }

    try {
      const response = await api.get(`/api/dna/retrieve/${sampleId}`);

      document.getElementById("dna-visualization-result").innerText =
        "DNA Data Retrieved Successfully:\n" + JSON.stringify(response, null, 2);

      // Render DNA graph using D3.js
      if (response.graph_data) {
        renderDNAGraph(response.graph_data);
      } else {
        document.getElementById("dna-visualization-result").innerText += "\nNo graph data available.";
      }
    } catch (error) {
      console.error("Error visualizing DNA:", error);
      document.getElementById("dna-visualization-result").innerText =
        "❌ Error visualizing DNA. Please check the Sample ID or try again later.";
    }
  });

  // Render DNA Graph Using D3.js
  function renderDNAGraph(graphData) {
    // Clear previous graph
    d3.select("#dna-graph-container").selectAll("*").remove();

    const svg = d3.select("#dna-graph-container")
      .append("svg")
      .attr("width", 800)
      .attr("height", 500);

    const simulation = d3.forceSimulation(graphData.nodes)
      .force("link", d3.forceLink(graphData.links).id(d => d.id))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(400, 250));

    // Draw links
    const link = svg.append("g")
      .selectAll("line")
      .data(graphData.links)
      .enter()
      .append("line")
      .attr("stroke", "#ccc")
      .attr("stroke-width", 2);

    // Draw nodes
    const node = svg.append("g")
      .selectAll("circle")
      .data(graphData.nodes)
      .enter()
      .append("circle")
      .attr("r", 10)
      .attr("fill", "#007bff")
      .call(drag(simulation));

    // Add tooltips
    node.append("title")
      .text(d => `Node: ${d.id}\nLabel: ${d.label}`);

    // Update simulation
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

  // Drag Functionality for Nodes
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


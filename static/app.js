document.addEventListener("DOMContentLoaded", () => {
    // UI Elements
    const dbStatusBadge = document.getElementById("db-status-badge");
    const reconnectBtn = document.getElementById("reconnect-btn");
    const valAssets = document.getElementById("val-assets");
    const valVulns = document.getElementById("val-vulns");
    const valPaths = document.getElementById("val-paths");
    
    const tabBtns = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");
    
    // Path Finder
    const selectSource = document.getElementById("select-source");
    const selectTarget = document.getElementById("select-target");
    const btnFindPath = document.getElementById("btn-find-path");
    
    // Blast Radius
    const selectBlastSource = document.getElementById("select-blast-source");
    const rangeHops = document.getElementById("range-hops");
    const valHops = document.getElementById("val-hops");
    const btnBlastRadius = document.getElementById("btn-blast-radius");
    
    // Auditor
    const vulnerabilityList = document.getElementById("vulnerability-list");
    
    // Admin
    const btnSeedDb = document.getElementById("btn-seed-db");
    const activeUriVal = document.getElementById("active-uri-val");
    
    // Workspace & Overlay
    const workspaceTitle = document.getElementById("workspace-title");
    const graphOverlay = document.getElementById("graph-overlay");
    const overlayText = document.getElementById("overlay-text");
    const emptyState = document.getElementById("empty-state");
    
    // Graph Controls
    const btnZoomIn = document.getElementById("btn-zoom-in");
    const btnZoomOut = document.getElementById("btn-zoom-out");
    const btnFit = document.getElementById("btn-fit");
    const btnResetLayout = document.getElementById("btn-reset-layout");
    
    // Details Drawer
    const detailsDrawer = document.getElementById("details-drawer");
    const detailsTitle = document.getElementById("details-title");
    const detailsType = document.getElementById("details-type");
    const detailsCriticality = document.getElementById("details-criticality");
    const detailsTableBody = document.querySelector("#details-table tbody");
    const closeDrawerBtn = document.getElementById("close-drawer-btn");
    
    // Connection Error Modal
    const errorModal = document.getElementById("error-modal");
    const errorModalMessage = document.getElementById("error-modal-message");
    const modalRetryBtn = document.getElementById("modal-retry-btn");

    let cyInstance = null;
    let isConnected = false;

    // Initialize Lucide Icons
    lucide.createIcons();

    // Range hops value update
    rangeHops.addEventListener("input", (e) => {
        valHops.textContent = e.target.value;
    });

    // Close drawer
    closeDrawerBtn.addEventListener("click", () => {
        detailsDrawer.classList.add("hidden");
    });

    // Tab Switching Logic
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            tabBtns.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));
            
            btn.classList.add("active");
            const tabId = btn.getAttribute("data-tab");
            document.getElementById(`tab-${tabId}`).classList.add("active");
        });
    });

    // Check Database connection
    async function checkConnection() {
        showLoader("Checking connection...");
        try {
            const response = await fetch("/api/status");
            const data = await response.json();
            
            if (data.status === "connected") {
                isConnected = true;
                dbStatusBadge.className = "status-badge connected";
                dbStatusBadge.querySelector(".status-text").textContent = "Connected";
                activeUriVal.textContent = data.uri;
                errorModal.classList.add("hidden");
                hideLoader();
                return true;
            } else {
                throw new Error(data.error || "Failed to reach CognoDB Cloud.");
            }
        } catch (error) {
            isConnected = false;
            dbStatusBadge.className = "status-badge disconnected";
            dbStatusBadge.querySelector(".status-text").textContent = "Disconnected";
            errorModalMessage.textContent = error.message;
            errorModal.classList.remove("hidden");
            hideLoader();
            return false;
        }
    }

    // Load initial data
    async function initializeAppData() {
        if (!isConnected) return;
        
        await Promise.all([
            loadStats(),
            populateDropdowns(),
            loadAuditorFindings()
        ]);
    }

    // Load statistics
    async function loadStats() {
        try {
            const response = await fetch("/api/stats");
            if (!response.ok) throw new Error("Stats fetch failed");
            const data = await response.json();
            
            // Total assets (User, Group, Role, Compute, DataStore)
            let totalAssets = 0;
            if (data.nodes) {
                Object.entries(data.nodes).forEach(([label, cnt]) => {
                    if (["User", "Group", "Role", "Compute", "DataStore"].includes(label)) {
                        totalAssets += cnt;
                    }
                });
            }
            valAssets.textContent = totalAssets || 0;
            
            // Vulnerabilities
            const totalVulns = data.vulnerabilities?.total || 0;
            const criticalVulns = data.vulnerabilities?.critical || 0;
            valVulns.textContent = `${totalVulns} (${criticalVulns} Crit)`;
            
            // Critical attack paths
            valPaths.textContent = data.critical_paths_count ?? 0;
            
            if (data.critical_paths_count > 0) {
                document.getElementById("kpi-paths").querySelector(".kpi-icon-wrapper").classList.add("red");
                document.getElementById("kpi-paths").querySelector(".kpi-icon-wrapper").classList.remove("amber");
            } else {
                document.getElementById("kpi-paths").querySelector(".kpi-icon-wrapper").classList.add("amber");
                document.getElementById("kpi-paths").querySelector(".kpi-icon-wrapper").classList.remove("red");
            }
        } catch (error) {
            console.error("Error loading stats:", error);
        }
    }

    // Populate drop downs
    async function populateDropdowns() {
        try {
            const response = await fetch("/api/nodes");
            if (!response.ok) throw new Error("Nodes fetch failed");
            const nodes = await response.json();
            
            // Clear drop downs
            selectSource.innerHTML = '<option value="" disabled selected>Select starting asset...</option>';
            selectTarget.innerHTML = '<option value="" disabled selected>Select target asset...</option>';
            selectBlastSource.innerHTML = '<option value="" disabled selected>Select compromised asset...</option>';
            
            // Filter nodes by category for better selections
            nodes.sort((a, b) => a.name.localeCompare(b.name));
            
            nodes.forEach(node => {
                const optString = `${node.name} (${node.type})`;
                
                const opt1 = document.createElement("option");
                opt1.value = node.id;
                opt1.textContent = optString;
                selectSource.appendChild(opt1);
                
                const opt2 = document.createElement("option");
                opt2.value = node.id;
                opt2.textContent = optString;
                selectTarget.appendChild(opt2);
                
                const opt3 = document.createElement("option");
                opt3.value = node.id;
                opt3.textContent = optString;
                selectBlastSource.appendChild(opt3);
            });
        } catch (error) {
            console.error("Error populating selects:", error);
        }
    }

    // Load Auditor findings
    async function loadAuditorFindings() {
        try {
            const response = await fetch("/api/vulnerabilities");
            if (!response.ok) throw new Error("Vulnerabilities fetch failed");
            const findings = await response.json();
            
            vulnerabilityList.innerHTML = "";
            if (findings.length === 0) {
                vulnerabilityList.innerHTML = `
                    <div class="empty-state-static">
                        <i data-lucide="check-circle" style="color: var(--neon-emerald); width: 36px; height: 36px;"></i>
                        <p>No critical privilege escalation chains found.</p>
                    </div>
                `;
                lucide.createIcons();
                return;
            }
            
            findings.forEach(finding => {
                const card = document.createElement("div");
                card.className = "finding-card";
                
                const scoreClass = finding.score >= 9.0 ? "critical" : "high";
                
                card.innerHTML = `
                    <div class="finding-header">
                        <span class="finding-cve">${finding.cve}</span>
                        <span class="finding-score ${scoreClass}">${finding.score.toFixed(1)} ${finding.severity}</span>
                    </div>
                    <div class="finding-title">${finding.vuln_name}</div>
                    <p class="tab-description" style="font-size:0.75rem; margin-top:0.25rem;">Exposes: <strong>${finding.compute}</strong></p>
                    <div class="finding-chain">
                        <span class="finding-chain-node compute">${finding.compute}</span>
                        <span class="finding-chain-arrow">&rarr;</span>
                        <span class="finding-chain-node role">${finding.role_name}</span>
                        <span class="finding-chain-arrow">&rarr;</span>
                        <span class="finding-chain-node datastore">${finding.datastore}</span>
                    </div>
                `;
                
                // Add event listener to visualize this path on click
                card.addEventListener("click", () => {
                    workspaceTitle.textContent = `Attack Vector: Exploiting ${finding.cve} to reach ${finding.datastore}`;
                    visualizePath(finding.compute_id, finding.datastore_id);
                });
                
                vulnerabilityList.appendChild(card);
            });
            
            lucide.createIcons();
        } catch (error) {
            vulnerabilityList.innerHTML = `<p style="color:var(--neon-red);">Query failed: ${error.message}</p>`;
        }
    }

    // Helper functions for loaders
    function showLoader(text = "Running Cypher query...") {
        overlayText.textContent = text;
        graphOverlay.classList.remove("hidden");
    }
    
    function hideLoader() {
        graphOverlay.classList.add("hidden");
    }

    // Init Cytoscape configuration
    function initCytoscape(elements) {
        emptyState.classList.add("hidden");
        
        if (cyInstance) {
            cyInstance.destroy();
        }
        
        cyInstance = cytoscape({
            container: document.getElementById('cy'),
            elements: elements,
            style: [
                {
                    selector: 'node',
                    style: {
                        'label': 'data(label)',
                        'font-family': 'Outfit, sans-serif',
                        'font-size': '11px',
                        'color': '#f8fafc',
                        'text-valign': 'bottom',
                        'text-margin-y': 8,
                        'text-background-opacity': 0.8,
                        'text-background-color': '#0d1324',
                        'text-background-padding': '3px 6px',
                        'text-background-shape': 'roundrectangle',
                        'text-background-border-width': 1,
                        'text-background-border-color': 'rgba(255,255,255,0.05)',
                        'background-color': '#64748b',
                        'width': 38,
                        'height': 38,
                        'border-width': 2,
                        'border-color': 'rgba(255, 255, 255, 0.15)',
                        'overlay-padding': '5px',
                        'overlay-opacity': 0,
                        'transition-property': 'background-color, border-color, border-width',
                        'transition-duration': '0.2s'
                    }
                },
                {
                    selector: 'node[type="User"]',
                    style: {
                        'background-color': '#2563eb', // blue
                        'shape': 'ellipse',
                        'border-color': '#3b82f6'
                    }
                },
                {
                    selector: 'node[type="Group"]',
                    style: {
                        'background-color': '#7c3aed', // purple
                        'shape': 'hexagon',
                        'border-color': '#8b5cf6'
                    }
                },
                {
                    selector: 'node[type="Role"]',
                    style: {
                        'background-color': '#d97706', // amber
                        'shape': 'diamond',
                        'border-color': '#f59e0b'
                    }
                },
                {
                    selector: 'node[type="Compute"]',
                    style: {
                        'background-color': '#059669', // green
                        'shape': 'round-rectangle',
                        'border-color': '#10b981'
                    }
                },
                {
                    selector: 'node[type="DataStore"]',
                    style: {
                        'background-color': '#db2777', // pink
                        'shape': 'cylinder',
                        'border-color': '#ec4899'
                    }
                },
                {
                    selector: 'node[type="Vulnerability"]',
                    style: {
                        'background-color': '#dc2626', // red
                        'shape': 'hexagon',
                        'border-color': '#ef4444',
                        'border-width': 3
                    }
                },
                {
                    selector: 'node[criticality="High"]',
                    style: {
                        'width': 46,
                        'height': 46,
                        'border-width': 3,
                        'border-color': '#f43f5e'
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'label': 'data(label)',
                        'font-family': 'JetBrains Mono, monospace',
                        'font-size': '8px',
                        'color': '#94a3b8',
                        'text-background-opacity': 0.85,
                        'text-background-color': '#070b14',
                        'text-background-padding': '2px 4px',
                        'text-background-shape': 'roundrectangle',
                        'text-rotation': 'autorotate',
                        'curve-style': 'bezier',
                        'target-arrow-shape': 'triangle',
                        'line-color': 'rgba(255, 255, 255, 0.15)',
                        'target-arrow-color': 'rgba(255, 255, 255, 0.15)',
                        'width': 1.5,
                        'arrow-scale': 0.8,
                        'transition-property': 'line-color, target-arrow-color, width',
                        'transition-duration': '0.2s'
                    }
                },
                // Attack route highlighting
                {
                    selector: 'edge[label="VULNERABLE_TO"], edge[label="EXPLOIT_LEADS_TO"]',
                    style: {
                        'line-color': 'rgba(239, 68, 68, 0.35)',
                        'target-arrow-color': 'rgba(239, 68, 68, 0.35)'
                    }
                },
                {
                    selector: 'edge[label="HAS_ACCESS"]',
                    style: {
                        'line-color': 'rgba(236, 72, 153, 0.35)',
                        'target-arrow-color': 'rgba(236, 72, 153, 0.35)'
                    }
                },
                {
                    selector: 'node:selected',
                    style: {
                        'border-color': '#00f2fe',
                        'border-width': 4
                    }
                },
                {
                    selector: 'edge:selected',
                    style: {
                        'line-color': '#00f2fe',
                        'target-arrow-color': '#00f2fe',
                        'width': 3.5
                    }
                }
            ],
            layout: {
                name: 'dagre',
                rankDir: 'LR', // Left to Right flows
                nodeSep: 60,
                rankSep: 100,
                animate: true,
                animationDuration: 400
            }
        });

        // Set up drawer events
        cyInstance.on('tap', 'node, edge', (evt) => {
            const item = evt.target;
            const data = item.data();
            showDetails(data);
        });

        cyInstance.on('tap', (evt) => {
            if (evt.target === cyInstance) {
                detailsDrawer.classList.add("hidden");
            }
        });
    }

    // Redraw layout
    btnResetLayout.addEventListener("click", () => {
        if (cyInstance) {
            cyInstance.layout({
                name: 'dagre',
                rankDir: 'LR',
                nodeSep: 60,
                rankSep: 100,
                animate: true,
                animationDuration: 400
            }).run();
        }
    });

    // Zooming & Fit
    btnZoomIn.addEventListener("click", () => {
        if (cyInstance) cyInstance.zoom(cyInstance.zoom() * 1.2);
    });
    btnZoomOut.addEventListener("click", () => {
        if (cyInstance) cyInstance.zoom(cyInstance.zoom() / 1.2);
    });
    btnFit.addEventListener("click", () => {
        if (cyInstance) cyInstance.fit(50);
    });

    // Show details of clicked element in Drawer
    function showDetails(data) {
        detailsDrawer.classList.remove("hidden");
        
        const label = data.label;
        const details = data.details || {};
        
        detailsTitle.textContent = label;
        
        if (data.source && data.target) {
            // It's an edge
            detailsType.textContent = "RELATIONSHIP";
            detailsType.className = "prop-badge";
            detailsCriticality.classList.add("hidden");
        } else {
            // It's a node
            detailsType.textContent = data.type;
            detailsType.className = `prop-badge`;
            
            detailsCriticality.classList.remove("hidden");
            detailsCriticality.textContent = `Criticality: ${data.criticality || 'Low'}`;
            detailsCriticality.className = `prop-badge criticality-${data.criticality || 'Low'}`;
        }
        
        // Build table
        detailsTableBody.innerHTML = "";
        
        // Display core fields first
        if (data.source && data.target) {
            addPropertyRow("Type", label);
            addPropertyRow("From Node ID", data.source);
            addPropertyRow("To Node ID", data.target);
        } else {
            addPropertyRow("Asset ID", data.id);
            addPropertyRow("Asset Type", data.type);
        }
        
        // Dynamic custom fields
        Object.entries(details).forEach(([key, val]) => {
            // Ignore standard properties we already displayed or internally generated ones
            if (["id", "name", "type", "criticality", "cve"].includes(key)) return;
            
            if (Array.isArray(val)) {
                addPropertyRow(key, val.join(", "));
            } else if (typeof val === 'object' && val !== null) {
                addPropertyRow(key, JSON.stringify(val));
            } else {
                addPropertyRow(key, val);
            }
        });
    }

    function addPropertyRow(name, val) {
        // Humanize key name
        const displayName = name.split("_").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
        
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="prop-name">${displayName}</td>
            <td class="prop-val">${val}</td>
        `;
        detailsTableBody.appendChild(tr);
    }

    // Visualize Attack path API call
    async function visualizePath(src, dst) {
        showLoader("Searching attack vectors...");
        detailsDrawer.classList.add("hidden");
        try {
            const response = await fetch(`/api/path?source=${encodeURIComponent(src)}&target=${encodeURIComponent(dst)}`);
            if (!response.ok) throw new Error("Path-finding query failed");
            const data = await response.json();
            
            hideLoader();
            
            if (!data.nodes || data.nodes.length === 0) {
                alert(data.message || "No attack path found between these nodes.");
                return;
            }
            
            initCytoscape(data);
            
            // Highlight source and target specifically
            cyInstance.$(`#${src}`).style({
                'border-color': '#00f2fe',
                'border-width': 4,
                'width': 52,
                'height': 52
            });
            cyInstance.$(`#${dst}`).style({
                'border-color': '#ff2e93',
                'border-width': 4,
                'width': 52,
                'height': 52
            });
            
            // Highlight everything as path flow
            cyInstance.edges().addClass('highlighted');
            
        } catch (error) {
            hideLoader();
            alert(`Query Failed: ${error.message}`);
        }
    }

    // Path Finder Trace Button Trigger
    btnFindPath.addEventListener("click", () => {
        const src = selectSource.value;
        const dst = selectTarget.value;
        
        if (!src || !dst) {
            alert("Please select both a source asset and a target asset.");
            return;
        }
        
        if (src === dst) {
            alert("Source and target assets must be different.");
            return;
        }
        
        const srcText = selectSource.options[selectSource.selectedIndex].text;
        const dstText = selectTarget.options[selectTarget.selectedIndex].text;
        workspaceTitle.textContent = `Attack Path: ${srcText.split(' (')[0]} → ${dstText.split(' (')[0]}`;
        
        visualizePath(src, dst);
    });

    // Blast Radius assessment trigger
    btnBlastRadius.addEventListener("click", async () => {
        const src = selectBlastSource.value;
        const hops = rangeHops.value;
        
        if (!src) {
            alert("Please select a compromised node to evaluate.");
            return;
        }
        
        showLoader(`Evaluating blast radius (${hops} hops)...`);
        detailsDrawer.classList.add("hidden");
        
        const srcText = selectBlastSource.options[selectBlastSource.selectedIndex].text;
        workspaceTitle.textContent = `Blast Radius Analysis: ${srcText.split(' (')[0]} (${hops} Hops)`;
        
        try {
            const response = await fetch(`/api/status`);
            const statusData = await response.json();
            if (statusData.status !== "connected") throw new Error("Database offline");
            
            const radiusResponse = await fetch(`/api/blast-radius?source=${encodeURIComponent(src)}&hops=${hops}`);
            if (!radiusResponse.ok) throw new Error("Blast radius query failed");
            const data = await radiusResponse.json();
            
            hideLoader();
            
            if (!data.nodes || data.nodes.length === 0) {
                alert("Exploded node not found or has no connections.");
                return;
            }
            
            initCytoscape(data);
            
            // Highlight compromised source node
            cyInstance.$(`#${src}`).style({
                'background-color': '#dc2626', // Red compromise color
                'border-color': '#ff2e93',
                'border-width': 4,
                'width': 54,
                'height': 54
            });
            
            // Add custom label to show compromise
            const currentLabel = cyInstance.$(`#${src}`).data('label');
            cyInstance.$(`#${src}`).data('label', `🔥 COMPROMISED: ${currentLabel}`);
            
            // Show alert if message returned
            if (data.message) {
                alert(data.message);
            }
        } catch (error) {
            hideLoader();
            alert(`Query Failed: ${error.message}`);
        }
    });

    // Seeding trigger
    btnSeedDb.addEventListener("click", async () => {
        if (!confirm("Are you sure you want to clean the graph database and reload the default cloud security mock data?")) return;
        
        showLoader("Clearing & seeding database...");
        try {
            const response = await fetch("/api/seed", { method: "POST" });
            const data = await response.json();
            
            hideLoader();
            if (data.success) {
                alert(data.message);
                
                // Reset visual workspace
                if (cyInstance) {
                    cyInstance.destroy();
                    cyInstance = null;
                }
                emptyState.classList.remove("hidden");
                workspaceTitle.textContent = "Active Security Topology";
                detailsDrawer.classList.add("hidden");
                
                // Re-initialize lists & drops
                await initializeAppData();
            } else {
                throw new Error(data.error || "Failed to seed.");
            }
        } catch (error) {
            hideLoader();
            alert(`Error: Seeding failed. ${error.message}`);
        }
    });

    // Header reconnect button
    reconnectBtn.addEventListener("click", async () => {
        const ok = await checkConnection();
        if (ok) {
            await initializeAppData();
            alert("Database reconnected successfully!");
        }
    });

    // Modal Retry Button
    modalRetryBtn.addEventListener("click", async () => {
        const ok = await checkConnection();
        if (ok) {
            await initializeAppData();
        } else {
            alert("Unable to connect. Please ensure your credentials are set correctly in .env.");
        }
    });

    // Main Startup trigger
    async function start() {
        const connected = await checkConnection();
        if (connected) {
            await initializeAppData();
        }
    }

    start();
});

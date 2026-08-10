#!/usr/bin/env python3
import os
from flask import Flask, jsonify, request, send_from_directory
from dotenv import load_dotenv
from neo4j import GraphDatabase
from seed import seed_database

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='static', static_url_path='')

COGNODB_URI = os.getenv("COGNODB_URI")
COGNODB_USER = os.getenv("COGNODB_USER", "cognodb")
COGNODB_PASSWORD = os.getenv("COGNODB_PASSWORD")
PORT = int(os.getenv("PORT", 5001))

# Global driver variable
driver = None

def get_driver():
    global driver
    if driver is not None:
        return driver
    
    if not COGNODB_URI or not COGNODB_PASSWORD:
        return None
    
    try:
        driver = GraphDatabase.driver(COGNODB_URI, auth=(COGNODB_USER, COGNODB_PASSWORD))
        driver.verify_connectivity()
        return driver
    except Exception as e:
        print(f"Error connecting to CognoDB: {e}")
        driver = None
        return None

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    drv = get_driver()
    if drv is None:
        return jsonify({
            "status": "disconnected",
            "error": "Database unreachable. Please check if COGNODB_URI and COGNODB_PASSWORD are correct and set in your .env file."
        })
    return jsonify({
        "status": "connected",
        "uri": COGNODB_URI
    })

@app.route('/api/seed', methods=['POST'])
def trigger_seed():
    if not COGNODB_URI or not COGNODB_PASSWORD:
        return jsonify({
            "success": False,
            "error": "Database credentials are not configured."
        }), 400
    
    try:
        seed_database()
        return jsonify({
            "success": True,
            "message": "Database seeded successfully!"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    drv = get_driver()
    if drv is None:
        return jsonify({"error": "Database disconnected"}), 503

    try:
        with drv.session() as session:
            # 1. Total nodes count
            node_counts = session.run("MATCH (n) RETURN labels(n)[0] as label, count(n) as count").data()
            node_stats = {row['label']: row['count'] for row in node_counts if row['label']}
            
            # 2. Total relationships count
            rel_counts = session.run("MATCH ()-[r]->() RETURN type(r) as type, count(r) as count").data()
            rel_stats = {row['type']: row['count'] for row in rel_counts}
            
            # 3. Total critical vulnerabilities
            vuln_stats = session.run(
                "MATCH (v:Vulnerability) RETURN count(v) as total, sum(case when v.severity = 'Critical' then 1 else 0 end) as critical"
            ).single()
            
            total_vulns = vuln_stats["total"] if vuln_stats else 0
            critical_vulns = vuln_stats["critical"] if vuln_stats else 0

            # 4. Count of paths to high criticality assets (critical attack vectors)
            critical_paths = session.run(
                "MATCH p=shortestPath((c:Compute)-[:VULNERABLE_TO|EXPLOIT_LEADS_TO|ASSUMES|HAS_ACCESS|RUNS_AS*1..8]->(d:DataStore {criticality: 'High'})) RETURN count(p) as count"
            ).single()["count"]

            return jsonify({
                "nodes": node_stats,
                "relationships": rel_stats,
                "vulnerabilities": {
                    "total": total_vulns,
                    "critical": critical_vulns
                },
                "critical_paths_count": critical_paths
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/nodes', methods=['GET'])
def get_nodes():
    drv = get_driver()
    if drv is None:
        return jsonify({"error": "Database disconnected"}), 503

    try:
        with drv.session() as session:
            result = session.run("MATCH (n) RETURN n.id as id, n.name as name, labels(n) as labels, n.criticality as criticality")
            nodes = []
            for r in result:
                # Primary label is the first label that is not "Asset"
                labels = r["labels"]
                primary_label = labels[0] if labels else "Unknown"
                if len(labels) > 1 and primary_label == "Asset":
                    primary_label = labels[1]
                elif len(labels) > 1 and labels[1] != "Asset":
                    primary_label = labels[1]

                nodes.append({
                    "id": r["id"],
                    "name": r["name"] or r["id"],
                    "type": primary_label,
                    "criticality": r["criticality"] or "Low"
                })
            return jsonify(nodes)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def parse_paths_to_cytoscape(records):
    cytoscape_nodes = {}
    cytoscape_edges = {}

    for record in records:
        path = record["p"]
        for node in path.nodes:
            node_id = node.get("id") or node.element_id
            labels = list(node.labels)
            primary_label = labels[0] if labels else "Unknown"
            if len(labels) > 1 and primary_label == "Asset":
                primary_label = labels[1]
            
            cytoscape_nodes[node_id] = {
                "data": {
                    "id": node_id,
                    "label": node.get("name") or node.get("cve") or node_id,
                    "type": primary_label,
                    "criticality": node.get("criticality", "Low"),
                    "details": dict(node)
                }
            }

        for rel in path.relationships:
            rel_id = rel.element_id
            start_id = rel.start_node.get("id") or rel.start_node.element_id
            end_id = rel.end_node.get("id") or rel.end_node.element_id
            
            cytoscape_edges[rel_id] = {
                "data": {
                    "id": rel_id,
                    "source": start_id,
                    "target": end_id,
                    "label": rel.type,
                    "details": dict(rel)
                }
            }

    return {
        "nodes": list(cytoscape_nodes.values()),
        "edges": list(cytoscape_edges.values())
    }

@app.route('/api/path', methods=['GET'])
def get_path():
    source = request.args.get('source')
    target = request.args.get('target')

    if not source or not target:
        return jsonify({"error": "Missing source or target parameter"}), 400

    drv = get_driver()
    if drv is None:
        return jsonify({"error": "Database disconnected"}), 503

    try:
        with drv.session() as session:
            # Cypher shortest path query spanning multiple potential relationships
            query = """
            MATCH (src {id: $source}), (dst {id: $target})
            MATCH p = shortestPath((src)-[:MEMBER_OF|ASSUMES|HAS_ACCESS|RUNS_AS|ACCESSIBLE_FROM|VULNERABLE_TO|EXPLOIT_LEADS_TO*1..15]->(dst))
            RETURN p
            """
            result = session.run(query, source=source, target=target)
            records = list(result)
            
            if not records:
                return jsonify({"nodes": [], "edges": [], "message": "No attack path found between these assets."})

            graph_data = parse_paths_to_cytoscape(records)
            return jsonify(graph_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/blast-radius', methods=['GET'])
def get_blast_radius():
    source = request.args.get('source')
    hops = int(request.args.get('hops', 3))

    if not source:
        return jsonify({"error": "Missing source parameter"}), 400

    if hops < 1 or hops > 4:
        return jsonify({"error": "Hops parameter must be between 1 and 4"}), 400

    drv = get_driver()
    if drv is None:
        return jsonify({"error": "Database disconnected"}), 503

    try:
        with drv.session() as session:
            # Find all paths from source up to 'hops' hops
            query = f"""
            MATCH (src {{id: $source}})
            MATCH p = (src)-[:MEMBER_OF|ASSUMES|HAS_ACCESS|RUNS_AS|ACCESSIBLE_FROM|VULNERABLE_TO|EXPLOIT_LEADS_TO*1..{hops}]->(dst)
            RETURN p
            """
            result = session.run(query, source=source)
            records = list(result)

            if not records:
                # Return just the source node
                source_query = "MATCH (src {id: $source}) RETURN src"
                src_node_res = session.run(source_query, source=source).single()
                if not src_node_res:
                    return jsonify({"error": f"Node with id '{source}' not found."}), 404
                
                node = src_node_res["src"]
                labels = list(node.labels)
                primary_label = labels[0] if labels else "Unknown"
                if len(labels) > 1 and primary_label == "Asset":
                    primary_label = labels[1]
                
                return jsonify({
                    "nodes": [{
                        "data": {
                            "id": source,
                            "label": node.get("name") or source,
                            "type": primary_label,
                            "criticality": node.get("criticality", "Low"),
                            "details": dict(node)
                        }
                    }],
                    "edges": [],
                    "message": "No outgoing connections found. Blast radius is limited to this asset."
                })

            graph_data = parse_paths_to_cytoscape(records)
            return jsonify(graph_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities_audit():
    drv = get_driver()
    if drv is None:
        return jsonify({"error": "Database disconnected"}), 503

    try:
        with drv.session() as session:
            # Query for attack vectors where a Compute has a vulnerability that leads to a Role that has access to a DataStore
            query = """
            MATCH (c:Compute)-[:VULNERABLE_TO]->(v:Vulnerability)-[:EXPLOIT_LEADS_TO]->(r:Role)-[:HAS_ACCESS]->(ds:DataStore)
            RETURN c.name as compute, c.id as compute_id,
                   v.cve as cve, v.severity as severity, v.score as score, v.name as vuln_name,
                   r.name as role_name, r.id as role_id,
                   ds.name as datastore, ds.id as datastore_id, ds.criticality as datastore_criticality
            ORDER BY v.score DESC
            """
            result = session.run(query)
            findings = []
            for r in result:
                findings.append({
                    "compute": r["compute"],
                    "compute_id": r["compute_id"],
                    "cve": r["cve"],
                    "severity": r["severity"],
                    "score": r["score"],
                    "vuln_name": r["vuln_name"],
                    "role_name": r["role_name"],
                    "role_id": r["role_id"],
                    "datastore": r["datastore"],
                    "datastore_id": r["datastore_id"],
                    "datastore_criticality": r["datastore_criticality"]
                })
            return jsonify(findings)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print(f"Starting AegisGraph Server on port {PORT}...")
    app.run(host='0.0.0.0', port=PORT, debug=True)

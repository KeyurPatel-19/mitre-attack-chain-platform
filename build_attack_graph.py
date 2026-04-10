import json
from pathlib import Path
import networkx as nx

PROJECT_DIR = Path("/Users/hely/Desktop/YT2_mitre_attack_chain_platform")
DATA_DIR = PROJECT_DIR / "Data"
PROCESSED_DIR = DATA_DIR / "processed_data"
GRAPH_DIR = DATA_DIR / "graphs"

GRAPH_DIR.mkdir(parents=True, exist_ok=True)

GRAPH_TARGETS = {
    "enterprise": (
        PROCESSED_DIR / "enterprise_nodes.json",
        PROCESSED_DIR / "enterprise_edges.json",
        GRAPH_DIR / "enterprise_attack_graph.graphml"
    ),
    "ics": (
        PROCESSED_DIR / "ics_nodes.json",
        PROCESSED_DIR / "ics_edges.json",
        GRAPH_DIR / "ics_attack_graph.graphml"
    ),
    "mobile": (
        PROCESSED_DIR / "mobile_nodes.json",
        PROCESSED_DIR / "mobile_edges.json",
        GRAPH_DIR / "mobile_attack_graph.graphml"
    ),
    "combined": (
        PROCESSED_DIR / "combined_nodes.json",
        PROCESSED_DIR / "combined_edges.json",
        GRAPH_DIR / "combined_attack_graph.graphml"
    )
}

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def safe_value(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return " | ".join(str(v) for v in value if v is not None)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)

def build_graph(nodes_file, edges_file, output_file):
    if not nodes_file.exists() or not edges_file.exists():
        print(f"[WARNING] Missing files for graph: {nodes_file} or {edges_file}")
        return

    nodes = load_json(nodes_file)
    edges = load_json(edges_file)

    G = nx.DiGraph()

    for node in nodes:
        node_id = node.get("id")
        if not node_id:
            continue

        G.add_node(
            node_id,
            name=safe_value(node.get("name")),
            type=safe_value(node.get("type")),
            external_id=safe_value(node.get("external_id")),
            dataset=safe_value(node.get("dataset")),
            platforms=safe_value(node.get("platforms")),
            domains=safe_value(node.get("domains")),
            tactics=safe_value(node.get("tactics"))
        )

    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")

        if not source or not target:
            continue

        G.add_edge(
            source,
            target,
            relationship=safe_value(edge.get("type")),
            dataset=safe_value(edge.get("dataset"))
        )

    nx.write_graphml(G, output_file, encoding="utf-8")

    print("=" * 70)
    print(f"Graph built successfully: {output_file.name}")
    print("=" * 70)
    print(f"Nodes: {G.number_of_nodes()}")
    print(f"Edges: {G.number_of_edges()}")
    print(f"Saved to: {output_file}")
    print()

def main():
    for name, (nodes_file, edges_file, output_file) in GRAPH_TARGETS.items():
        build_graph(nodes_file, edges_file, output_file)

if __name__ == "__main__":
    main()
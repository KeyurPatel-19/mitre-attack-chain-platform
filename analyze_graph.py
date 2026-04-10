import json
from pathlib import Path
from collections import Counter
import networkx as nx
import pandas as pd

PROJECT_DIR = Path("/Users/hely/Desktop/YT2_mitre_attack_chain_platform")
DATA_DIR = PROJECT_DIR / "Data"
PROCESSED_DIR = DATA_DIR / "processed_data"
ANALYSIS_DIR = DATA_DIR / "analysis"

ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

GRAPH_INPUTS = {
    "enterprise": (
        PROCESSED_DIR / "enterprise_nodes.json",
        PROCESSED_DIR / "enterprise_edges.json"
    ),
    "ics": (
        PROCESSED_DIR / "ics_nodes.json",
        PROCESSED_DIR / "ics_edges.json"
    ),
    "mobile": (
        PROCESSED_DIR / "mobile_nodes.json",
        PROCESSED_DIR / "mobile_edges.json"
    ),
    "combined": (
        PROCESSED_DIR / "combined_nodes.json",
        PROCESSED_DIR / "combined_edges.json"
    )
}


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_graph(nodes, edges):
    G = nx.DiGraph()

    for node in nodes:
        node_id = node.get("id")
        if not node_id:
            continue
        G.add_node(node_id, **node)

    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")
        if not source or not target:
            continue
        if source in G.nodes and target in G.nodes:
            G.add_edge(source, target, **edge)

    return G


def safe_top_dict(metric_dict, top_n=20):
    return sorted(metric_dict.items(), key=lambda x: x[1], reverse=True)[:top_n]


def run_analysis(dataset_name, nodes_path, edges_path):
    if not nodes_path.exists() or not edges_path.exists():
        print(f"[WARNING] Missing processed files for {dataset_name}")
        return

    nodes = load_json(nodes_path)
    edges = load_json(edges_path)
    G = build_graph(nodes, edges)

    if G.number_of_nodes() == 0:
        print(f"[WARNING] Graph is empty for {dataset_name}")
        return

    UG = G.to_undirected()

    # -------------------------
    # Basic metrics
    # -------------------------
    degree_centrality = nx.degree_centrality(G)
    in_degree_centrality = nx.in_degree_centrality(G)
    out_degree_centrality = nx.out_degree_centrality(G)
    betweenness_centrality = nx.betweenness_centrality(G, k=min(100, G.number_of_nodes()), normalized=True)
    closeness_centrality = nx.closeness_centrality(G)

    # -------------------------
    # Communities
    # -------------------------
    try:
        communities = list(nx.community.greedy_modularity_communities(UG))
    except Exception:
        communities = []

    community_map = {}
    for idx, community in enumerate(communities):
        for node_id in community:
            community_map[node_id] = idx

    # -------------------------
    # Node analysis table
    # -------------------------
    node_rows = []
    for node_id, attrs in G.nodes(data=True):
        node_rows.append({
            "id": node_id,
            "name": attrs.get("name", ""),
            "type": attrs.get("type", ""),
            "external_id": attrs.get("external_id", ""),
            "dataset": attrs.get("dataset", ""),
            "platforms": " | ".join(attrs.get("platforms", [])) if isinstance(attrs.get("platforms"), list) else "",
            "domains": " | ".join(attrs.get("domains", [])) if isinstance(attrs.get("domains"), list) else "",
            "tactics": " | ".join(attrs.get("tactics", [])) if isinstance(attrs.get("tactics"), list) else "",
            "in_degree": G.in_degree(node_id),
            "out_degree": G.out_degree(node_id),
            "total_degree": G.degree(node_id),
            "degree_centrality": degree_centrality.get(node_id, 0.0),
            "in_degree_centrality": in_degree_centrality.get(node_id, 0.0),
            "out_degree_centrality": out_degree_centrality.get(node_id, 0.0),
            "betweenness_centrality": betweenness_centrality.get(node_id, 0.0),
            "closeness_centrality": closeness_centrality.get(node_id, 0.0),
            "community_id": community_map.get(node_id, -1)
        })

    node_df = pd.DataFrame(node_rows)

    # -------------------------
    # Summary
    # -------------------------
    summary = {
        "dataset": dataset_name,
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "density": nx.density(G),
        "weakly_connected_components": nx.number_weakly_connected_components(G),
        "strongly_connected_components": nx.number_strongly_connected_components(G),
        "community_count": len(communities),
        "node_type_counts": dict(Counter([attrs.get("type", "UNKNOWN") for _, attrs in G.nodes(data=True)])),
        "top_degree_centrality": safe_top_dict(degree_centrality),
        "top_betweenness_centrality": safe_top_dict(betweenness_centrality),
        "top_closeness_centrality": safe_top_dict(closeness_centrality)
    }

    # -------------------------
    # Save files
    # -------------------------
    node_output = ANALYSIS_DIR / f"{dataset_name}_node_analysis.csv"
    summary_output = ANALYSIS_DIR / f"{dataset_name}_graph_summary.json"

    node_df.to_csv(node_output, index=False)

    with open(summary_output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("=" * 70)
    print(f"[DONE] Graph analysis completed for: {dataset_name}")
    print(f"[DONE] Node analysis saved: {node_output}")
    print(f"[DONE] Summary saved: {summary_output}")
    print(f"[INFO] Nodes: {G.number_of_nodes()} | Edges: {G.number_of_edges()}")
    print()


def main():
    for dataset_name, (nodes_path, edges_path) in GRAPH_INPUTS.items():
        run_analysis(dataset_name, nodes_path, edges_path)


if __name__ == "__main__":
    main()
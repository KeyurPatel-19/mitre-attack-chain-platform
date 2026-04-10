from pathlib import Path
import pandas as pd
import json

PROJECT_DIR = Path("/Users/hely/Desktop/YT2_mitre_attack_chain_platform")
DATA_DIR = PROJECT_DIR / "Data"

PROCESSED_DIR = DATA_DIR / "processed_data"
ANALYSIS_DIR = DATA_DIR / "analysis"
ML_DIR = DATA_DIR / "ml_results"
DASHBOARD_DIR = DATA_DIR / "dashboard_data"

DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)

TARGETS = {
    "enterprise": {
        "nodes": PROCESSED_DIR / "enterprise_nodes.json",
        "edges": PROCESSED_DIR / "enterprise_edges.json",
        "analysis": ANALYSIS_DIR / "enterprise_node_analysis.csv",
        "ml": ML_DIR / "enterprise_ml_results.csv"
    },
    "ics": {
        "nodes": PROCESSED_DIR / "ics_nodes.json",
        "edges": PROCESSED_DIR / "ics_edges.json",
        "analysis": ANALYSIS_DIR / "ics_node_analysis.csv",
        "ml": ML_DIR / "ics_ml_results.csv"
    },
    "mobile": {
        "nodes": PROCESSED_DIR / "mobile_nodes.json",
        "edges": PROCESSED_DIR / "mobile_edges.json",
        "analysis": ANALYSIS_DIR / "mobile_node_analysis.csv",
        "ml": ML_DIR / "mobile_ml_results.csv"
    },
    "combined": {
        "nodes": PROCESSED_DIR / "combined_nodes.json",
        "edges": PROCESSED_DIR / "combined_edges.json",
        "analysis": ANALYSIS_DIR / "combined_node_analysis.csv",
        "ml": ML_DIR / "combined_ml_results.csv"
    }
}


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def prepare_target(dataset_name, files):
    missing = [str(path) for path in files.values() if not path.exists()]
    if missing:
        print(f"[WARNING] Missing files for {dataset_name}:")
        for item in missing:
            print(f"  - {item}")
        return

    nodes_df = pd.DataFrame(load_json(files["nodes"]))
    edges_df = pd.DataFrame(load_json(files["edges"]))
    analysis_df = pd.read_csv(files["analysis"])
    ml_df = pd.read_csv(files["ml"])

    # Merge node + analysis + ML
    merged_df = analysis_df.merge(
        ml_df[["id", "cluster_id", "is_anomaly", "pca_x", "pca_y"]],
        on="id",
        how="left"
    )

    nodes_output = DASHBOARD_DIR / f"{dataset_name}_dashboard_nodes.csv"
    edges_output = DASHBOARD_DIR / f"{dataset_name}_dashboard_edges.csv"
    summary_output = DASHBOARD_DIR / f"{dataset_name}_dashboard_summary.json"

    merged_df.to_csv(nodes_output, index=False)
    edges_df.to_csv(edges_output, index=False)

    summary = {
        "dataset": dataset_name,
        "node_count": int(len(merged_df)),
        "edge_count": int(len(edges_df)),
        "cluster_count": int(merged_df["cluster_id"].nunique()) if "cluster_id" in merged_df.columns else 0,
        "anomaly_count": int(merged_df["is_anomaly"].fillna(0).sum()) if "is_anomaly" in merged_df.columns else 0,
        "datasets_present": sorted(merged_df["dataset"].dropna().unique().tolist()) if "dataset" in merged_df.columns else []
    }

    with open(summary_output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("=" * 70)
    print(f"[DONE] Dashboard data prepared for: {dataset_name}")
    print(f"[DONE] Nodes file: {nodes_output}")
    print(f"[DONE] Edges file: {edges_output}")
    print(f"[DONE] Summary file: {summary_output}")
    print()


def main():
    for dataset_name, files in TARGETS.items():
        prepare_target(dataset_name, files)


if __name__ == "__main__":
    main()
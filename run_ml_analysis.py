from pathlib import Path
import json
import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA

PROJECT_DIR = Path("/Users/hely/Desktop/YT2_mitre_attack_chain_platform")
DATA_DIR = PROJECT_DIR / "Data"
FEATURES_DIR = DATA_DIR / "features"
ML_DIR = DATA_DIR / "ml_results"

ML_DIR.mkdir(parents=True, exist_ok=True)

INPUT_FILES = {
    "enterprise": FEATURES_DIR / "enterprise_features.csv",
    "ics": FEATURES_DIR / "ics_features.csv",
    "mobile": FEATURES_DIR / "mobile_features.csv",
    "combined": FEATURES_DIR / "combined_features.csv"
}

ML_COLUMNS = [
    "in_degree",
    "out_degree",
    "total_degree",
    "degree_centrality",
    "in_degree_centrality",
    "out_degree_centrality",
    "betweenness_centrality",
    "closeness_centrality",
    "community_id",
    "platform_count",
    "domain_count",
    "tactic_count",
    "name_length",
    "type_code"
]


def run_ml(dataset_name, file_path):
    if not file_path.exists():
        print(f"[WARNING] Missing features file: {file_path}")
        return

    df = pd.read_csv(file_path)

    available_cols = [col for col in ML_COLUMNS if col in df.columns]
    X = df[available_cols].fillna(0)

    if len(X) < 5:
        print(f"[WARNING] Not enough rows for ML in {dataset_name}")
        return

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # -------------------------
    # Clustering
    # -------------------------
    n_clusters = min(5, max(2, len(df) // 50))
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    df["cluster_id"] = kmeans.fit_predict(X_scaled)

    # -------------------------
    # Anomaly Detection
    # -------------------------
    iso = IsolationForest(contamination=0.05, random_state=42)
    df["anomaly_score"] = iso.fit_predict(X_scaled)
    df["is_anomaly"] = df["anomaly_score"].apply(lambda x: 1 if x == -1 else 0)

    # -------------------------
    # PCA for dashboard scatter plot
    # -------------------------
    pca = PCA(n_components=2, random_state=42)
    coords = pca.fit_transform(X_scaled)
    df["pca_x"] = coords[:, 0]
    df["pca_y"] = coords[:, 1]

    # -------------------------
    # Summary
    # -------------------------
    summary = {
        "dataset": dataset_name,
        "rows": int(len(df)),
        "ml_columns_used": available_cols,
        "cluster_count": int(df["cluster_id"].nunique()),
        "anomaly_count": int(df["is_anomaly"].sum()),
        "cluster_distribution": df["cluster_id"].value_counts().sort_index().to_dict()
    }

    # -------------------------
    # Save
    # -------------------------
    output_csv = ML_DIR / f"{dataset_name}_ml_results.csv"
    output_json = ML_DIR / f"{dataset_name}_ml_summary.json"

    df.to_csv(output_csv, index=False)

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("=" * 70)
    print(f"[DONE] ML analysis completed for: {dataset_name}")
    print(f"[DONE] Results saved: {output_csv}")
    print(f"[DONE] Summary saved: {output_json}")
    print()


def main():
    for dataset_name, file_path in INPUT_FILES.items():
        run_ml(dataset_name, file_path)


if __name__ == "__main__":
    main()
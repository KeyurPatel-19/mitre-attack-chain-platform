from pathlib import Path
import pandas as pd

PROJECT_DIR = Path("/Users/hely/Desktop/YT2_mitre_attack_chain_platform")
DATA_DIR = PROJECT_DIR / "Data"
ANALYSIS_DIR = DATA_DIR / "analysis"
FEATURES_DIR = DATA_DIR / "features"

FEATURES_DIR.mkdir(parents=True, exist_ok=True)

INPUT_FILES = {
    "enterprise": ANALYSIS_DIR / "enterprise_node_analysis.csv",
    "ics": ANALYSIS_DIR / "ics_node_analysis.csv",
    "mobile": ANALYSIS_DIR / "mobile_node_analysis.csv",
    "combined": ANALYSIS_DIR / "combined_node_analysis.csv"
}


def count_pipe_items(value):
    if pd.isna(value) or str(value).strip() == "":
        return 0
    return len([x for x in str(value).split("|") if x.strip()])


def build_feature_file(dataset_name, file_path):
    if not file_path.exists():
        print(f"[WARNING] Missing analysis file: {file_path}")
        return

    df = pd.read_csv(file_path)

    df["platform_count"] = df["platforms"].apply(count_pipe_items)
    df["domain_count"] = df["domains"].apply(count_pipe_items)
    df["tactic_count"] = df["tactics"].apply(count_pipe_items)
    df["name_length"] = df["name"].fillna("").astype(str).apply(len)
    df["description_length"] = df["description"].fillna("").astype(str).apply(len) if "description" in df.columns else 0

    # Keep original metadata + ML-friendly columns
    feature_df = df.copy()

    # Type encoding
    feature_df["type_code"] = feature_df["type"].astype("category").cat.codes

    output_file = FEATURES_DIR / f"{dataset_name}_features.csv"
    feature_df.to_csv(output_file, index=False)

    print(f"[DONE] Features saved: {output_file}")


def main():
    for dataset_name, file_path in INPUT_FILES.items():
        build_feature_file(dataset_name, file_path)


if __name__ == "__main__":
    main()
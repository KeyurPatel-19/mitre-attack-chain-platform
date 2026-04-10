import json
from pathlib import Path
from collections import Counter

# ============================================================
# BASE PATHS
# ============================================================
PROJECT_DIR = Path("/Users/hely/Desktop/YT2_mitre_attack_chain_platform")
DATA_DIR = PROJECT_DIR / "Data"
RAW_DIR = DATA_DIR / "raw_data"
CLEANED_DIR = DATA_DIR / "cleaned_data"

CLEANED_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# DATASETS
# ============================================================
DATASETS = {
    "enterprise": RAW_DIR / "enterprise-attack-18.1.json",
    "ics": RAW_DIR / "ics-attack-18.1.json",
    "mobile": RAW_DIR / "mobile-attack-18.1.json",
}

# ============================================================
# USEFUL OBJECT TYPES
# ============================================================
USEFUL_TYPES = {
    "attack-pattern",
    "x-mitre-tactic",
    "intrusion-set",
    "malware",
    "tool",
    "campaign",
    "course-of-action",
    "relationship"
}

# ============================================================
# HELPERS
# ============================================================
def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def extract_external_id(external_references):
    if not isinstance(external_references, list):
        return None

    valid_sources = {
        "mitre-attack",
        "mitre-mobile-attack",
        "mitre-ics-attack"
    }

    for ref in external_references:
        if ref.get("source_name") in valid_sources and "external_id" in ref:
            return ref["external_id"]
    return None

def simplify_object(obj):
    obj_type = obj.get("type")

    if obj_type == "relationship":
        return {
            "id": obj.get("id"),
            "type": obj_type,
            "relationship_type": obj.get("relationship_type", ""),
            "source_ref": obj.get("source_ref", ""),
            "target_ref": obj.get("target_ref", ""),
            "description": obj.get("description", ""),
            "created": obj.get("created", ""),
            "modified": obj.get("modified", "")
        }

    simplified = {
        "id": obj.get("id"),
        "type": obj_type,
        "name": obj.get("name", ""),
        "description": obj.get("description", ""),
        "created": obj.get("created", ""),
        "modified": obj.get("modified", "")
    }

    external_id = extract_external_id(obj.get("external_references", []))
    if external_id:
        simplified["external_id"] = external_id

    if obj.get("x_mitre_platforms"):
        simplified["x_mitre_platforms"] = obj["x_mitre_platforms"]

    if obj.get("x_mitre_domains"):
        simplified["x_mitre_domains"] = obj["x_mitre_domains"]

    if obj.get("kill_chain_phases"):
        simplified["kill_chain_phases"] = [
            {
                "kill_chain_name": phase.get("kill_chain_name", ""),
                "phase_name": phase.get("phase_name", "")
            }
            for phase in obj["kill_chain_phases"]
        ]

    if obj_type == "x-mitre-tactic":
        simplified["x_mitre_shortname"] = obj.get("x_mitre_shortname", "")

    return simplified

def clean_dataset(dataset_name: str, input_file: Path):
    if not input_file.exists():
        print(f"[WARNING] File not found: {input_file}")
        return

    print("=" * 70)
    print(f"Cleaning dataset: {dataset_name}")
    print("=" * 70)

    data = load_json(input_file)
    objects = data.get("objects", [])

    # -----------------------------
    # First-pass removal counters
    # -----------------------------
    removed_revoked = 0
    removed_deprecated = 0
    removed_wrong_type = 0
    removed_missing_id = 0
    removed_missing_type = 0
    removed_invalid_relationship = 0

    first_pass_objects = []

    # -----------------------------
    # First pass cleaning
    # -----------------------------
    for obj in objects:
        obj_type = obj.get("type")
        obj_id = obj.get("id")

        if not obj_type:
            removed_missing_type += 1
            continue

        if not obj_id:
            removed_missing_id += 1
            continue

        if obj.get("revoked", False):
            removed_revoked += 1
            continue

        if obj.get("x_mitre_deprecated", False):
            removed_deprecated += 1
            continue

        if obj_type not in USEFUL_TYPES:
            removed_wrong_type += 1
            continue

        if obj_type == "relationship":
            if not obj.get("source_ref") or not obj.get("target_ref") or not obj.get("relationship_type"):
                removed_invalid_relationship += 1
                continue

        first_pass_objects.append(simplify_object(obj))

    # -----------------------------
    # Second pass: remove orphan relationships
    # -----------------------------
    kept_ids = {obj["id"] for obj in first_pass_objects if obj.get("id")}
    cleaned_objects = []
    removed_orphan_relationship = 0

    for obj in first_pass_objects:
        if obj.get("type") == "relationship":
            source_ref = obj.get("source_ref")
            target_ref = obj.get("target_ref")

            if source_ref not in kept_ids or target_ref not in kept_ids:
                removed_orphan_relationship += 1
                continue

        cleaned_objects.append(obj)

    # -----------------------------
    # Build final cleaned data
    # -----------------------------
    cleaned_data = {
        "type": data.get("type", "bundle"),
        "id": data.get("id", f"bundle--{dataset_name}-cleaned"),
        "spec_version": data.get("spec_version", "2.1"),
        "objects": cleaned_objects
    }

    type_counts = Counter(obj["type"] for obj in cleaned_objects)

    cleaned_file = CLEANED_DIR / f"{dataset_name}-attack-cleaned.json"
    summary_file = CLEANED_DIR / f"{dataset_name}-attack-cleaning-summary.json"

    summary = {
        "dataset": dataset_name,
        "input_file": str(input_file),
        "output_file": str(cleaned_file),
        "total_objects_before": len(objects),
        "total_objects_after_first_pass": len(first_pass_objects),
        "total_objects_after_final_cleaning": len(cleaned_objects),
        "removed": {
            "revoked": removed_revoked,
            "deprecated": removed_deprecated,
            "wrong_type": removed_wrong_type,
            "missing_id": removed_missing_id,
            "missing_type": removed_missing_type,
            "invalid_relationship": removed_invalid_relationship,
            "orphan_relationship": removed_orphan_relationship
        },
        "remaining_object_types": dict(type_counts)
    }

    with open(cleaned_file, "w", encoding="utf-8") as f:
        json.dump(cleaned_data, f, indent=2, ensure_ascii=False)

    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"[DONE] Cleaned file saved: {cleaned_file}")
    print(f"[DONE] Summary file saved: {summary_file}")
    print(f"[INFO] Objects before: {len(objects)}")
    print(f"[INFO] After first pass: {len(first_pass_objects)}")
    print(f"[INFO] Final objects after orphan removal: {len(cleaned_objects)}")
    print(f"[INFO] Orphan relationships removed: {removed_orphan_relationship}")
    print()

def main():
    for dataset_name, input_file in DATASETS.items():
        clean_dataset(dataset_name, input_file)

    print("=" * 70)
    print("All datasets cleaned successfully.")
    print("=" * 70)

if __name__ == "__main__":
    main()
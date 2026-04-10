import json
from pathlib import Path
from collections import Counter

PROJECT_DIR = Path("/Users/hely/Desktop/YT2_mitre_attack_chain_platform")
DATA_DIR = PROJECT_DIR / "Data"
CLEANED_DIR = DATA_DIR / "cleaned_data"
VALIDATION_DIR = DATA_DIR / "validation_reports"

VALIDATION_DIR.mkdir(parents=True, exist_ok=True)

FILES = {
    "enterprise": CLEANED_DIR / "enterprise-attack-cleaned.json",
    "ics": CLEANED_DIR / "ics-attack-cleaned.json",
    "mobile": CLEANED_DIR / "mobile-attack-cleaned.json",
}

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def validate_cleaned_file(dataset_name, file_path):
    if not file_path.exists():
        print(f"[WARNING] Missing cleaned file: {file_path}")
        return

    data = load_json(file_path)
    objects = data.get("objects", [])

    id_set = set()
    duplicate_ids = set()
    type_counter = Counter()
    relationship_counter = Counter()
    missing_id_count = 0
    missing_type_count = 0

    for obj in objects:
        obj_id = obj.get("id")
        obj_type = obj.get("type")

        if not obj_id:
            missing_id_count += 1
            continue

        if not obj_type:
            missing_type_count += 1
            continue

        if obj_id in id_set:
            duplicate_ids.add(obj_id)
        else:
            id_set.add(obj_id)

        type_counter[obj_type] += 1

        if obj_type == "relationship":
            relationship_counter[obj.get("relationship_type", "UNKNOWN")] += 1

    broken_relationships = []
    for obj in objects:
        if obj.get("type") == "relationship":
            source_ref = obj.get("source_ref")
            target_ref = obj.get("target_ref")

            if source_ref not in id_set or target_ref not in id_set:
                broken_relationships.append({
                    "id": obj.get("id"),
                    "relationship_type": obj.get("relationship_type"),
                    "source_ref": source_ref,
                    "target_ref": target_ref
                })

    report = {
        "dataset": dataset_name,
        "file": str(file_path),
        "total_objects": len(objects),
        "duplicate_id_count": len(duplicate_ids),
        "missing_id_count": missing_id_count,
        "missing_type_count": missing_type_count,
        "broken_relationship_count": len(broken_relationships),
        "object_type_counts": dict(type_counter),
        "relationship_type_counts": dict(relationship_counter),
        "sample_broken_relationships": broken_relationships[:10]
    }

    report_path = VALIDATION_DIR / f"{dataset_name}-validation-report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("=" * 70)
    print(f"Validation complete for: {dataset_name}")
    print("=" * 70)
    print(f"Report saved: {report_path}")
    print(f"Total objects: {len(objects)}")
    print(f"Duplicate IDs: {len(duplicate_ids)}")
    print(f"Broken relationships: {len(broken_relationships)}")
    print(f"Missing IDs: {missing_id_count}")
    print(f"Missing types: {missing_type_count}")
    print()

def main():
    for dataset_name, file_path in FILES.items():
        validate_cleaned_file(dataset_name, file_path)

if __name__ == "__main__":
    main()
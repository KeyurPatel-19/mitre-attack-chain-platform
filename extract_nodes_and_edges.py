import json
from pathlib import Path

PROJECT_DIR = Path("/Users/hely/Desktop/YT2_mitre_attack_chain_platform")
DATA_DIR = PROJECT_DIR / "Data"
CLEANED_DIR = DATA_DIR / "cleaned_data"
PROCESSED_DIR = DATA_DIR / "processed_data"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

INPUT_FILES = {
    "enterprise": CLEANED_DIR / "enterprise-attack-cleaned.json",
    "ics": CLEANED_DIR / "ics-attack-cleaned.json",
    "mobile": CLEANED_DIR / "mobile-attack-cleaned.json",
}

KEEP_NODE_TYPES = {
    "attack-pattern",
    "x-mitre-tactic",
    "intrusion-set",
    "malware",
    "tool",
    "campaign",
    "course-of-action"
}

KEEP_RELATIONSHIP_TYPES = {
    "uses",
    "mitigates",
    "subtechnique-of"
}

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def get_tactics(obj):
    tactics = []
    for phase in obj.get("kill_chain_phases", []):
        phase_name = phase.get("phase_name")
        if phase_name:
            tactics.append(phase_name)
    return tactics

def normalize_node(obj, dataset_name):
    return {
        "id": obj.get("id"),
        "type": obj.get("type"),
        "name": obj.get("name", ""),
        "description": obj.get("description", ""),
        "external_id": obj.get("external_id"),
        "platforms": obj.get("x_mitre_platforms", []),
        "domains": obj.get("x_mitre_domains", []),
        "tactics": get_tactics(obj) if obj.get("type") == "attack-pattern" else [],
        "dataset": dataset_name
    }

def process_dataset(dataset_name, file_path):
    if not file_path.exists():
        print(f"[WARNING] Missing cleaned file: {file_path}")
        return [], []

    data = load_json(file_path)
    objects = data.get("objects", [])

    node_map = {}
    nodes = []
    edges = []

    for obj in objects:
        if obj.get("type") in KEEP_NODE_TYPES:
            node = normalize_node(obj, dataset_name)
            node_id = node["id"]
            if node_id and node_id not in node_map:
                node_map[node_id] = node
                nodes.append(node)

    for obj in objects:
        if obj.get("type") != "relationship":
            continue

        rel_type = obj.get("relationship_type")
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")

        if rel_type not in KEEP_RELATIONSHIP_TYPES:
            continue

        if source_ref not in node_map or target_ref not in node_map:
            continue

        edges.append({
            "id": obj.get("id"),
            "type": rel_type,
            "source": source_ref,
            "target": target_ref,
            "dataset": dataset_name
        })

    return nodes, edges

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    combined_nodes = []
    combined_edges = []
    seen_node_ids = set()

    for dataset_name, file_path in INPUT_FILES.items():
        nodes, edges = process_dataset(dataset_name, file_path)

        save_json(PROCESSED_DIR / f"{dataset_name}_nodes.json", nodes)
        save_json(PROCESSED_DIR / f"{dataset_name}_edges.json", edges)

        print(f"[DONE] Saved {dataset_name} nodes: {PROCESSED_DIR / f'{dataset_name}_nodes.json'}")
        print(f"[DONE] Saved {dataset_name} edges: {PROCESSED_DIR / f'{dataset_name}_edges.json'}")

        for node in nodes:
            if node["id"] not in seen_node_ids:
                combined_nodes.append(node)
                seen_node_ids.add(node["id"])

        combined_edges.extend(edges)

    save_json(PROCESSED_DIR / "combined_nodes.json", combined_nodes)
    save_json(PROCESSED_DIR / "combined_edges.json", combined_edges)

    print()
    print(f"[DONE] Saved combined nodes: {PROCESSED_DIR / 'combined_nodes.json'}")
    print(f"[DONE] Saved combined edges: {PROCESSED_DIR / 'combined_edges.json'}")

if __name__ == "__main__":
    main()
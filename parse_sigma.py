from pathlib import Path
import yaml

SIGMA_REPO_DIR = Path(__file__).parent / "sigma"
RULE_DIRS = ["rules", "rules-emerging-threats"]

def iter_sigma_rules():
    for rule_dir in RULE_DIRS:
        dir_path = SIGMA_REPO_DIR / rule_dir
        if not dir_path.exists():
            continue
        for path in dir_path.rglob("*.yml"):
            with path.open("r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)

            if not isinstance(rule, dict):
                continue

            yield {
                "id": rule.get("id"),
                "title": rule.get("title"),
                "path": str(path),
                "tags": rule.get("tags", []),
                "logsource": rule.get("logsource", {}),
            }

def extract_attack_ids_from_tags(tags) -> set[str]:
    ids = set()
    for tag in tags or []:
        # We care about tags like "attack.t1059.001"
        if tag.startswith("attack.t"):
            # Remove "attack." and upper-case the T…
            tech = tag.split("attack.")[1]      # e.g. "t1059.001"
            ids.add(tech.upper())               # "T1059.001"
    return ids

#!/usr/bin/env python3
"""
Sigma -> Analytic YAML converter (KQL embedded)
- Writes ONLY .yml files (no .kql sidecars)
- Keeps the script lean: minimal logging, no directory wiping, no extra checks
"""

import argparse
import sys
from pathlib import Path
import re
import logging
import shutil
from textwrap import indent

from sigma.plugins import InstalledSigmaPlugins
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

try:
    import yaml
except Exception:
    yaml = None


def kql_from_sigma(rule_text: str, pipeline_name: str) -> str:
    """Convert Sigma YAML text to a single KQL query string."""
    plugins = InstalledSigmaPlugins.autodiscover()
    backends = plugins.backends
    if "kusto" not in backends:
        print(
            "Error: Kusto backend not found. Install pySigma-backend-microsoft365defender",
            file=sys.stderr,
        )
        sys.exit(1)

    pipeline_resolver = plugins.get_pipeline_resolver()
    processing_pipeline = (
        pipeline_resolver.resolve([pipeline_name]) if pipeline_name else ProcessingPipeline()
    )
    backend = backends["kusto"](processing_pipeline=processing_pipeline)
    sigma_rule = SigmaCollection.from_yaml(rule_text)
    result = backend.convert(sigma_rule, "default")

    if isinstance(result, list):
        result = "\n".join(result)

    # Normalize whitespace and indentation around pipes
    result = result.replace("\r\n", "\n").replace("\r", "\n")
    kql_text = re.sub(r"\n\s*\n+", "\n", result)
    kql_text = re.sub(r"(?m)^[ \t]+(?=\|)", "", kql_text)  # unindent lines that start with a pipe
    return kql_text.strip()


def analytic_yaml_from_sigma(rule_path: Path, kql_query: str) -> str:
    """Build analytic YAML string, embedding KQL as a block scalar.
    If PyYAML is available, we use it for the header; otherwise, write a basic YAML manually.
    """
    # Best-effort parse the first document for metadata
    meta = {}
    if yaml is not None:
        try:
            docs = list(yaml.safe_load_all(rule_path.read_text(encoding="utf-8")))
            if docs and isinstance(docs[0], dict):
                meta = docs[0]
        except Exception:
            meta = {}

    # Simple defaults
    level = (meta.get("level") or "Medium")
    name = meta.get("title") or meta.get("name") or rule_path.stem
    description = meta.get("description", "")
    tags = meta.get("tags") or []

    def level_to_freq_sev(level):
        l = str(level).lower()
        if l in ("critical", "high"):
            return ("PT5M", "PT15M", "High")
        if l in ("medium", "moderate"):
            return ("PT15M", "PT1H", "Medium")
        if l in ("low", "informational", "info"):
            return ("PT1H", "P1D", "Low")
        return ("PT15M", "PT1H", "Medium")

    qf, qp, sev = level_to_freq_sev(level)

    header = {
        "name": name,
        "severity": level or sev,
        "enabled": meta.get("enabled", True),
        "triggerThreshold": meta.get("triggerThreshold", 0),
        "triggerOperator": meta.get("triggerOperator", "gt"),
        "description": description,
        "tactics": tags if isinstance(tags, list) else [str(tags)],
        "queryFrequency": meta.get("queryFrequency", qf),
        "queryPeriod": meta.get("queryPeriod", qp),
        "incidentConfiguration": meta.get(
            "incidentConfiguration",
            {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": True,
                    "lookbackDuration": "PT5H",
                    "matchingMethod": "AllEntities",
                    "groupByEntities": [],
                    "groupByAlertDetails": [],
                    "groupByCustomDetails": [],
                },
            },
        ),
        "eventGroupingSettings": meta.get("eventGroupingSettings", {"aggregationKind": "SingleAlert"}),
        "entityMappings": meta.get(
            "entityMappings",
            [
                {
                    "entityType": "Host",
                    "fieldMappings": [
                        {"identifier": "FullName", "columnName": "DeviceName"},
                        {"identifier": "HostName", "columnName": "HostName"},
                        {"identifier": "DnsDomain", "columnName": "DnsDomain"},
                        ],
                }
            ],
        ),
    }

    if yaml is not None:
        # Use PyYAML for header, then append query as block scalar
        header_yaml = yaml.safe_dump(header, sort_keys=False, allow_unicode=True)
        block = "query: |\n" + indent(kql_query, "  ") + ("\n" if not kql_query.endswith("\n") else "")
        return header_yaml + block
    else:
        # Minimal YAML writer (very basic; no nested lists formatting fanciness)
        lines = []
        for k, v in header.items():
            if isinstance(v, bool):
                lines.append(f"{k}: {'true' if v else 'false'}")
            elif isinstance(v, (int, float)):
                lines.append(f"{k}: {v}")
            elif isinstance(v, list):
                lines.append(f"{k}:")
                for item in v:
                    lines.append(f"  - {item}")
            elif isinstance(v, dict):
                lines.append(f"{k}:")
                for k2, v2 in v.items():
                    lines.append(f"  {k2}: {v2}")
            else:
                lines.append(f"{k}: {v}")
        lines.append("query: |")
        lines.extend(["  " + ln for ln in kql_query.splitlines()])
        return "\n".join(lines) + "\n"
def read_rule_ids_from_file(rules_file: Path) -> list[str]:
    """Read and deduplicate rule IDs from rules.txt"""
    if not rules_file.exists():
        print(f"Error: Rules file not found: {rules_file}", file=sys.stderr)
        sys.exit(1)

    rule_ids = []
    seen = set()

    with rules_file.open('r', encoding='utf-8') as f:
        for line in f:
            rule_id = line.strip()
            if rule_id and rule_id not in seen:
                seen.add(rule_id)
                rule_ids.append(rule_id)

    return rule_ids


def find_sigma_rule_by_id(rule_id: str, sigma_dir: Path) -> Path | None:
    """Find a Sigma rule file by its ID in the sigma directory"""
    # Search in rules/ and rules-emerging-threats/
    for subdir in ["rules", "rules-emerging-threats"]:
        search_dir = sigma_dir / subdir
        if not search_dir.exists():
            continue

        # Search all .yml and .yaml files
        for rule_path in list(search_dir.rglob("*.yml")) + list(search_dir.rglob("*.yaml")):
            try:
                content = rule_path.read_text(encoding='utf-8')
                # Look for id: rule_id in the YAML
                if yaml is not None:
                    try:
                        docs = list(yaml.safe_load_all(content))
                        if docs and isinstance(docs[0], dict):
                            if docs[0].get('id') == rule_id:
                                return rule_path
                    except Exception:
                        pass
                else:
                    # Simple text search if PyYAML not available
                    if f"id: {rule_id}" in content:
                        return rule_path
            except Exception:
                continue

    return None


def _resolve_log_dir(input_path: Path, out_dir: Path | None, out_file: Path | None) -> Path:
    """Choose a directory to hold logs. Prefer output directory; else parent of output file; else CWD."""
    if out_dir is not None:
        return out_dir
    if out_file is not None:
        return out_file.parent
    return Path.cwd()


def _setup_logging(log_dir: Path) -> tuple[Path, Path]:
    log_dir.mkdir(parents=True, exist_ok=True)
    convert_log = log_dir / "convert.log"
    failed_log = log_dir / "failed_rules.log"

    # Configure root logger to write to convert.log
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(convert_log, encoding="utf-8"),],
        force=True,
    )
    # Truncate failed_rules.log at start
    failed_log.write_text("", encoding="utf-8")
    return convert_log, failed_log



def convert(input_path: Path, pipeline: str, output: str | None) -> None:
    """Convert a single file or all .yml/.yaml files under a directory to analytic YAML only.
    - If input and output are directories, wipe EVERYTHING in the output directory before writing.
    - All progress/errors go to convert.log; failed rule names go to failed_rules.log.
    """
    if input_path.is_dir():
        rule_files = list(input_path.rglob("*.yml")) + list(input_path.rglob("*.yaml"))
        if not rule_files:
            logging.error(f"No .yml or .yaml files found in '%s'", input_path)
            sys.exit(1)
    else:
        rule_files = [input_path]

    out_dir: Path | None = None
    out_file: Path | None = None
    if output:
        p = Path(output)
        if input_path.is_dir():
            # treat as directory
            out_dir = p
            out_dir.mkdir(parents=True, exist_ok=True)
        else:
            # if output has a suffix, treat as file; else as directory
            if p.suffix:
                out_file = p
                p.parent.mkdir(parents=True, exist_ok=True)
            else:
                out_dir = p
                out_dir.mkdir(parents=True, exist_ok=True)

    # Setup logging files
    log_dir = _resolve_log_dir(input_path, out_dir, out_file)
    convert_log_path, failed_log_path = _setup_logging(log_dir)
    logging.info("Starting conversion")
    logging.info("Input: %s", str(input_path))
    if out_dir:
        logging.info("Output directory: %s", str(out_dir))
    if out_file:
        logging.info("Output file: %s", str(out_file))
    logging.info("Pipeline: %s", pipeline)

    # Wipe EVERYTHING in output directory if both input and output are directories
    if out_dir is not None and input_path.is_dir():
        logging.info("Wiping output directory: %s", out_dir)
        for child in list(out_dir.iterdir()):
            try:
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
            except Exception as e:
                logging.warning("Failed to remove %s: %s", child, e)

    # Process files with per-rule error handling
    failed_names = []
    for rf in rule_files:
        try:
            kql = kql_from_sigma(rf.read_text(encoding="utf-8"), pipeline)
            analytic = analytic_yaml_from_sigma(rf, kql)

            if input_path.is_dir():
                if out_dir:
                    rel = rf.parent.relative_to(input_path)
                    dest_dir = out_dir / rel
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    dest = dest_dir / (rf.stem + ".yml")
                    dest.write_text(analytic, encoding="utf-8")
                    logging.info("Wrote %s", dest)
                else:
                    # no output directory: log the YAML content
                    logging.info("# --- %s ---", rf)
                    logging.info("\n%s", analytic)
            else:
                if out_file:
                    dest = out_file.with_suffix(".yml")
                    dest.write_text(analytic, encoding="utf-8")
                    logging.info("Wrote %s", dest)
                elif out_dir:
                    dest = out_dir / (rf.stem + ".yml")
                    dest.write_text(analytic, encoding="utf-8")
                    logging.info("Wrote %s", dest)
                else:
                    logging.info("%s", analytic)

        except Exception as e:
            logging.error("Failed converting %s: %s", rf, e, exc_info=True)
            failed_names.append(rf.stem)

    # Write failed rules list
    if failed_names:
        with failed_log_path.open("a", encoding="utf-8") as fh:
            for name in failed_names:
                fh.write(name + "\n")
        logging.info("Failed rules written to %s (%d items)", failed_log_path, len(failed_names))
    else:
        logging.info("No failed rules.")

    logging.info("Finished. Logs: %s; Failed: %s", convert_log_path, failed_log_path)


def convert_from_rules_file(rules_file: Path, pipeline: str, output: str | None) -> None:
    """Convert rules from a rules.txt file containing rule IDs.
    - Reads and deduplicates rule IDs from rules.txt
    - Finds each Sigma rule by ID in the sigma/ directory
    - Converts to analytic YAML format
    """
    # Read and deduplicate rule IDs
    rule_ids = read_rule_ids_from_file(rules_file)

    if not rule_ids:
        logging.error("No rule IDs found in rules file")
        sys.exit(1)

    # Determine sigma directory
    sigma_dir = Path(__file__).parent / "sigma"
    if not sigma_dir.exists():
        print(f"Error: Sigma directory not found: {sigma_dir}", file=sys.stderr)
        sys.exit(1)

    # Setup output directory
    out_dir: Path | None = None
    if output:
        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)

    # Setup logging
    log_dir = _resolve_log_dir(rules_file.parent, out_dir, None)
    convert_log_path, failed_log_path = _setup_logging(log_dir)

    logging.info("Starting conversion from rules file")
    logging.info("Rules file: %s", rules_file)
    logging.info("Found %d unique rule IDs", len(rule_ids))
    if out_dir:
        logging.info("Output directory: %s", out_dir)
    logging.info("Pipeline: %s", pipeline)

    # Wipe output directory if specified
    if out_dir is not None:
        logging.info("Wiping output directory: %s", out_dir)
        for child in list(out_dir.iterdir()):
            try:
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
            except Exception as e:
                logging.warning("Failed to remove %s: %s", child, e)

    # Process each rule ID
    failed_names = []
    not_found = []

    for rule_id in rule_ids:
        # Find the Sigma rule file
        rule_path = find_sigma_rule_by_id(rule_id, sigma_dir)

        if rule_path is None:
            logging.warning("Rule not found for ID: %s", rule_id)
            not_found.append(rule_id)
            continue

        try:
            # Convert the rule
            kql = kql_from_sigma(rule_path.read_text(encoding='utf-8'), pipeline)
            analytic = analytic_yaml_from_sigma(rule_path, kql)

            if out_dir:
                # Write to output directory
                dest = out_dir / f"{rule_id}.yml"
                dest.write_text(analytic, encoding='utf-8')
                logging.info("Wrote %s", dest)
            else:
                # Log the YAML content
                logging.info("# --- %s ---", rule_id)
                logging.info("\n%s", analytic)

        except Exception as e:
            logging.error("Failed converting %s: %s", rule_id, e, exc_info=True)
            failed_names.append(rule_id)

    # Write not found IDs
    if not_found:
        logging.warning("%d rule IDs not found in Sigma repository", len(not_found))
        with failed_log_path.open('a', encoding='utf-8') as fh:
            fh.write("# Not found:\n")
            for rule_id in not_found:
                fh.write(f"{rule_id}\n")

    # Write failed conversions
    if failed_names:
        with failed_log_path.open('a', encoding='utf-8') as fh:
            fh.write("# Failed conversions:\n")
            for rule_id in failed_names:
                fh.write(f"{rule_id}\n")
        logging.info("Failed rules written to %s (%d items)", failed_log_path, len(failed_names))
    else:
        logging.info("No failed rules.")

    success_count = len(rule_ids) - len(not_found) - len(failed_names)
    logging.info("Finished. Logs: %s; Failed: %s", convert_log_path, failed_log_path)
    logging.info("Successfully converted %d/%d rules", success_count, len(rule_ids))

    # Clean up rules.txt (commented out)
    # rules_file.unlink()
    # logging.info("Deleted %s", rules_file)


def main():
    parser = argparse.ArgumentParser(description="Convert Sigma rules to analytic YAML (KQL embedded).")
    parser.add_argument("input", help="Path to Sigma rule YAML file, directory containing rules, or rules.txt file with rule IDs")
    parser.add_argument(
        "-p",
        "--pipeline",
        default="microsoft_xdr",
        help="Processing pipeline to use (default: microsoft_xdr)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file or directory. If omitted, prints YAML to stdout. For directory input, treat as output directory.",
    )
    args = parser.parse_args()

    input_path = Path(args.input)

    # Check if input is a rules.txt file
    if input_path.is_file() and input_path.name == "rules.txt":
        convert_from_rules_file(input_path, args.pipeline, args.output)
    else:
        convert(input_path, args.pipeline, args.output)


if __name__ == "__main__":
    main()

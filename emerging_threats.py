from pathlib import Path
import yaml

# ============================================================================
# Sigma Rules Functions
# ============================================================================

SIGMA_REPO_DIR = Path(__file__).parent / "sigma"
# Only emerging threats
RULE_DIRS = ["rules-emerging-threats"]

# Load available log sources
LOGSOURCES_PATH = Path(__file__).parent / "logsources.yml"
with open(LOGSOURCES_PATH, 'r') as f:
    logsources_config = yaml.safe_load(f)

def is_logsource_available(logsource: dict) -> bool:
    """Check if a Sigma rule's logsource matches our available log sources"""
    if not logsource:
        return False

    for mapping in logsources_config.get('mappings', []):
        match_criteria = mapping.get('match', {})

        # Check if all criteria in the mapping match the rule's logsource
        match = True
        for key, value in match_criteria.items():
            if logsource.get(key) != value:
                match = False
                break

        if match:
            return True

    return False

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
                "level": rule.get("level", "medium"),
                "status": rule.get("status", "test"),
                "description": rule.get("description", ""),
            }

def is_cve_specific(rule: dict) -> bool:
    """Check if a rule is CVE-specific"""
    title = rule.get('title', '').lower()
    description = rule.get('description', '').lower()

    # Check for CVE patterns
    if 'cve-' in title or 'cve-' in description:
        return True

    return False

def is_malware_specific(rule: dict) -> bool:
    """Check if a rule is specific to a named malware family"""
    title = rule.get('title', '').lower()

    # Common malware/ransomware family indicators
    malware_indicators = [
        'emotet', 'trickbot', 'dridex', 'qakbot', 'qbot', 'pikabot', 'icedid',
        'wannacry', 'notpetya', 'maze', 'conti', 'darkside', 'revil', 'ryuk',
        'lockergoga', 'rorschach', 'snatch', 'darkgate', 'locky', 'cerber',
        'sodinokibi', 'babuk', 'blackbyte', 'alphv', 'blackcat',
        'cobalt strike', 'metasploit', 'mimikatz', 'bloodhound',
        'snake malware', 'kapeka', 'taidoor', 'elise backdoor', 'plugx',
        'zxshell', 'moriya rootkit', 'pingback backdoor', 'adwind',
        'formbook', 'guloader', 'ursnif', 'rhadamanthys', 'katz stealer',
        'lummac stealer', 'funklocker', 'hermetic wiper', 'raspberry robin',
        'coldsteel rat', 'csharp streamer rat', 'fireball archer',
        'goofy guineapig', 'devil bait', 'small sieve', 'baby shark',
        'empiremonkey', 'griffon malware', 'foggyweb', '3cxdesktopapp',
        'kamikakabot', 'kalambur backdoor', 'serpent backdoor'
    ]

    # Check if title contains malware-specific terms
    for indicator in malware_indicators:
        if indicator in title:
            return True

    return False

def extract_attack_ids_from_tags(tags) -> set[str]:
    ids = set()
    for tag in tags or []:
        if tag.startswith("attack.t"):
            tech = tag.split("attack.")[1]
            ids.add(tech.upper())
    return ids

# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    matching_rules = []
    total_rules = 0
    filtered_by_logsource = 0
    filtered_by_cve = 0
    filtered_by_malware = 0

    print("="*80)
    print("EMERGING THREAT RULES - LOG SOURCE ANALYSIS")
    print("="*80)
    print("\nScanning Emerging Threat Sigma rules...")

    for rule in iter_sigma_rules():
        total_rules += 1

        # Filter by available log sources
        if not is_logsource_available(rule['logsource']):
            filtered_by_logsource += 1
            continue

        # Filter out CVE-specific rules
        if is_cve_specific(rule):
            filtered_by_cve += 1
            continue

        # Filter out malware-specific rules
        if is_malware_specific(rule):
            filtered_by_malware += 1
            continue

        matching_rules.append(rule)

    print(f"Scanned {total_rules} Emerging Threat Sigma rules")
    print(f"Filtered out {filtered_by_logsource} rules (log source not available)")
    print(f"Filtered out {filtered_by_cve} rules (CVE-specific)")
    print(f"Filtered out {filtered_by_malware} rules (malware-specific)")
    print(f"Found {len(matching_rules)} rules matching your criteria\n")

    # Group by log source
    logsource_to_rules = {}
    for rule in matching_rules:
        ls = rule['logsource']
        # Create a string key for the logsource
        if 'product' in ls and 'category' in ls:
            key = f"{ls['product']}/{ls['category']}"
        elif 'product' in ls and 'service' in ls:
            key = f"{ls['product']}/{ls['service']}"
        elif 'product' in ls:
            key = ls['product']
        elif 'category' in ls:
            key = ls['category']
        else:
            key = "other"

        if key not in logsource_to_rules:
            logsource_to_rules[key] = []
        logsource_to_rules[key].append(rule)

    # Show level distribution
    level_counts = {}
    for rule in matching_rules:
        level = rule.get('level', 'medium')
        level_counts[level] = level_counts.get(level, 0) + 1

    # Show status distribution
    status_counts = {}
    for rule in matching_rules:
        status = rule.get('status', 'test')
        status_counts[status] = status_counts.get(status, 0) + 1

    print("="*80)
    print("SUMMARY")
    print("="*80)

    print(f"\nTotal rules: {len(matching_rules)}")

    print("\nRule severity distribution:")
    for level in ['critical', 'high', 'medium', 'low', 'informational']:
        if level in level_counts:
            print(f"  {level}: {level_counts[level]}")

    print("\nRule status distribution:")
    for status in ['stable', 'test', 'experimental', 'deprecated']:
        if status in status_counts:
            print(f"  {status}: {status_counts[status]}")

    # TIERED DETECTION STRATEGY
    print("\n" + "="*80)
    print("TIERED DETECTION STRATEGY")
    print("="*80)

    tier1_rules = [r for r in matching_rules if r.get('level') == 'critical']
    tier2_rules = [r for r in matching_rules if r.get('level') == 'high']
    tier3_rules = [r for r in matching_rules if r.get('level') in ('medium', 'low', 'informational')]

    print(f"\nTier 1 - Critical (Immediate Response): {len(tier1_rules)} rules")
    print("  APT campaigns and high-confidence threat indicators")
    print("  → Auto-alert, high-priority queue")

    print(f"\nTier 2 - High (Investigation Queue): {len(tier2_rules)} rules")
    print("  Nation-state TTPs and emerging attack patterns")
    print("  → Investigation queue, analyst review")

    print(f"\nTier 3 - Medium/Low (Threat Hunting): {len(tier3_rules)} rules")
    print("  Lower-confidence indicators and hunting queries")
    print("  → Proactive hunting, correlation")

    # Show rules by log source
    print("\n" + "="*80)
    print("RULES BY LOG SOURCE")
    print("="*80)

    sorted_logsources = sorted(logsource_to_rules.items(), key=lambda x: len(x[1]), reverse=True)
    for logsource, rules in sorted_logsources:
        print(f"\n{logsource}: {len(rules)} rule(s)")

        # Sort by level (critical first)
        level_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
        sorted_rules = sorted(rules, key=lambda r: level_order.get(r.get('level', 'medium'), 2))

        # Show first 10 rules per log source
        for rule in sorted_rules[:10]:
            level_badge = f"[{rule.get('level', 'medium').upper()}]"
            status_badge = f"[{rule.get('status', 'test')}]"
            print(f"  {level_badge:12} {status_badge:14} {rule['title']}")

        if len(sorted_rules) > 10:
            print(f"  ... and {len(sorted_rules) - 10} more")

    # Extract MITRE ATT&CK techniques
    all_techniques = set()
    technique_to_rules = {}
    for rule in matching_rules:
        techs = extract_attack_ids_from_tags(rule['tags'])
        all_techniques.update(techs)
        for tech in techs:
            if tech not in technique_to_rules:
                technique_to_rules[tech] = []
            technique_to_rules[tech].append(rule)

    print("\n" + "="*80)
    print(f"MITRE ATT&CK COVERAGE ({len(all_techniques)} techniques)")
    print("="*80)

    sorted_techniques = sorted(technique_to_rules.items(), key=lambda x: len(x[1]), reverse=True)
    print("\nTop 20 techniques by rule count:")
    for tech, rules in sorted_techniques[:20]:
        print(f"  {tech}: {len(rules)} rule(s)")

    print("\n" + "="*80)
    print("RECOMMENDATIONS")
    print("="*80)

    print(f"\n✓ {len(matching_rules)} emerging threat rules available for your log sources")
    print(f"✓ Covers {len(all_techniques)} MITRE ATT&CK techniques")
    print(f"✓ {len(tier1_rules)} critical rules for immediate alerting")

    print(f"\n💡 Deployment Strategy:")
    print(f"  1. Deploy Tier 1 rules ({len(tier1_rules)}) for APT campaign detection")
    print(f"  2. Deploy Tier 2 rules ({len(tier2_rules)}) for nation-state TTPs")
    print(f"  3. Use Tier 3 rules ({len(tier3_rules)}) for threat hunting")
    print(f"  4. Review quarterly and add new emerging threats")
    print(f"  5. Combine with apt2sigma.py rules for comprehensive coverage")

    # Write rule IDs to file
    output_file = Path(__file__).parent / "rules.txt"
    with open(output_file, 'a') as f:
        for rule in matching_rules:
            rule_id = rule.get('id')
            if rule_id:
                f.write(f"{rule_id}\n")

    print(f"\n✓ Appended {len(matching_rules)} rule IDs to rules.txt")

import json
from pathlib import Path
import yaml

# ============================================================================
# MITRE ATT&CK Functions
# ============================================================================

# Load MITRE ATT&CK data directly
enterprise_attack_path = Path(__file__).parent / "enterprise-attack.json"
with open(enterprise_attack_path, 'r') as f:
    attack_data = json.load(f)

objects = attack_data.get('objects', [])

def get_group_by_name(substr: str):
    """Find a group by name substring"""
    substr = substr.lower()
    for obj in objects:
        if obj.get('type') == 'intrusion-set':
            name = obj.get('name', '').lower()
            if substr in name and not obj.get('revoked', False):
                return obj
    raise ValueError(f"No group matching {substr}")

def get_group_technique_ids(group_name: str) -> set[str]:
    """Get all technique IDs used by a group"""
    group = get_group_by_name(group_name)
    group_id = group['id']

    technique_ids = set()
    for obj in objects:
        if obj.get('type') == 'relationship':
            if obj.get('source_ref') == group_id and obj.get('relationship_type') == 'uses':
                target_ref = obj.get('target_ref', '')
                if target_ref.startswith('attack-pattern'):
                    for tech in objects:
                        if tech.get('id') == target_ref:
                            for ref in tech.get('external_references', []):
                                if ref.get('source_name') in ('mitre-attack', 'mitre-attack-legacy'):
                                    ext_id = ref.get('external_id')
                                    if ext_id and ext_id.startswith('T'):
                                        technique_ids.add(ext_id.upper())

    return technique_ids

# ============================================================================
# Sigma Rules Functions
# ============================================================================

SIGMA_REPO_DIR = Path(__file__).parent / "sigma"
RULE_DIRS = ["rules", "rules-emerging-threats"]

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

def extract_tactics_from_tags(tags) -> set[str]:
    """Extract MITRE ATT&CK tactics from tags"""
    tactics = set()
    for tag in tags or []:
        if tag.startswith("attack.") and not tag.startswith("attack.t"):
            # Remove "attack." prefix
            tactic = tag.replace("attack.", "")
            # Filter out non-tactic tags
            if tactic not in ['g0', 's0', 'car', 'capec'] and not tactic[0].isdigit():
                tactics.add(tactic.replace("-", "_"))
    return tactics

def get_technique_to_tactic_mapping() -> dict:
    """Build mapping of techniques to tactics from ATT&CK data"""
    mapping = {}
    for obj in objects:
        if obj.get('type') == 'attack-pattern' and not obj.get('revoked', False):
            # Get technique ID
            tech_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') in ('mitre-attack', 'mitre-attack-legacy'):
                    tech_id = ref.get('external_id')
                    break

            if tech_id and tech_id.startswith('T'):
                # Get tactics from kill_chain_phases
                tactics = []
                for phase in obj.get('kill_chain_phases', []):
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactics.append(phase.get('phase_name', '').replace('-', '_'))

                mapping[tech_id.upper()] = tactics

    return mapping

def calculate_rule_priority_score(rule: dict) -> int:
    """Calculate a priority score for a rule (higher is better)"""
    score = 0

    # Level scoring (most important)
    level_scores = {
        'critical': 100,
        'high': 50,
        'medium': 20,
        'low': 5,
        'informational': 1
    }
    score += level_scores.get(rule.get('level', 'medium'), 20)

    # Status scoring
    status_scores = {
        'stable': 30,
        'test': 20,
        'experimental': 10,
        'deprecated': 0
    }
    score += status_scores.get(rule.get('status', 'test'), 20)

    return score

def prioritize_rules(matches: list, max_rules: int = 100, max_per_technique: int = 3) -> list:
    """Prioritize and limit rules based on various criteria"""

    # Group by technique
    technique_to_matches = {}
    for match in matches:
        for tech in match['matching_techniques']:
            if tech not in technique_to_matches:
                technique_to_matches[tech] = []
            technique_to_matches[tech].append(match)

    # Sort techniques by number of rules (prioritize less-covered techniques)
    # Techniques with fewer rules are likely more unique/important
    sorted_techniques = sorted(technique_to_matches.items(), key=lambda x: len(x[1]))

    selected_rules = []
    selected_rule_ids = set()

    # First pass: Ensure at least 1 rule per technique
    for tech, tech_matches in sorted_techniques:
        # Score and sort rules for this technique
        scored = [(match, calculate_rule_priority_score(match['rule'])) for match in tech_matches]
        scored.sort(key=lambda x: x[1], reverse=True)

        # Add top rule if we haven't selected it yet
        for match, score in scored[:1]:
            rule_id = match['rule']['id']
            if rule_id not in selected_rule_ids:
                selected_rules.append(match)
                selected_rule_ids.add(rule_id)
                break

    # Second pass: Add more rules per technique up to max_per_technique
    for tech, tech_matches in sorted_techniques:
        scored = [(match, calculate_rule_priority_score(match['rule'])) for match in tech_matches]
        scored.sort(key=lambda x: x[1], reverse=True)

        added = 0
        for match, score in scored:
            rule_id = match['rule']['id']
            if rule_id not in selected_rule_ids:
                selected_rules.append(match)
                selected_rule_ids.add(rule_id)
                added += 1
                if added >= max_per_technique - 1:  # -1 because we added 1 in first pass
                    break

    # Third pass: If under max_rules, add highest scoring remaining rules
    if len(selected_rules) < max_rules:
        all_remaining = []
        for match in matches:
            if match['rule']['id'] not in selected_rule_ids:
                all_remaining.append((match, calculate_rule_priority_score(match['rule'])))

        all_remaining.sort(key=lambda x: x[1], reverse=True)

        for match, score in all_remaining:
            if len(selected_rules) >= max_rules:
                break
            selected_rules.append(match)
            selected_rule_ids.add(match['rule']['id'])

    # If still over max_rules, trim by score
    if len(selected_rules) > max_rules:
        scored = [(match, calculate_rule_priority_score(match['rule'])) for match in selected_rules]
        scored.sort(key=lambda x: x[1], reverse=True)
        selected_rules = [match for match, score in scored[:max_rules]]

    return selected_rules

# ============================================================================
# Main APT to Sigma Mapping
# ============================================================================

def find_rules_for_apt_group(group_name: str, filter_by_logsource: bool = True):
    """Find all Sigma rules that detect techniques used by an APT group"""
    print(f"Getting techniques for {group_name}...")
    apt_techniques = get_group_technique_ids(group_name)
    print(f"Found {len(apt_techniques)} techniques used by {group_name}")

    matching_rules = []
    total_rules = 0
    filtered_by_logsource = 0
    filtered_by_cve = 0
    filtered_by_malware = 0

    print("\nScanning Sigma rules...")
    for rule in iter_sigma_rules():
        total_rules += 1

        # Filter by available log sources if enabled
        if filter_by_logsource and not is_logsource_available(rule['logsource']):
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

        rule_techniques = extract_attack_ids_from_tags(rule['tags'])

        # Find overlapping techniques
        overlap = apt_techniques & rule_techniques

        if overlap:
            matching_rules.append({
                'rule': rule,
                'matching_techniques': overlap
            })

    print(f"Scanned {total_rules} Sigma rules")
    if filter_by_logsource:
        print(f"Filtered out {filtered_by_logsource} rules (log source not available)")
    print(f"Filtered out {filtered_by_cve} rules (CVE-specific)")
    print(f"Filtered out {filtered_by_malware} rules (malware-specific)")
    print(f"Found {len(matching_rules)} rules that detect {group_name} techniques\n")

    return matching_rules, apt_techniques

if __name__ == "__main__":
    # Multi-APT approach: Analyze multiple threat actors
    threat_actors = [
        "APT29",      # Russia - Government/Defense/Energy
        "APT28",      # Russia - Government/Military/Media
        "Lazarus",    # North Korea - Finance/Crypto/Defense
        "APT41",      # China - Healthcare/Tech/Telecom
        "FIN7"        # Cybercrime - Retail/Hospitality/Finance
    ]

    print("="*80)
    print("MULTI-THREAT ACTOR ANALYSIS")
    print("="*80)
    print(f"\nAnalyzing {len(threat_actors)} threat actors:")
    for actor in threat_actors:
        print(f"  - {actor}")

    # Get techniques for each APT
    apt_techniques_map = {}
    all_apt_techniques = set()

    print("\nGathering techniques for each threat actor...")
    for actor in threat_actors:
        try:
            techs = get_group_technique_ids(actor)
            apt_techniques_map[actor] = techs
            all_apt_techniques.update(techs)
            print(f"  {actor}: {len(techs)} techniques")
        except ValueError as e:
            print(f"  {actor}: Not found (skipping)")
            continue

    print(f"\nTotal unique techniques across all actors: {len(all_apt_techniques)}")

    # Find techniques used by multiple APTs (high-value targets)
    technique_apt_count = {}
    for tech in all_apt_techniques:
        count = sum(1 for actor_techs in apt_techniques_map.values() if tech in actor_techs)
        technique_apt_count[tech] = count

    multi_apt_techniques = {tech: count for tech, count in technique_apt_count.items() if count >= 2}
    print(f"Techniques used by multiple APTs: {len(multi_apt_techniques)}")

    # Use the union of all APT techniques for rule matching
    all_matches, _ = find_rules_for_apt_group(threat_actors[0], filter_by_logsource=True)

    # But actually we need to scan for all techniques
    # Let me rescan with combined techniques
    print(f"\nScanning for rules covering any of the {len(all_apt_techniques)} techniques...")

    matching_rules = []
    total_rules = 0
    filtered_by_logsource = 0
    filtered_by_cve = 0
    filtered_by_malware = 0

    for rule in iter_sigma_rules():
        total_rules += 1

        if not is_logsource_available(rule['logsource']):
            filtered_by_logsource += 1
            continue

        if is_cve_specific(rule):
            filtered_by_cve += 1
            continue

        if is_malware_specific(rule):
            filtered_by_malware += 1
            continue

        rule_techniques = extract_attack_ids_from_tags(rule['tags'])
        overlap = all_apt_techniques & rule_techniques

        if overlap:
            # Track which APTs this rule covers
            covered_apts = []
            for actor, actor_techs in apt_techniques_map.items():
                if overlap & actor_techs:
                    covered_apts.append(actor)

            matching_rules.append({
                'rule': rule,
                'matching_techniques': overlap,
                'covered_apts': covered_apts,
                'apt_count': len(covered_apts)
            })

    print(f"Found {len(matching_rules)} rules covering techniques from these threat actors")

    # Prioritize and limit rules
    MAX_RULES = 100
    MAX_PER_TECHNIQUE = 3

    print(f"\nPrioritizing rules (targeting {MAX_RULES} rules, max {MAX_PER_TECHNIQUE} per technique)...")
    matches = prioritize_rules(matching_rules, max_rules=MAX_RULES, max_per_technique=MAX_PER_TECHNIQUE)
    print(f"Selected {len(matches)} rules")

    # Print summary
    print("\n" + "="*80)
    print(f"PRIORITIZED SIGMA RULES - MULTI-THREAT ACTOR COVERAGE")
    print("="*80)

    # Group by technique
    technique_to_rules = {}
    for match in matches:
        for tech in match['matching_techniques']:
            if tech not in technique_to_rules:
                technique_to_rules[tech] = []
            technique_to_rules[tech].append(match)

    # Show coverage statistics
    covered_techniques = set(technique_to_rules.keys())
    uncovered_techniques = all_apt_techniques - covered_techniques

    print(f"\nCoverage: {len(covered_techniques)}/{len(all_apt_techniques)} techniques ({len(covered_techniques)/len(all_apt_techniques)*100:.1f}%)")
    print(f"Total rules: {len(matches)}")

    # Show multi-APT coverage stats
    multi_apt_rules = [m for m in matches if m.get('apt_count', 0) >= 2]
    print(f"Rules covering multiple APTs: {len(multi_apt_rules)}")

    # Show APT coverage
    print("\nThreat actor coverage:")
    for actor in apt_techniques_map.keys():
        actor_covered = sum(1 for m in matches if actor in m.get('covered_apts', []))
        actor_total = len(apt_techniques_map[actor])
        actor_matched = sum(1 for tech in apt_techniques_map[actor] if tech in covered_techniques)
        print(f"  {actor}: {actor_matched}/{actor_total} techniques ({actor_matched/actor_total*100:.1f}%) - {actor_covered} rules")

    # Show level distribution
    level_counts = {}
    for match in matches:
        level = match['rule'].get('level', 'medium')
        level_counts[level] = level_counts.get(level, 0) + 1

    print("\nRule severity distribution:")
    for level in ['critical', 'high', 'medium', 'low', 'informational']:
        if level in level_counts:
            print(f"  {level}: {level_counts[level]}")

    # KILL CHAIN COVERAGE ANALYSIS
    print("\n" + "="*80)
    print("KILL CHAIN (MITRE TACTICS) COVERAGE")
    print("="*80)

    # Get technique to tactic mapping
    tech_to_tactic = get_technique_to_tactic_mapping()

    # Map covered techniques to tactics
    tactic_coverage = {}
    all_tactics = set()

    for tech in all_apt_techniques:
        tactics = tech_to_tactic.get(tech, [])
        for tactic in tactics:
            all_tactics.add(tactic)
            if tactic not in tactic_coverage:
                tactic_coverage[tactic] = {'total': 0, 'covered': 0, 'rules': []}
            tactic_coverage[tactic]['total'] += 1

    for tech in covered_techniques:
        tactics = tech_to_tactic.get(tech, [])
        for tactic in tactics:
            if tactic in tactic_coverage:
                tactic_coverage[tactic]['covered'] += 1

    # Count rules per tactic
    for match in matches:
        for tech in match['matching_techniques']:
            tactics = tech_to_tactic.get(tech, [])
            for tactic in tactics:
                if tactic in tactic_coverage:
                    if match not in tactic_coverage[tactic]['rules']:
                        tactic_coverage[tactic]['rules'].append(match)

    # Show tactic coverage
    print("\nCoverage by MITRE ATT&CK Tactic:")
    tactic_order = [
        'reconnaissance', 'resource_development', 'initial_access', 'execution',
        'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
        'discovery', 'lateral_movement', 'collection', 'command_and_control',
        'exfiltration', 'impact'
    ]

    for tactic in tactic_order:
        if tactic in tactic_coverage:
            cov = tactic_coverage[tactic]
            pct = (cov['covered'] / cov['total'] * 100) if cov['total'] > 0 else 0
            rule_count = len(cov['rules'])
            status = "✓" if pct >= 50 else "⚠" if pct >= 25 else "✗"
            print(f"  {status} {tactic.replace('_', ' ').title():25} {cov['covered']:3}/{cov['total']:3} ({pct:5.1f}%) - {rule_count:3} rules")

    # Identify gaps
    weak_tactics = [t for t, c in tactic_coverage.items() if c['covered'] / c['total'] < 0.3]
    if weak_tactics:
        print(f"\n⚠ Weak coverage tactics (< 30%):")
        for tactic in weak_tactics:
            print(f"  - {tactic.replace('_', ' ').title()}")

    # TIERED DETECTION STRATEGY
    print("\n" + "="*80)
    print("TIERED DETECTION STRATEGY")
    print("="*80)

    # Organize rules into tiers based on severity
    tier1_rules = [m for m in matches if m['rule'].get('level') == 'critical']
    tier2_rules = [m for m in matches if m['rule'].get('level') == 'high']
    tier3_rules = [m for m in matches if m['rule'].get('level') in ('medium', 'low', 'informational')]

    print(f"\nTier 1 - Critical (Immediate Response): {len(tier1_rules)} rules")
    print("  High-fidelity detections requiring immediate investigation")
    print("  → Auto-alert, high-priority queue, potential auto-response")

    print(f"\nTier 2 - High (Investigation Queue): {len(tier2_rules)} rules")
    print("  Behavioral detections requiring analysis")
    print("  → Investigation queue, analyst review, correlate with other events")

    print(f"\nTier 3 - Medium/Low (Threat Hunting): {len(tier3_rules)} rules")
    print("  Hunt queries and low-confidence indicators")
    print("  → Proactive hunting, correlation, baseline deviations")

    # Show top multi-APT rules (high value targets)
    print("\n" + "="*80)
    print("HIGH-VALUE RULES (Cover Multiple Threat Actors)")
    print("="*80)

    multi_apt_sorted = sorted([m for m in matches if m.get('apt_count', 0) >= 2],
                               key=lambda x: (x.get('apt_count', 0), -len(x['matching_techniques'])),
                               reverse=True)

    print(f"\nTop 10 rules covering multiple APTs:")
    for i, match in enumerate(multi_apt_sorted[:10], 1):
        rule = match['rule']
        apt_list = ', '.join(match.get('covered_apts', []))
        level_badge = f"[{rule.get('level', 'medium').upper()}]"
        tech_count = len(match['matching_techniques'])
        print(f"\n{i}. {level_badge} {rule['title']}")
        print(f"   Covers {match.get('apt_count', 0)} APTs: {apt_list}")
        print(f"   Techniques: {tech_count} - {', '.join(sorted(list(match['matching_techniques']))[:5])}")

    # Show sample tier 1 rules
    print("\n" + "="*80)
    print("TIER 1 - CRITICAL RULES (Sample)")
    print("="*80)

    print(f"\nShowing first 15 critical rules:")
    for i, match in enumerate(tier1_rules[:15], 1):
        rule = match['rule']
        apt_list = ', '.join(match.get('covered_apts', [])[:3])
        tech_count = len(match['matching_techniques'])
        print(f"{i:2}. {rule['title']}")
        print(f"    APTs: {apt_list} | Techniques: {tech_count}")

    # Show uncovered techniques with tactics
    if uncovered_techniques:
        print("\n" + "="*80)
        print(f"DETECTION GAPS ({len(uncovered_techniques)} uncovered techniques)")
        print("="*80)

        # Group uncovered by tactic
        uncovered_by_tactic = {}
        for tech in uncovered_techniques:
            tactics = tech_to_tactic.get(tech, ['unknown'])
            for tactic in tactics:
                if tactic not in uncovered_by_tactic:
                    uncovered_by_tactic[tactic] = []
                uncovered_by_tactic[tactic].append(tech)

        for tactic in tactic_order:
            if tactic in uncovered_by_tactic:
                techs = uncovered_by_tactic[tactic]
                print(f"\n{tactic.replace('_', ' ').title()}: {len(techs)} techniques")
                for tech in sorted(techs)[:5]:  # Show first 5
                    print(f"  - {tech}")
                if len(techs) > 5:
                    print(f"  ... and {len(techs) - 5} more")

    print("\n" + "="*80)
    print("SUMMARY & RECOMMENDATIONS")
    print("="*80)

    print(f"\n✓ Deployed {len(matches)} rules covering {len(covered_techniques)} techniques")
    print(f"✓ {len(multi_apt_rules)} rules cover multiple threat actors (high ROI)")
    print(f"✓ Coverage across {len([t for t in tactic_coverage.values() if t['covered'] > 0])} MITRE tactics")

    if weak_tactics:
        print(f"\n⚠ Action Items:")
        print(f"  1. Weak tactic coverage in: {', '.join([t.replace('_', ' ').title() for t in weak_tactics[:3]])}")
        print(f"  2. Consider adding custom rules for {len(uncovered_techniques)} uncovered techniques")
        print(f"  3. Validate Tier 1 rules in test environment before production")

    print(f"\n💡 Next Steps:")
    print(f"  1. Deploy Tier 1 rules ({len(tier1_rules)}) with high-priority alerting")
    print(f"  2. Deploy Tier 2 rules ({len(tier2_rules)}) to investigation queue")
    print(f"  3. Use Tier 3 rules ({len(tier3_rules)}) for threat hunting")
    print(f"  4. Test with Atomic Red Team for covered techniques")
    print(f"  5. Tune false positives over 30-day baseline period")

    # Write rule IDs to file
    output_file = Path(__file__).parent / "rules.txt"
    with open(output_file, 'a') as f:
        for match in matches:
            rule_id = match['rule'].get('id')
            if rule_id:
                f.write(f"{rule_id}\n")

    print(f"\n✓ Appended {len(matches)} rule IDs to rules.txt")

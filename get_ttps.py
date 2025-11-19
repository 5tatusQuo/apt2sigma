import json
from pathlib import Path

# Load MITRE ATT&CK data directly
enterprise_attack_path = Path(__file__).parent / "enterprise-attack.json"
with open(enterprise_attack_path, 'r') as f:
    attack_data = json.load(f)

# Extract all objects
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

    # Find all relationships where this group uses techniques
    technique_ids = set()
    for obj in objects:
        if obj.get('type') == 'relationship':
            if obj.get('source_ref') == group_id and obj.get('relationship_type') == 'uses':
                target_ref = obj.get('target_ref', '')
                # Target could be a technique or software
                if target_ref.startswith('attack-pattern'):
                    # Find the technique and get its external ID
                    for tech in objects:
                        if tech.get('id') == target_ref:
                            for ref in tech.get('external_references', []):
                                if ref.get('source_name') in ('mitre-attack', 'mitre-attack-legacy'):
                                    ext_id = ref.get('external_id')
                                    if ext_id and ext_id.startswith('T'):
                                        technique_ids.add(ext_id.upper())

    return technique_ids

# Get APT29 techniques
apt29_tech_ids = get_group_technique_ids("APT29")
print(apt29_tech_ids)

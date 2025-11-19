# APT to Sigma

Map APT threat actors to Sigma detection rules based on available log sources.

## Overview

Two scripts analyze Sigma rules against multiple APT groups (APT29, APT28, Lazarus, APT41, FIN7):
- **apt2sigma.py** - Maps APT techniques to standard Sigma rules
- **emerging_threats.py** - Catalogs emerging threat rules for your log sources

Both filter out CVE-specific and malware-specific rules (handled by Microsoft Defender XDR).

## Setup

```bash
# Create venv and install dependencies
python3 -m venv .
./bin/pip install pyyaml attackcti

# Clone Sigma repository
git clone https://github.com/SigmaHQ/sigma

# Download MITRE ATT&CK data
curl -L -o enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

## Usage

```bash
# Analyze APT-focused rules (100 rules, 41.9% coverage)
./bin/python apt2sigma.py

# Analyze emerging threat rules (71 rules)
./bin/python emerging_threats.py

# Both scripts append rule IDs to rules.txt
```

## Configuration

Edit `logsources.yml` to match your available log sources (Microsoft Defender for Endpoint, Azure, M365).

## Output

- **Multi-APT coverage** - Shows which rules cover multiple threat actors
- **Kill chain analysis** - Coverage by MITRE ATT&CK tactics
- **Tiered strategy** - Critical/High/Medium rules for different response levels
- **rules.txt** - Rule IDs for deployment (deduplicate before use)

## Results

- ~145 total rules (after deduplication)
- 98 unique techniques covered (41.9% of APT techniques)
- 71% of rules cover multiple APT groups

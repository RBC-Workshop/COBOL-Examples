import json
from collections import defaultdict

with open("snyk-results.json") as f:
    results = json.load(f)

grouped = defaultdict(list)

if "vulnerabilities" in results:
    for proj in results.get("vulnerabilities", []):
        for vuln in proj.get("vulnerabilities", []):
            grouped[vuln["id"]].append(vuln)
else:
    print("No vulnerabilities section found in results")

if grouped:
    for vid, items in grouped.items():
        print(f"{vid}: {len(items)} occurrence(s)")
else:
    print("No vulnerabilities found to group")
    print("Scan results summary:")
    if "error" in results:
        print(f"  Error: {results['error']}")
    if "ok" in results:
        print(f"  Status: {'Success' if results['ok'] else 'No supported files detected'}")

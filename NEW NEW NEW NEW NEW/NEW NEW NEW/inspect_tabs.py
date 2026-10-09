import re

with open("hexstrike_server.py", "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

tabs = ['sast-sca', 'sast', 'sca', 'dast', 'dns', 'ssl', 'csv', 'unified']

for t in tabs:
    m = re.search(r'(<div id="tab-' + t + r'".*?)(?=<div id="tab-|\</body\>)', content, re.DOTALL)
    if m:
        c = m.group(1)
        print(f"=== {t} ===")
        for pattern in ['status-badge', 'gauge', 'tabs-bar', 'filter-bar', 'cards-view', 'md-view', 'output', 'score-val', 'rating-val', 'findings-val', 'severity-pills', 'count-val', 'count-badge', 'search-input']:
            found = re.findall(r'id="([^"]*' + pattern + r'[^"]*)"', c)
            print(f"  {pattern}: {found}")
    else:
        print(f"=== {t} NOT FOUND ===")

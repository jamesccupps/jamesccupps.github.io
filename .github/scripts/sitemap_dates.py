#!/usr/bin/env python3
"""Move each <lastmod> in sitemap.xml forward to the day its page last changed.

Most pages on this site are published from their own repositories, so editing
one doesn't touch this sitemap. For every URL in it, this asks the GitHub API
for the newest commit to that page's source and, if it's later than the
<lastmod>, moves the date up to that day (UTC). It never moves a date back, so
a date set by hand to a later day stands.

    python3 .github/scripts/sitemap_dates.py           # update sitemap.xml
    python3 .github/scripts/sitemap_dates.py --check   # report only; exit 1 if a date is behind

GITHUB_TOKEN, when set, is sent for the API's higher rate limit; without it the
script still works for a sitemap this size (one request per URL, 60 an hour).
A URL the API can't answer for keeps its date and is reported as a warning.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

OWNER = "jamesccupps"
SITE = "https://jamesccupps.github.io/"
HUB = "jamesccupps.github.io"
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SITEMAP = os.path.join(ROOT, "sitemap.xml")

# Where a page's source lives, as (repository, path). A path ending in "/" is a
# folder, so a change to anything in it (screenshots included) counts.
# Pages not listed are found by the rules in sources().
SOURCES = {
    "": [(HUB, "index.html")],
    "Wetbulb/": [("Wetbulb", "index.html")],
    "CoolingTowerSim/": [("CoolingTowerSim", "index.html")],
    "Airflow-Lab/app/": [("Airflow-Lab", "js/")],     # the app itself, published under app/ by its Pages workflow
    "Reef/": [("Reef", "index.html")],
    "Reef/paper/": [("Reef", "paper/index.html")],
}


def sources(rel):
    """Candidate (repository, path) pairs for a site path such as 'PingerPlot/'."""
    if rel in SOURCES:
        return SOURCES[rel]
    seg, _, rest = rel.partition("/")
    if os.path.isdir(os.path.join(ROOT, seg)):          # a folder of this repository: p2/, PPCL/ ...
        return [(HUB, rel)]
    if not rest:                                         # a project site's front page
        return [(seg, "site/"), (seg, "index.html")]
    return [(seg, rest), (seg, "site/" + rest)]          # a page inside a project site


def api(path):
    req = urllib.request.Request("https://api.github.com/" + path, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "sitemap-dates",
        **({"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"]} if os.environ.get("GITHUB_TOKEN") else {}),
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def last_change(repo, path):
    """The UTC day of the newest commit touching path in repo, or None if none does."""
    q = urllib.parse.urlencode({"path": path.rstrip("/"), "per_page": 1})
    commits = api(f"repos/{OWNER}/{repo}/commits?{q}")
    return commits[0]["commit"]["committer"]["date"][:10] if commits else None


def main():
    check = "--check" in sys.argv[1:]
    text = open(SITEMAP, encoding="utf-8").read()
    changed, warnings = [], 0

    def update(m):
        nonlocal warnings
        url, current = m.group(2), m.group(4)
        if not url.startswith(SITE):
            return m.group(0)
        rel = url[len(SITE):]
        try:
            day = next((d for d in (last_change(r, p) for r, p in sources(rel)) if d), None)
        except (urllib.error.URLError, KeyError, ValueError) as e:
            print(f"::warning title=sitemap dates::{url}: {e}")
            warnings += 1
            return m.group(0)
        if day is None:
            print(f"::warning title=sitemap dates::{url}: no commits found for {sources(rel)}")
            warnings += 1
            return m.group(0)
        if day <= current:
            return m.group(0)
        changed.append(f"{url}  {current} -> {day}")
        return m.group(1) + m.group(2) + m.group(3) + day + m.group(5)

    new = re.sub(r"(<loc>)([^<]+)(</loc>\s*<lastmod>)([^<]+)(</lastmod>)", update, text)
    for line in changed:
        print(line)
    if not changed:
        print("Every date is current." + (f" ({warnings} URL(s) skipped.)" if warnings else ""))
    if check:
        return 1 if changed else 0
    if new != text:
        with open(SITEMAP, "w", encoding="utf-8", newline="") as f:
            f.write(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())

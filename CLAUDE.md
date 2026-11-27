# jamesccupps.github.io: notes for Claude Code

James's GitHub Pages user site. No one chat owns this repository: whichever chat works on it reads this first, and
keeps it current.

## Start here

- `git pull` first. A daily job commits to `main` (the sitemap dates, below).
- James works on `main` and has allowed pushing to it directly. Commit as
  `James Cupps <148652101+jamesccupps@users.noreply.github.com>`.

## What is here, and what isn't

- `index.html`: the hub, the DOS-terminal page ("CUPPS.EXE"). The page text is plain HTML, so search engines read it
  without running the script; the terminal is built on top of it.
- `p2/index.html`: the APOGEE P2 (Protocol II) technical reference. The old addresses `/protocol.html` and
  `/security.html` are gone on purpose (they 404); `/p2/` replaced them.
- `PPCL/`, `HVACTrend/`, `Light-Beam/`: the project pages for repositories that don't publish their own site. GitHub
  Pages serves `/<repo>/` from that repository when it has Pages turned on, and falls through to this repository's
  folder of the same name otherwise. If one of those repositories ever turns on its own Pages, its site replaces the
  folder here: move the page there and delete the folder.
- Every other project page (`/Slate/`, `/NoteForge/`, `/Wetbulb/`, `/Reef/`, the two games `/PocketMaine/` and
  `/EightFold/`, and the rest) is published from its own
  repository and edited there, not here. Only its entry in `sitemap.xml` lives here.
  `/Airflow-Lab/` (Nov 27) has two addresses in the sitemap: its project page, and the app itself at
  `/Airflow-Lab/app/`.
- `404.html` (`noindex`), `og.png` (the hub's social image), `favicon.ico`, `fonts/` (with its OFL license),
  `robots.txt`, `sitemap.xml`.
- `6f4669f95049414a71045ac20c1d6046.txt`: the IndexNow key. Public by design; it must stay at the root.
- Published from `main` by GitHub Pages with Jekyll, so nothing starting with `.` or `_` is published (`.github/`
  isn't, which is intended). This file is published as a plain file at `/CLAUDE.md`, like any file without
  front matter; `robots.txt` keeps `.md` files out of search.

## Search

- Every page keeps: a `<title>` of 60 characters or less, a meta description of 160 or less, a canonical link,
  `og:*` tags with an image, and JSON-LD. James is described as a facilities director: no employer, city or state.
  `/EightFold/` has only a `<title>` so far (Nov 23); the rest of that list is to add in its own repository.
- `sitemap.xml` lists every page of the site, including the pages other repositories publish (29 addresses on
  Nov 27). Add a new page there when it goes up. `robots.txt` points to it and keeps raw `.md` files and Slate's apt
  repository out of search.
- `<lastmod>` dates are kept by `.github/workflows/sitemap-dates.yml`, daily at 10:37 UTC (GitHub sometimes starts
  it hours late). `.github/scripts/sitemap_dates.py` finds the newest commit to each page's source and moves the date
  forward only; if one moved, the job commits and asks Pages to rebuild. Run it by hand from Actions → Sitemap dates;
  `python .github/scripts/sitemap_dates.py --check` reports without changing anything. A page whose source isn't
  where the script looks (this repository's folder, or another repository's `site/index.html` or `index.html`)
  needs an entry in its `SOURCES`, or the job warns and leaves that date alone.
- `.github/workflows/indexnow.yml` runs after each Pages build and tells Bing (and the other IndexNow engines) the
  site changed. A failed ping is a warning, never a failed build.
- The sitemap is submitted to Google Search Console and Bing Webmaster Tools (James's accounts, in his browser).
  In Search Console it is submitted twice, as `/sitemap.xml` (Nov 16) and `/sitemap.xml?v=2` (Nov 23), because the
  first sat at "Couldn't fetch" with no "Last read" date, meaning Google never read it. Same file either way.
- `/UnifiStockWatcher/` has never been crawled by Google, despite weeks of indexing requests, while Protect Panes'
  page (same template, same launch day, same hub section) is indexed. `/UnifiStockWatcher/how-it-works/` (Nov 23)
  is the test: if Google crawls it, the front page's URL is stuck; if not, Google is skipping that site.

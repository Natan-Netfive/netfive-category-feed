#!/usr/bin/env python3
"""Netfive Category Feed builder.

Gera dist/feed.json (consumido pelo app Foundry), dist/categories.csv (formato de
importação do app v1.1: category,url) e dist/manifest.json (versão + sha256).

Ordem de prioridade por categoria:
  1. Curadoria Netfive (curated: em config/categories.yaml) -> sempre entra
  2. Wildcards de categoria (ex.: *.bet.br)               -> sempre entra
  3. Varredura proativa (scan: na categoria; scripts/game_scan.py): sites encontrados no
     Tranco Top 1M por nome + conteúdo + categorias da Cloudflare, que nenhuma lista cobre
  4. Fontes externas (UT1, Hagezi), filtradas por popularidade (Tranco) quando disponível,
     ordenadas pelo ranking e cortadas em max_domains.
"""
import csv, datetime, hashlib, io, json, os, re, sys, urllib.request, zipfile, zlib
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import game_scan  # noqa: E402  pylint: disable=wrong-import-position

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "state")
CFG = yaml.safe_load(open(os.path.join(ROOT, "config", "categories.yaml"), encoding="utf-8"))
DIST = os.path.join(ROOT, "dist")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def log(*a):
    print(*a, file=sys.stderr, flush=True)


MAX_DOWNLOAD = 200_000_000        # bytes, compressed or not (the Tranco zip is ~10 MB, lists < 100 MB)


def fetch(url, timeout=120):
    """Download a source list with size caps (also after gunzip: no decompression bombs)."""
    if not url.startswith("https://"):
        raise ValueError(f"only https sources are allowed: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "netfive-category-feed/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError(f"{url}: larger than {MAX_DOWNLOAD} bytes")
    if url.endswith(".gz") or data[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        data = d.decompress(data, MAX_DOWNLOAD + 1)
        if len(data) > MAX_DOWNLOAD or d.unconsumed_tail:
            raise ValueError(f"{url}: larger than {MAX_DOWNLOAD} bytes once decompressed")
    return data


def parse_domains(text):
    out = set()
    for line in text.splitlines():
        d = line.split("#", 1)[0].strip().lower().lstrip("*.").rstrip(".")
        if d.startswith("www."):
            d = d[4:]
        if DOMAIN_RE.match(d):
            out.add(d)
    return out


def load_tranco(url, top):
    try:
        z = zipfile.ZipFile(io.BytesIO(fetch(url, 300)))
        rank = {}
        with z.open(z.namelist()[0]) as f:
            for line in io.TextIOWrapper(f, encoding="utf-8"):
                r, d = line.strip().split(",", 1)
                if int(r) > top:
                    break
                rank[d.lower()] = int(r)
        log(f"[tranco] {len(rank)} domínios carregados")
        return rank
    except Exception as e:
        log(f"[tranco] indisponível ({e}); seguindo sem ranking de popularidade")
        return None


def covered(domain, keep):
    """True se o domínio já é coberto por um pai presente em keep (o app adiciona *.pai)."""
    parts = domain.split(".")
    return any(".".join(parts[i:]) in keep for i in range(1, len(parts) - 1))


# Names on the Public Suffix List that appear in the sources (Falcon refuses globs on them)
PUBLIC_SUFFIXES = set(game_scan.MULTI_SUFFIXES) | {
    "bet.br", "game-host.org", "game-server.cc", "netgamers.jp", "servegame.com", "servegame.org", "vpnplus.to",
    "azurewebsites.net", "cloudfront.net", "appspot.com", "s3.amazonaws.com", "workers.dev"}
# Public suffixes that exist only for one kind of site: they may be listed (same list as the app's safety.py)
BLOCKABLE_SUFFIXES = {"bet.br", "itch.io", "servegame.com", "servegame.org", "netgamers.jp", "game-host.org",
                      "game-server.cc", "vpnplus.to"}
# A source list adding a site this popular (Tranco rank) that was not in the previous feed is held back
# for a human: it is how a compromised or mistaken upstream list would break thousands of customers.
NEW_POPULAR_RANK = 1000


def protects(name, never):
    """The never_block entry that `name` would block, or None. The app deploys every name as "name" +
    "*.name", so a name blocks a never_block entry when it is that entry or one of its parents. A
    specific product under a protected domain (gemini.google.com) stays allowed; the app's own
    safety.py adds the critical subdomains (login, update) that can never be blocked."""
    if name in never:
        return name
    return next((n for n in never if n.endswith("." + name)), None)


def acceptable(name, never):
    """Whether a domain may go into the feed (not a public suffix, not covering a never_block name)."""
    if "." not in name or (name in PUBLIC_SUFFIXES and name not in BLOCKABLE_SUFFIXES):
        return False
    return protects(name, never) is None


def previous_feed():
    """Domains per category of the feed currently published (empty on the first build)."""
    try:
        old = json.load(open(os.path.join(DIST, "feed.json"), encoding="utf-8"))
        return {c: set(v.get("domains") or []) for c, v in (old.get("categories") or {}).items()}
    except (OSError, ValueError):
        return {}


def make_single_safe(rank, never, min_label):
    """
    Decide when a domain may be deployed as ONE dotless wildcard entry, "*example.com", instead of
    the "example.com" + "*.example.com" pair. Falcon accepts it and it matches example.com and every
    subdomain, but also any name that merely ends with the same text ("*in.com" would block
    linkedin.com). It is used only when:
      - the first label has at least `min_label` characters, and
      - no other name of the Tranco Top 1M nor of never_block ends with it (lookalike collision), and
      - it is not a public suffix.
    Without a Tranco ranking nothing is considered safe (every domain keeps the pair).
    """
    if not rank:
        return lambda _x: False
    known = list(rank) + list(never)
    by_tail = {}
    for name in known:
        by_tail.setdefault(name[-6:], []).append(name)

    def safe(x):
        if len(x.split(".")[0]) < min_label or x in PUBLIC_SUFFIXES or x.count(".") < 1:
            return False
        for name in by_tail.get(x[-6:], ()):
            if name != x and name.endswith(x) and not name.endswith("." + x):
                return False
        return True
    return safe


def main():
    d = CFG["defaults"]; src = CFG["sources"]
    never = {x.lower() for x in CFG.get("never_block", [])}
    rank = load_tranco(src["tranco"], d["popularity_top"])
    cache, feed_cats, csv_rows = {}, {}, []
    before = previous_feed()
    held = []

    # 1ª passada: fontes externas de todas as categorias (a varredura ignora o que já está listado)
    externals, used_by = {}, {}
    for cat, spec in CFG["categories"].items():
        external, used = set(), []
        if not spec.get("curated_only"):
            for kind in ("ut1", "hagezi"):
                for lst in spec.get(kind, []):
                    url = src[kind].format(list=lst)
                    if url not in cache:
                        try:
                            cache[url] = parse_domains(fetch(url).decode("utf-8", "ignore"))
                            log(f"[{kind}:{lst}] {len(cache[url])} domínios")
                        except Exception as e:
                            log(f"[{kind}:{lst}] falhou: {e}"); cache[url] = set()
                    external |= cache[url]; used.append(f"{kind}:{lst}")
        externals[cat], used_by[cat] = external, used
    listed = set().union(*externals.values()) | {
        x.lower() for items in (CFG.get("curated") or {}).values() for x in items}
    single_safe = make_single_safe(rank, never, d.get("single_entry_min_label", 6))

    for cat, spec in CFG["categories"].items():
        limit = spec.get("max_domains", d["max_domains"])
        curated = [x.lower() for x in CFG.get("curated", {}).get(cat, []) if DOMAIN_RE.match(x.lower())]
        external, used = externals[cat], used_by[cat]

        discovered = []
        scan_cfg = spec.get("scan")
        if scan_cfg and scan_cfg.get("enabled", True) and os.environ.get("SCAN_ENABLED", "1") != "0":
            if rank is None:
                log(f"[scan:{cat}] sem ranking Tranco; varredura não executada")
            else:
                cache_path = os.path.join(STATE, scan_cfg.get("cache", f"scan_{cat}.json"))
                discovered = game_scan.run_scan(rank, listed, never, cache_path, scan_cfg)
                used = used + ["netfive:scan"]

        # never_block protects the name, its subdomains and against parents that cover it; public
        # suffixes are never listed (except the single-purpose ones in BLOCKABLE_SUFFIXES)
        external = {x for x in external if acceptable(x, never)}
        if rank is not None:
            ranked = sorted((x for x in external if x in rank), key=lambda x: rank[x])
        else:  # sem ranking: prioriza domínios curtos (registráveis) e ordem estável
            ranked = sorted(external, key=lambda x: (x.count("."), len(x), x))
        old = before.get(cat)
        if old is not None and rank is not None:
            new_popular = [x for x in ranked if rank[x] <= NEW_POPULAR_RANK and x not in old]
            if new_popular:
                held += [f"{cat}: {x} (Tranco #{rank[x]})" for x in new_popular]
                ranked = [x for x in ranked if x not in set(new_popular)]

        keep = [x for x in curated if acceptable(x, never)]
        keep_set = set(keep)
        for x in discovered:   # varredura: antes das listas externas, para não ser cortada
            if len(keep) >= limit:
                break
            if x not in keep_set and acceptable(x, never) and not covered(x, keep_set):
                keep.append(x); keep_set.add(x)
        for x in ranked:
            if len(keep) >= limit:
                break
            if x not in keep_set and not covered(x, keep_set):
                keep.append(x); keep_set.add(x)

        wild = [w.lower() for w in spec.get("wildcards", []) if acceptable(w.lower(), never)]
        # fqdns: the classic form (x + *.x) every app version reads.
        # fqdns_single: same domains, but a safe domain becomes ONE dotless entry "*x" (read by app v3.4+,
        # so a policy holds about twice as many domains under the sensor's ~10,600-entry limit).
        fqdns, fqdns_single, single = [], [], 0
        for w in wild:
            fqdns.append(f"*.{w}")
            fqdns_single.append(f"*.{w}")
        for x in keep:
            fqdns.append(x)
            if d["add_wildcard"]:
                fqdns.append(f"*.{x}")
            if d["add_wildcard"] and single_safe(x):
                fqdns_single.append(f"*{x}")
                single += 1
            else:
                fqdns_single.append(x)
                if d["add_wildcard"]:
                    fqdns_single.append(f"*.{x}")

        feed_cats[cat] = {
            "domains": keep, "wildcards": wild, "fqdns": fqdns, "fqdns_single": fqdns_single, "fqdn_single_count": len(fqdns_single),
            "count": len(keep), "fqdn_count": len(fqdns),
            "curated": len(curated), "discovered": len(discovered), "external_candidates": len(external),
            "single_entry": single,
            "sources": ["netfive:curated"] + used,
        }
        for x in wild:
            csv_rows.append((cat, f"*.{x}"))
        for x in keep:
            csv_rows.append((cat, x))
        log(f"=> {cat}: {len(keep)} domínios ({len(fqdns)} FQDNs) | candidatos externos {len(external)}")

    os.makedirs(DIST, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    feed = {
        "schema": "netfive.category-feed/v1",
        "version": now.strftime("%Y.%m.%d.%H%M"),
        "generated_at": now.isoformat(timespec="seconds"),
        "popularity_ranking": rank is not None,
        "attribution": "Inclui dados de UT1 Blacklists (Université Toulouse Capitole, CC BY-SA 4.0) e Hagezi DNS Blocklists (GPL-3.0).",
        "never_block": sorted(never),
        "categories": feed_cats,
    }
    blob = json.dumps(feed, ensure_ascii=False, indent=1).encode("utf-8")
    open(os.path.join(DIST, "feed.json"), "wb").write(blob)
    with open(os.path.join(DIST, "categories.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["category", "url"]); w.writerows(csv_rows)
    manifest = {"version": feed["version"], "generated_at": feed["generated_at"],
                "sha256": hashlib.sha256(blob).hexdigest(),
                "categories": {k: v["count"] for k, v in feed_cats.items()}}
    json.dump(manifest, open(os.path.join(DIST, "manifest.json"), "w"), indent=1)
    if held:
        # Not an error: these stay out until a person adds them to `curated` in config/categories.yaml
        log(f"[held] {len(held)} sites populares novos vindos de listas externas, fora do feed até revisão:")
        for item in held[:100]:
            log(f"  {item}")
        with open(os.path.join(DIST, "held.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(held) + "\n")
    log(f"OK versão {feed['version']} sha256 {manifest['sha256'][:16]}…")


if __name__ == "__main__":
    main()

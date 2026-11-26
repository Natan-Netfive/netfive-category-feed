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
import csv, datetime, gzip, hashlib, io, json, os, re, sys, urllib.request, zipfile
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


def fetch(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "netfive-category-feed/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    if url.endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
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


def main():
    d = CFG["defaults"]; src = CFG["sources"]
    never = {x.lower() for x in CFG.get("never_block", [])}
    rank = load_tranco(src["tranco"], d["popularity_top"])
    cache, feed_cats, csv_rows = {}, {}, []

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

        external -= never
        if rank is not None:
            ranked = sorted((x for x in external if x in rank), key=lambda x: rank[x])
        else:  # sem ranking: prioriza domínios curtos (registráveis) e ordem estável
            ranked = sorted(external, key=lambda x: (x.count("."), len(x), x))

        keep = [x for x in curated if x not in never]
        keep_set = set(keep)
        for x in discovered:   # varredura: antes das listas externas, para não ser cortada
            if len(keep) >= limit:
                break
            if x not in keep_set and x not in never and not covered(x, keep_set):
                keep.append(x); keep_set.add(x)
        for x in ranked:
            if len(keep) >= limit:
                break
            if x not in keep_set and not covered(x, keep_set):
                keep.append(x); keep_set.add(x)

        wild = [w.lower() for w in spec.get("wildcards", [])]
        fqdns = []
        for w in wild:
            fqdns.append(f"*.{w}")
        for x in keep:
            fqdns.append(x)
            if d["add_wildcard"]:
                fqdns.append(f"*.{x}")

        feed_cats[cat] = {
            "domains": keep, "wildcards": wild, "fqdns": fqdns,
            "count": len(keep), "fqdn_count": len(fqdns),
            "curated": len(curated), "discovered": len(discovered), "external_candidates": len(external),
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
    log(f"OK versão {feed['version']} sha256 {manifest['sha256'][:16]}…")


if __name__ == "__main__":
    main()

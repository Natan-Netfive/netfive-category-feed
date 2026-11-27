#!/usr/bin/env python3
"""Varredura proativa de sites de jogos para o Netfive Category Feed.

Nao depende de telemetria: parte do ranking Tranco (Top 1M) e encontra sites de jogos
antes que algum host os acesse.

  1. Candidatos por nome: dominios do Tranco cujo nome sugere jogo (game, jogos, play, friv,
     .io, .gg ...) e que nenhuma fonte externa ja classifica.
  2. Analise de conteudo: baixa a pagina inicial e pontua com a MESMA heuristica do
     classificador do app (SDKs/engines de jogos, iframes de jogo, frases, titulo).
  3. Cloudflare (opcional, CF_API_TOKEN + CF_ACCOUNT_ID): categorias de conteudo da
     Cloudflare (Intel API) para os candidatos e para os dominios mais populares do Tranco
     que nenhuma lista cobre (pega sites cujo nome nao denuncia o jogo).

Decisao (o feed vale para todos os clientes):
  - heuristica forte (score >= STRONG_SCORE e sinal jogavel)              -> bloquear
  - Cloudflare "Gaming" sem "Education"                                   -> bloquear
  - Cloudflare "Gaming" + "Education" com score >= BLOCK_SCORE e jogavel  -> bloquear
  - o resto nao entra (fica no cache como review/clean/error)

O cache (state/scan_cache.json) guarda o resultado de cada dominio; cada execucao so reanalisa
os novos e os vencidos, dentro de um orcamento de tempo, para caber no GitHub Actions.
"""
import datetime
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

BLOCK_SCORE = 8
STRONG_SCORE = 16
NAME_SCORE = 12      # basta isto quando o próprio nome do domínio já indica jogo
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/130.0.0.0 Safari/537.36")
MAX_BYTES = 400_000
FQDN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def validate_fqdn(fqdn: str) -> bool:
    return bool(FQDN_RE.match(fqdn or ""))


# ---- heuristica: copiada de urlblock/handlers/classifier.py (manter as duas iguais) ----------
# Second-level public suffixes seen in Brazil/LatAm and elsewhere (registrable domain = one more label)
MULTI_SUFFIXES = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "bet.br", "art.br", "blog.br", "eco.br", "emp.br",
    "ind.br", "inf.br", "jus.br", "leg.br", "mil.br", "srv.br", "tv.br", "app.br", "dev.br", "log.br",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.ar", "com.mx", "com.co", "com.pe", "com.cl", "com.uy",
    "com.py", "com.bo", "com.ve", "com.ec", "com.au", "net.au", "co.nz", "co.jp", "co.kr", "co.in",
    "com.tr", "com.cn", "com.hk", "com.tw", "com.sg", "co.za", "com.pt", "com.es", "com.ru",
    "github.io", "netlify.app", "vercel.app", "pages.dev", "web.app", "firebaseapp.com",
    "herokuapp.com", "itch.io", "blogspot.com", "wordpress.com",
}
INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".corp", ".home", ".arpa", ".localdomain", ".intranet",
                     ".invalid", ".test", ".example", ".localhost")

PLAYABLE_MARKERS = {  # game SDKs, engines and embed hosts: weight 4 each
    "gamedistribution.com": "SDK GameDistribution", "gd_sdk": "SDK GameDistribution",
    "gamemonetize": "SDK GameMonetize", "famobi": "Famobi", "playhop": "Playhop",
    "poki-sdk": "SDK Poki", "poki.com/sdk": "SDK Poki", "sdk.crazygames": "SDK CrazyGames",
    "crazygames-sdk": "SDK CrazyGames", "gamepix": "GamePix", "gamesnacks": "GameSnacks",
    "yandex.ru/games": "Yandex Games", "yandex.com/games": "Yandex Games",
    # "ysdk" alone matched minified code on google.com.br / withgoogle.com: use the SDK's init call
    "yagames.init": "Yandex Games SDK", "gamezop": "Gamezop",
    "gamearter": "GameArter", "softgames": "Softgames", "gamejolt": "GameJolt",
    "itch.io/embed": "itch.io embed", "unityloader": "Unity WebGL", "createunityinstance": "Unity WebGL",
    "unityframework": "Unity WebGL", ".unityweb": "Unity WebGL", "c3runtime": "Construct 3",
    "construct 3": "Construct 3", "phaser.min.js": "Phaser", "phaser.js": "Phaser",
    "ruffle.js": "Ruffle (Flash)", "@ruffle-rs": "Ruffle (Flash)", "game-iframe": "iframe de jogo",
    "gameiframe": "iframe de jogo", "game_iframe": "iframe de jogo", "game-frame": "iframe de jogo",
    "gameframe": "iframe de jogo", "html5games": "HTML5 games", "kiz10": "Kiz10", "addictinggames": "AddictingGames",
    "miniclip": "Miniclip", "iogames": "io games", "coolmathgames": "Coolmath",
}
PLAY_PHRASES = [  # weight 2 each, at most 5 counted; any of them is a "playable" signal
    "jogos online", "jogos grátis", "jogos gratis", "jogar grátis", "jogar gratis", "jogar agora",
    "jogue grátis", "jogue gratis", "jogue agora", "jogos de corrida", "jogos de tiro", "jogos de luta",
    "jogos de meninas", "jogos de futebol", "jogos de carro", "jogos io", "jogos de 2 jogadores",
    "jogos para 2", "novos jogos", "jogos populares", "jogos friv", "jogos de aventura", "jogos de quebra-cabeça",
    "free online games", "play free", "play online games", "play now", "browser games", "html5 games",
    "io games", "2 player games", "racing games", "shooting games", "puzzle games", "arcade games",
    "action games", "multiplayer games", "unblocked games", "games for kids", "play games online",
    "juegos gratis", "juegos online", "jugar gratis", "juegos de", "jugar ahora",
]
TITLE_WORDS = re.compile(r"\b(games?|jogos?|juegos?|arcade|friv|play)\b", re.I)
DOMAIN_STRONG = re.compile(r"(games?|jogos?|juegos?|friv|kizi|arcade|poki|y8|gamer|minijogos|clickjogos)", re.I)
WORD_COUNT = re.compile(r"\b(games?|jogos?|juegos?)\b", re.I)
# Bounded quantifiers: the HTML is untrusted (same as the app's classifier)
TITLE_RE = re.compile(r"<title[^>]{0,200}>(.{0,1000}?)</title>", re.I | re.S)
META_RE = re.compile(r'<meta[^>]{0,300}name=["\'](?:description|keywords)["\'][^>]{0,300}content=["\']([^"\']{0,1000})',
                     re.I)


class _PublicOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to http(s) names that resolve to public addresses."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise urllib.error.URLError("redirect to an unsupported URL")
        for info in socket.getaddrinfo(parts.hostname, parts.port or 443, type=socket.SOCK_STREAM):
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            if not ip.is_global:
                raise urllib.error.URLError("redirect to a non-public address")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_PublicOnlyRedirects)
_OPENER.addheaders = []


def registrable(fqdn: str) -> str:
    """example.com for a.b.example.com; example.com.br for www.example.com.br."""
    labels = fqdn.strip(".").lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_candidate(fqdn: str) -> bool:
    if not fqdn or "." not in fqdn or fqdn.endswith(INTERNAL_SUFFIXES):
        return False
    if re.fullmatch(r"[\d.]+", fqdn) or ":" in fqdn:
        return False
    return validate_fqdn(fqdn)


def score_page(domain: str, html: str) -> dict:
    """Score a page. Returns {"score", "signals", "playable", "title"}."""
    text = html.lower()
    signals, score, playable = [], 0, False
    seen_markers = set()
    for marker, label in PLAYABLE_MARKERS.items():
        if marker in text and label not in seen_markers:
            seen_markers.add(label)
            signals.append(label)
            score += 4
            playable = True
    phrases = [p for p in PLAY_PHRASES if p in text]
    # One English phrase alone ("play now", "action games") also appears on news and stores
    pt_es = [p for p in phrases if p.startswith(("jog", "jueg", "jug", "novos"))]
    if pt_es or len(phrases) >= 2:
        playable = True
    if phrases:
        score += 2 * min(len(phrases), 5)
        signals.append("frases: " + ", ".join(phrases[:5]))
    title_m = TITLE_RE.search(html)
    title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:150] if title_m else ""
    meta = " ".join(META_RE.findall(html))[:500]
    if TITLE_WORDS.search(title) or TITLE_WORDS.search(meta):
        score += 3
        signals.append("título/descrição de jogos")
    if DOMAIN_STRONG.search(domain.split(".")[0]):
        score += 3
        signals.append("nome do domínio")
    words = len(WORD_COUNT.findall(text))
    if words >= 30:
        score += 2
        signals.append(f"{words} menções a jogos")
    return {"score": score, "signals": signals, "playable": playable, "title": title}


# ---- varredura ----------------------------------------------------------------------------
NAME_RE = re.compile(r"(games?|gaming|jogos?|juegos?|jeux|spiele|friv|arcade|kizi|poki|y8|minijogos|"
                     r"clickjogos|unblocked|gamer|playgam|^play|play$|io-?games)", re.I)
SCAN_TLDS = (".io", ".gg", ".games", ".fun")
CF_GAMING = re.compile(r"gam(e|es|ing)", re.I)
CF_EDUCATION = re.compile(r"educat", re.I)


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def name_candidates(rank: dict) -> list:
    """Dominios do Tranco que parecem de jogos pelo nome ou TLD, do mais popular ao menos."""
    out = [d for d in rank if d.endswith(SCAN_TLDS) or NAME_RE.search(d.rsplit(".", 1)[0])]
    return sorted(out, key=lambda d: rank[d])


def fetch_page(domain: str) -> dict:
    """Pagina inicial (https, www., http): {"html", "final_url"} ou {"error"}."""
    last = "unreachable"
    for url in (f"https://{domain}/", f"https://www.{domain}/", f"http://{domain}/"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA,
                                                       "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8"})
            with _OPENER.open(req, timeout=8) as resp:
                body = resp.read(MAX_BYTES)
                charset = resp.headers.get_content_charset() or "utf-8"
                return {"html": body.decode(charset, "replace"), "final_url": resp.geturl()}
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
        except Exception as e:  # pylint: disable=broad-exception-caught
            last = type(e).__name__
    return {"error": last}


class Cloudflare:
    """Categorias de conteudo da Cloudflare (Intel API). Inativo sem CF_API_TOKEN/CF_ACCOUNT_ID."""

    MIN_INTERVAL = 0.26   # ~230 req/min, abaixo do limite global de 1200 req / 5 min

    def __init__(self):
        self.token = os.environ.get("CF_API_TOKEN", "").strip()
        self.account = os.environ.get("CF_ACCOUNT_ID", "").strip()
        self.enabled = bool(self.token and self.account)
        self.disabled_reason = None if self.enabled else "CF_API_TOKEN/CF_ACCOUNT_ID ausentes"
        self.calls = 0
        self._last = 0.0

    def categories(self, domain: str):
        """Lista de nomes de categorias, ou None (sem dado / desativado)."""
        if not self.enabled:
            return None
        delay = self.MIN_INTERVAL - (time.time() - self._last)
        if delay > 0:
            time.sleep(delay)
        self._last = time.time()
        url = (f"https://api.cloudflare.com/client/v4/accounts/{self.account}/intel/domain?"
               + urllib.parse.urlencode({"domain": domain}))
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = json.loads(resp.read())
            self.calls += 1
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self.enabled = False
                self.disabled_reason = f"Cloudflare HTTP {e.code}: token sem permissao de leitura de Intel"
                log(f"[cloudflare] {self.disabled_reason}; seguindo sem Cloudflare")
            return None
        except Exception:  # pylint: disable=broad-exception-caught
            return None
        return parse_cf_categories(body)


def parse_cf_categories(body) -> list:
    result = (body or {}).get("result") or {}
    if isinstance(result, list):
        result = result[0] if result else {}
    cats = result.get("content_categories") or []
    return [c.get("name") for c in cats if isinstance(c, dict) and c.get("name")]


def name_hit(domain: str) -> bool:
    """O nome (sem o TLD) indica jogo: game, jogos, friv, playgam..."""
    return bool(NAME_RE.search(domain.rsplit(".", 1)[0]))


def decide(score: dict, cf, by_name: bool = False) -> str:
    """block | review | clean"""
    cf = cf or []
    gaming = any(CF_GAMING.search(c) for c in cf)
    education = any(CF_EDUCATION.search(c) for c in cf)
    s, playable = score.get("score", 0), score.get("playable", False)
    if s >= STRONG_SCORE and playable:
        return "block"
    if by_name and s >= NAME_SCORE and playable:
        return "block"     # nome de jogo + página jogável (ex.: playgama.com, score 15)
    if gaming and not education:
        return "block"
    if gaming and s >= BLOCK_SCORE and playable:
        return "block"
    if s >= BLOCK_SCORE or gaming:
        return "review"
    return "clean"


def _expired(entry, now, ttl_days, error_ttl_days) -> bool:
    try:
        checked = datetime.datetime.fromisoformat(entry["checked"])
    except (KeyError, TypeError, ValueError):
        return True
    ttl = error_ttl_days if entry.get("decision") == "error" else ttl_days
    return now - checked > datetime.timedelta(days=ttl)


def analyze(domain: str, cloudflare: Cloudflare, use_cf: bool) -> dict:
    page = fetch_page(domain)
    cf = cloudflare.categories(domain) if use_cf else None
    if "error" in page:
        entry = {"score": 0, "playable": False, "signals": [page["error"]]}
        decision = decide(entry, cf) if cf else "error"
    else:
        entry = score_page(domain, page["html"])
        decision = decide(entry, cf, name_hit(domain))
        # The state file is public: no text copied from third-party pages goes into it
        entry.pop("title", None)
    entry.update(decision=decision, cf=cf)
    return entry


def run_scan(rank: dict, known: set, never: set, cache_path: str, cfg: dict) -> list:
    """Atualiza o cache e devolve os dominios a bloquear, do mais popular ao menos."""
    cache = json.load(open(cache_path, encoding="utf-8")) if os.path.exists(cache_path) else {}
    now = datetime.datetime.now(datetime.timezone.utc)
    budget = float(os.environ.get("SCAN_BUDGET_MINUTES", cfg.get("budget_minutes", 60))) * 60
    workers = int(cfg.get("workers", 32))
    ttl, err_ttl = int(cfg.get("ttl_days", 30)), int(cfg.get("error_ttl_days", 7))
    cf_top = int(cfg.get("cloudflare_top", 200000))
    cf_left = [int(os.environ.get("CF_BUDGET", cfg.get("cloudflare_budget", 6000)))]
    cloudflare = Cloudflare()

    def skip(d):
        base = registrable(d)
        return d in known or base in known or d in never or base in never or not is_candidate(d)

    def stale(d):
        return d not in cache or _expired(cache[d], now, ttl, err_ttl)

    def take_cf():
        if cloudflare.enabled and cf_left[0] > 0:
            cf_left[0] -= 1
            return True
        return False

    by_name = [d for d in name_candidates(rank) if not skip(d)]
    todo = [d for d in by_name if stale(d)]
    cf_only = []
    if cloudflare.enabled:
        name_set = set(by_name)
        cf_only = [d for d in sorted(rank, key=rank.get)[:cf_top] if d not in name_set and not skip(d) and stale(d)]
    log(f"[scan] candidatos por nome: {len(by_name)} (a analisar: {len(todo)}); "
        f"so Cloudflare: {len(cf_only)}; Cloudflare: {'ativa' if cloudflare.enabled else cloudflare.disabled_reason}")

    started, analyzed = time.time(), 0
    stamp = now.isoformat(timespec="seconds")
    queue = iter(todo)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = {}

        def submit_next():
            if time.time() - started > budget:
                return False
            for d in queue:
                pending[pool.submit(analyze, d, cloudflare, take_cf())] = d
                return True
            return False

        for _ in range(workers * 2):
            if not submit_next():
                break
        while pending:
            finished, _ = wait(list(pending), return_when=FIRST_COMPLETED)
            for fut in finished:
                d = pending.pop(fut)
                try:
                    entry = fut.result()
                except Exception as e:  # pylint: disable=broad-exception-caught
                    entry = {"score": 0, "playable": False, "signals": [type(e).__name__],
                             "decision": "error", "cf": None}
                entry["checked"] = stamp
                cache[d] = entry
                analyzed += 1
                submit_next()
    log(f"[scan] analisados por conteudo: {analyzed} em {int(time.time() - started)} s")

    cf_done = 0
    for d in cf_only:   # sequencial: limite de taxa da API
        if time.time() - started > budget or not take_cf():
            break
        cats = cloudflare.categories(d)
        if cats is None and not cloudflare.enabled:
            break
        cache[d] = {"score": 0, "playable": False, "signals": [], "cf": cats or [],
                    "decision": decide({}, cats), "checked": stamp}
        cf_done += 1
    log(f"[scan] consultados so na Cloudflare: {cf_done}; chamadas Cloudflare: {cloudflare.calls}")

    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    counts = {}
    for e in cache.values():
        counts[e.get("decision")] = counts.get(e.get("decision"), 0) + 1
    blocked = sorted((d for d, e in cache.items() if e.get("decision") == "block" and not skip(d)),
                     key=lambda d: rank.get(d, 10 ** 9))
    log(f"[scan] cache: {len(cache)} dominios {counts}; a bloquear: {len(blocked)}")
    return blocked

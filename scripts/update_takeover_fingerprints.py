#!/usr/bin/env python3
"""Regenera padme/data/takeover_fingerprints.json a partir do can-i-take-over-xyz.

    python scripts/update_takeover_fingerprints.py            # baixa do GitHub
    python scripts/update_takeover_fingerprints.py --source fingerprints.json
    python scripts/update_takeover_fingerprints.py --check    # só mostra o diff

Regras da conversão (explicáveis, sem adivinhação):
  - entra só o que o upstream marca como "Vulnerable" ou "Edge case";
    "Not vulnerable" SAI (evita alerta crítico falso);
  - o serviço precisa de um alvo de CNAME (é assim que o collector casa);
    IP e URL no campo cname são descartados;
  - precisa de um sinal: NXDOMAIN ou uma assinatura de corpo. Só-status HTTP
    (ex.: "HTTP_STATUS=500") é fraco demais e fica de fora;
  - a assinatura vira REGEX: texto literal é escapado; as que o upstream já
    escreve como regex (".*", "\\.", "|") passam como estão;
  - `_CURATED` completa serviços que o upstream lista sem CNAME e mantém
    domínios/assinaturas que a base do Padmé já usava (união, nunca troca).

Ao final grava `reviewed` com a data de hoje: rodar este script É a revisão
que o `padme doctor` cobra a cada 180 dias. Revise o diff antes do commit.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

UPSTREAM = ("https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/"
            "master/fingerprints.json")
OUT = Path(__file__).resolve().parent.parent / "padme" / "data" / "takeover_fingerprints.json"

_HOST_RE = re.compile(r"^(?=.*[a-z])[a-z0-9-]+(\.[a-z0-9-]+)+$")
_REGEX_HINT = re.compile(r"\.\*|\\\.|\|")

# nome no upstream -> (nome exibido, cnames extras, assinaturas extras em texto).
# Vem da base curada que o Padmé já usava; o upstream não traz CNAME para
# vários desses (ou traz um só, mais estreito).
_CURATED: dict[str, tuple[str, list[str], list[str]]] = {
    "Github": ("GitHub Pages", ["github.io"], []),
    "Heroku": ("Heroku", ["herokuapp.com", "herokudns.com", "herokussl.com"], []),
    "Shopify": ("Shopify", ["myshopify.com"], []),
    "Tumblr": ("Tumblr", ["domains.tumblr.com"], []),
    "Pantheon": ("Pantheon", ["pantheonsite.io"],
                 ["The gods are wise, but do not know of the site which you seek"]),
    "Readthedocs": ("Read the Docs", ["readthedocs.io"], ["unknown to Read the Docs"]),
    "AWS/S3": ("AWS S3", ["amazonaws.com"], ["NoSuchBucket"]),
    "Ghost": ("Ghost", [], ["The thing you were looking for is no longer here"]),
    "Surge.sh": ("Surge.sh", ["surge.sh"], []),
    "Wordpress": ("WordPress", [], []),
    "Microsoft Azure": ("Azure", ["trafficmanager.net", "azurefd.net"], []),
    # Serviços que o upstream lista SEM alvo de CNAME, completados com o domínio
    # inequivocamente da plataforma (a assinatura de corpo vem do upstream). Só
    # entram sufixos que a própria plataforma é dona — errar o sufixo só causaria
    # falso NEGATIVO (não casa), nunca falso positivo.
    "Campaign Monitor": ("Campaign Monitor", ["createsend.com"], []),
    "Canny": ("Canny", ["canny.io"], []),
    "Pingdom": ("Pingdom", ["stats.pingdom.com"], []),
    "Intercom": ("Intercom", ["custom.intercom.help"], []),
    "Netlify": ("Netlify", ["netlify.app"], []),
    "Vercel": ("Vercel", ["cname.vercel-dns.com"], []),
    "Webflow": ("Webflow", ["proxy-ssl.webflow.com"], []),
}


def _literal(text: str) -> str:
    """Texto literal -> regex, sem escapar espaço (JSON legível; não usamos re.X)."""
    return re.escape(text).replace("\\ ", " ")


def _patterns(raw: str) -> list[str]:
    """Assinatura do upstream -> regexes. O README do upstream separa
    alternativas com crase ("a` `b"); `&#124;` é o '|' escapado da tabela."""
    raw = html.unescape(raw or "").strip()
    if not raw or raw.upper() == "NXDOMAIN" or raw.upper().startswith("HTTP_STATUS"):
        return []
    parts = [p.strip(" `") for p in raw.split("` `")] if "` `" in raw else [raw]
    return [p if _REGEX_HINT.search(p) else _literal(p) for p in parts if p]


def convert(upstream: list[dict]) -> tuple[list[dict], list[str]]:
    services, skipped = [], []
    for entry in upstream:
        name = entry.get("service", "?")
        status = (entry.get("status") or "").lower()
        if status not in ("vulnerable", "edge case"):
            continue
        shown, extra_cnames, extra_fps = _CURATED.get(name, (name, [], []))
        cnames = sorted({c.lower().rstrip(".") for c in entry.get("cname") or []
                         if _HOST_RE.match(c.lower().rstrip("."))} | set(extra_cnames))
        nxdomain = bool(entry.get("nxdomain"))
        pats = _patterns(entry.get("fingerprint", "")) + [_literal(f) for f in extra_fps]
        if not cnames:
            skipped.append(f"{name}: upstream sem alvo de CNAME")
            continue
        if not nxdomain and not pats:
            skipped.append(f"{name}: sem NXDOMAIN nem assinatura de corpo "
                           f"({entry.get('fingerprint') or 'vazia'})")
            continue
        regex = "|".join(dict.fromkeys(pats))
        re.compile(regex)  # assinatura inválida quebra aqui, não em produção
        services.append({"service": shown, "status": status, "cnames": cnames,
                         "fingerprint": regex, "nxdomain": nxdomain})
    services.sort(key=lambda s: s["service"].lower())
    return services, skipped


def _load(source: str | None) -> list[dict]:
    if source:
        return json.loads(Path(source).read_text("utf-8"))
    with urllib.request.urlopen(UPSTREAM, timeout=30) as resp:  # noqa: S310 — URL fixa
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--source", help="fingerprints.json local (padrão: baixa do GitHub)")
    ap.add_argument("--check", action="store_true", help="só mostra o diff, não grava")
    args = ap.parse_args()

    services, skipped = convert(_load(args.source))
    old = {s["service"]: s for s in json.loads(OUT.read_text("utf-8"))["services"]}
    new = {s["service"]: s for s in services}
    for name in sorted(new.keys() - old.keys()):
        print(f"+ {name} ({new[name]['status']})")
    for name in sorted(old.keys() - new.keys()):
        print(f"- {name}")
    for name in sorted(old.keys() & new.keys()):
        if old[name] != new[name]:
            print(f"~ {name}")
    for s in skipped:
        print(f"  (fora) {s}")
    print(f"{len(services)} serviço(s) na base nova.")
    if args.check:
        return 0

    doc = {
        "_comment": ("Gerado por scripts/update_takeover_fingerprints.py a partir do "
                     "can-i-take-over-xyz. 'fingerprint' é REGEX (case-insensitive) "
                     "buscada no corpo HTTP; vazio + nxdomain=true = vulnerável quando "
                     "o alvo do CNAME não existe. 'status' edge case = reivindicação "
                     "depende do caso (confiança menor). Rode o script de novo para "
                     "revisar; o doctor avisa após 180 dias."),
        "source": UPSTREAM,
        "reviewed": date.today().isoformat(),
        "services": services,
    }
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", "utf-8")
    print(f"gravado: {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

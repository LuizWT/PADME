"""Webhook assinado (ponto 3): HMAC-SHA256 com timestamp, anti-replay."""

import asyncio
import json

import httpx

from padme.config import Config, WebhookConfig
from padme.engine import build_notifiers
from padme.models import Event, EventType, Kind
from padme.notify import webhook
from padme.notify.webhook import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WebhookNotifier,
    sign,
    verify,
)


def _captura(monkeypatch):
    pedidos: list[httpx.Request] = []
    real = httpx.AsyncClient

    def handler(request):
        pedidos.append(request)
        return httpx.Response(204)

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(webhook.httpx, "AsyncClient", factory)
    return pedidos


def _ev():
    return Event("x.com", EventType.ADDED, Kind.PORT, "x.com:6379", None, "open",
                 event_id="e1", scan_id="s1", detected_at="2026-09-30T00:00:00+00:00")


def test_sign_e_verify():
    body = b'{"a":1}'
    sig = sign("s3gr3d0", "1700000000", body)
    assert sig.startswith("sha256=") and len(sig) == 7 + 64
    assert verify("s3gr3d0", "1700000000", body, sig, now=1700000100)
    assert not verify("s3gr3d0", "1700000000", b'{"a":2}', sig, now=1700000100)   # corpo alterado
    assert not verify("s3gr3d0", "1700000001", body, sig, now=1700000100)         # ts trocado
    assert not verify("outro", "1700000000", body, sig, now=1700000100)           # segredo errado
    assert not verify("s3gr3d0", "1700000000", body, sig, now=1700000000 + 3600)  # replay velho
    assert not verify("s3gr3d0", "nao-e-numero", body, sig)


def test_post_assinado_confere_do_lado_do_destino(monkeypatch):
    pedidos = _captura(monkeypatch)
    n = WebhookNotifier("https://hook.exemplo/padme", secret="s3gr3d0",
                        headers={"X-Padme-Token": "abc", SIGNATURE_HEADER: "forjado"})
    assert asyncio.run(n.notify_events("x.com", [_ev()])).ok
    req = pedidos[0]
    ts, sig = req.headers[TIMESTAMP_HEADER], req.headers[SIGNATURE_HEADER]
    assert verify("s3gr3d0", ts, req.content, sig)          # o destino valida os bytes recebidos
    assert req.headers["X-Padme-Token"] == "abc"            # headers do usuário continuam
    assert req.headers["content-type"] == "application/json"
    assert json.loads(req.content)["events"][0]["key"] == "x.com:6379"


def test_sem_segredo_nao_assina(monkeypatch):
    pedidos = _captura(monkeypatch)
    assert asyncio.run(WebhookNotifier("https://hook.exemplo/padme").announce("oi")).ok
    assert TIMESTAMP_HEADER not in pedidos[0].headers
    assert SIGNATURE_HEADER not in pedidos[0].headers
    assert json.loads(pedidos[0].content)["type"] == "announce"


def test_config_expande_segredo_e_liga_no_notifier(monkeypatch):
    monkeypatch.setenv("PADME_WEBHOOK_SECRET", "vindo-do-env")
    wh = WebhookConfig(enabled=True, url="https://hook.exemplo/padme",
                       secret="${PADME_WEBHOOK_SECRET}").resolved()
    assert wh.secret == "vindo-do-env"
    n = next(x for x in build_notifiers(Config(targets=["x.com"], webhook=wh))
             if x.name == "webhook")
    assert n.secret == "vindo-do-env"

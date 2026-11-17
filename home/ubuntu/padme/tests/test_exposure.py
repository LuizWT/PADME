"""Testes das checagens HTTP fixas e da proteção contra vazamento de conteúdo."""
import asyncio
import json

import httpx

from padme.collectors import exposure
from padme.evidence import evidence_of
from padme.models import Event, EventType, Kind
from padme.notify.telegram import format_events


def _body(check: dict) -> str:
    sig = check["signature"]
    if "contains" in sig:
        return str(sig["contains"])
    if check["id"] == "env-file":
        return "DB_PASSWORD=fixture-secret"
    return f"<title>Index of {check['path']}</title>"


def _run(routes: dict[str, httpx.Response | Exception], soft_body: bytes = b"not found"):
    def handler(request: httpx.Request):
        path = request.url.path
        if path.startswith("/.__padme_soft404_"):
            return httpx.Response(404, headers={"content-type": "text/html"}, content=soft_body)
        result = routes.get(path, httpx.Response(404, headers={"content-type": "text/plain"}, content=b"no"))
        if isinstance(result, Exception):
            raise result
        return result

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await exposure.collect_host("example.com", client)

    return asyncio.run(go())


def test_each_curated_signature_detects_and_similar_body_is_rejected():
    for check in exposure.CHECKS:
        content_type = check["signature"]["content_types"][0]
        routes = {check["path"]: httpx.Response(
            200, headers={"content-type": content_type}, content=_body(check).encode())}
        result = _run(routes)
        assert [r.metadata["signature"] for r in result.records] == [check["id"]]
        similar = "almost similar body" if "regex" in check["signature"] else _body(check).replace(
            str(check["signature"].get("contains", "")), "almost")
        result = _run({check["path"]: httpx.Response(
            200, headers={"content-type": content_type}, content=similar.encode())})
        assert result.records == []


def test_soft_404_never_turns_identical_generic_body_into_finding():
    result = _run({"/.env": httpx.Response(
        200, headers={"content-type": "text/plain"}, content=b"same generic page")},
                  soft_body=b"same generic page")
    assert result.records == []


def test_timeout_is_inconclusive_and_404_is_authoritative():
    timeout = httpx.ReadTimeout("fixture timeout")
    result = _run({"/.env": timeout})
    assert result.ok is False
    assert result.records == []
    result = _run({})
    assert result.ok is True
    assert result.records == []


def test_body_is_capped_before_matching_and_content_never_leaks():
    secret = b"PREFIX " + b"x" * 5000 + b"DB_PASSWORD=fixture-secret"
    result = _run({"/.env": httpx.Response(
        200, headers={"content-type": "text/plain"}, content=secret)})
    assert result.records == []

    body = "DB_PASSWORD=fixture-secret"
    response = httpx.Response(200, headers={"content-type": "text/plain"}, content=body)
    result = _run({"/.env": response})
    record = result.records[0]
    event = Event("example.com", EventType.ADDED, Kind.EXPOSURE, record.key,
                  new_value=record.value, metadata=record.metadata)
    evidence = evidence_of(Kind.EXPOSURE, record.key, record.value, record.metadata)
    message = format_events("example.com", [event])
    for rendered in (repr(record), repr(evidence), message):
        assert body not in rendered
        assert "fixture-secret" not in rendered


def test_data_is_curated_and_has_no_query_paths():
    doc = json.loads(__import__("pathlib").Path("padme/data/exposures.json").read_text())
    assert 10 <= len(doc["checks"]) <= 15
    assert all("?" not in c["path"] and "=" not in c["path"] for c in doc["checks"])

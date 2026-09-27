"""Multi-vantage: consolidação de exports por source e detecção de divergências."""

from padme.merge import merge_exports


def _row(source, kind, key, value=""):
    return {"source": source, "target": "alvo.com", "kind": kind, "key": key, "value": value}


def test_merge_presenca_divergente():
    casa = [_row("casa", "subdomain", "www.alvo.com", "live"),
            _row("casa", "subdomain", "api.alvo.com", "live")]
    vps = [_row("vps-eu", "subdomain", "www.alvo.com", "live")]  # não vê api
    res = merge_exports([casa, vps])
    assert res["sources"] == ["casa", "vps-eu"]
    assert res["asset_count"] == 2
    div = {a["key"]: a for a in res["divergences"]}
    assert "api.alvo.com" in div
    assert div["api.alvo.com"]["divergence"] == "presence"
    assert div["api.alvo.com"]["sources_seen"] == ["casa"]
    assert div["api.alvo.com"]["sources_missing"] == ["vps-eu"]
    # www visto pelos dois -> não é divergência
    assert "www.alvo.com" not in div


def test_merge_valor_divergente():
    casa = [_row("casa", "http", "https://alvo.com", "200 | nginx")]
    vps = [_row("vps-eu", "http", "https://alvo.com", "403 | nginx")]  # geo-block
    res = merge_exports([casa, vps])
    div = res["divergences"]
    assert len(div) == 1
    assert div[0]["divergence"] == "value"
    assert div[0]["values"]["casa"].startswith("200")
    assert div[0]["values"]["vps-eu"].startswith("403")


def test_merge_convergente_sem_divergencia():
    a = [_row("casa", "port", "alvo.com:443", "open")]
    b = [_row("vps-eu", "port", "alvo.com:443", "open")]
    res = merge_exports([a, b])
    assert res["asset_count"] == 1
    assert res["divergences"] == []


def test_merge_source_ausente_vira_interrogacao():
    res = merge_exports([[{"target": "x.com", "kind": "dns", "key": "x.com|A|1", "value": "1"}]])
    assert res["sources"] == ["?"]

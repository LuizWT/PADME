"""P0.6/P0.9 — política de rede: IP privado/reservado e redirect."""

from padme.netpolicy import any_disallowed, is_public_ip, redirect_allowed


def test_is_public_ip_v4():
    assert is_public_ip("8.8.8.8")
    assert is_public_ip("1.1.1.1")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("10.0.0.1")
    assert not is_public_ip("172.16.0.1")
    assert not is_public_ip("192.168.1.1")
    assert not is_public_ip("169.254.0.1")     # link-local
    assert not is_public_ip("0.0.0.0")         # unspecified


def test_is_public_ip_v6():
    assert not is_public_ip("::1")             # loopback
    assert not is_public_ip("fe80::1")         # link-local
    assert not is_public_ip("fc00::1")         # ULA
    assert is_public_ip("2606:4700:4700::1111")


def test_is_public_ip_invalido():
    assert not is_public_ip("nao-e-ip")
    assert not is_public_ip("")


def test_any_disallowed_basta_um():
    assert any_disallowed({"8.8.8.8", "10.0.0.1"})   # um privado já bloqueia
    assert not any_disallowed({"8.8.8.8", "1.1.1.1"})
    assert not any_disallowed(set())                 # sem info -> não bloqueia


def test_redirect_allowed():
    assert not redirect_allowed("http://127.0.0.1/x", allow_private=False)  # SSRF loopback
    assert not redirect_allowed("http://10.0.0.1/", allow_private=False)
    assert not redirect_allowed("http://exemplo.com/", allow_private=False)  # host não-IP: não valida
    assert redirect_allowed("http://8.8.8.8/", allow_private=False)
    assert redirect_allowed("http://127.0.0.1/", allow_private=True)         # opt-in consciente

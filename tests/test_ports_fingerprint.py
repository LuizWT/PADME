"""Testes do fingerprint de serviço/produto/versão das portas (§5.3)."""

from padme.collectors.ports import fingerprint
from padme.differ import field_changes
from padme.evidence import evidence_of
from padme.models import Kind


def test_service_vem_da_porta_sem_banner():
    assert fingerprint(22, "") == {"service": "ssh"}
    assert fingerprint(3389, "") == {"service": "rdp"}
    assert fingerprint(65000, "") == {}          # porta desconhecida, sem banner


def test_ssh_banner_produto_e_versao():
    fp = fingerprint(22, "SSH-2.0-OpenSSH_9.6p1 Debian-3")
    assert fp == {"service": "ssh", "product": "OpenSSH", "version": "9.6p1"}


def test_ftp_banner_vsftpd():
    fp = fingerprint(21, "220 (vsFTPd 3.0.5)")
    assert fp["service"] == "ftp" and fp["product"] == "vsFTPd" and fp["version"] == "3.0.5"


def test_smtp_banner_produto_sem_versao():
    fp = fingerprint(25, "220 mail.exemplo.com ESMTP Postfix (Ubuntu)")
    assert fp["service"] == "smtp" and fp["product"] == "Postfix"
    assert "version" not in fp


def test_banner_desconhecido_so_service():
    assert fingerprint(8080, "algo-proprietario xyz") == {"service": "http"}


def test_evidence_inclui_service_product_version():
    ev = evidence_of(Kind.PORT, "a.com:22", "open · SSH-2.0-OpenSSH_9.6p1",
                     {"port": 22, "banner": "SSH-2.0-OpenSSH_9.6p1",
                      "service": "ssh", "product": "OpenSSH", "version": "9.6p1"})
    assert ev["type"] == "tcp_connect" and ev["state"] == "open"
    assert ev["service"] == "ssh" and ev["product"] == "OpenSSH" and ev["version"] == "9.6p1"


def test_diff_detecta_mudanca_de_versao():
    old = {"port": 22, "banner": "SSH-2.0-OpenSSH_9.6p1", "service": "ssh",
           "product": "OpenSSH", "version": "9.6p1"}
    new = {"port": 22, "banner": "SSH-2.0-OpenSSH_9.7p1", "service": "ssh",
           "product": "OpenSSH", "version": "9.7p1"}
    ch = field_changes(Kind.PORT, "open · x", old, "open · y", new)
    assert "version" in ch and ch["version"]["new"] == "9.7p1"
    assert "service" not in ch          # serviço não mudou

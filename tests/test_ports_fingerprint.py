"""Testes do fingerprint de serviço/produto/versão das portas (§5.3)."""

from padme.collectors.ports import _decode_banner, fingerprint
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


def test_service_map_cobre_exposicao_relevante():
    # portas que, abertas na borda, são sinal por si só (bancos/admin/orquestração)
    casos = {6379: "redis", 27017: "mongodb", 9200: "elasticsearch",
             2375: "docker", 6443: "kubernetes-api", 5432: "postgresql",
             1433: "mssql", 445: "smb", 11211: "memcached", 15672: "rabbitmq"}
    for porta, svc in casos.items():
        assert fingerprint(porta, "")["service"] == svc


def test_dovecot_pop3_banner_produto():
    fp = fingerprint(110, "+OK Dovecot ready.")
    assert fp["service"] == "pop3" and fp["product"] == "Dovecot"
    assert "version" not in fp


def test_proftpd_banner_produto_e_versao():
    fp = fingerprint(21, "220 ProFTPD 1.3.7a Server ready.")
    assert fp["service"] == "ftp" and fp["product"] == "ProFTPD" and fp["version"] == "1.3.7a"


def test_mysql_handshake_decodifica_versao():
    # greeting do MySQL: [3B tamanho][seq=0x00][0x0a proto][versão NUL-terminada]
    data = b"\x4a\x00\x00\x00\x0a" + b"8.0.34" + b"\x00" + b"\x11\x22\x33\x44"
    banner = _decode_banner(data)
    assert banner == "MySQL 8.0.34"
    assert fingerprint(3306, banner) == {"service": "mysql", "product": "MySQL",
                                         "version": "8.0.34"}


def test_mariadb_handshake_extrai_versao_real():
    # MariaDB prefixa uma versão de replicação falsa (5.5.5-) antes da real
    ver = b"5.5.5-10.6.12-MariaDB-1:10.6.12+maria~focal"
    data = b"\x60\x00\x00\x00\x0a" + ver + b"\x00" + b"\x00\x00"
    banner = _decode_banner(data)
    assert banner == "MariaDB 10.6.12"
    fp = fingerprint(3306, banner)
    assert fp["service"] == "mysql" and fp["product"] == "MariaDB"
    assert fp["version"] == "10.6.12"


def test_decode_banner_texto_nao_e_confundido_com_mysql():
    # banner de texto (SMTP) não casa a assinatura binária do MySQL
    data = b"220 mail.example.com ESMTP Postfix\r\n"
    assert _decode_banner(data) == "220 mail.example.com ESMTP Postfix"
    # assinatura binária sem versão de forma válida cai fora (não vira "MySQL")
    assert _decode_banner(b"\x01\x02\x03\x00\x0aXYZ\x00") == ""


def test_smtp_openbsd_haraka_na_allowlist():
    assert fingerprint(25, "220 mx.example.org ESMTP OpenSMTPD")["product"] == "OpenSMTPD"
    fp = fingerprint(25, "220 mail ESMTP Haraka 3.0.2 ready")
    assert fp["product"] == "Haraka" and fp["version"] == "3.0.2"


def test_ftp_servidores_alvos_frequentes():
    # daemons FTP que se anunciam e são alvos recorrentes (CVE)
    assert fingerprint(21, "220 Serv-U FTP Server v15.1.6 ready")["product"] == "Serv-U"
    assert fingerprint(21, "220 CrushFTP Server ready")["product"] == "CrushFTP"


def test_smtp_exchange_e_zimbra():
    assert fingerprint(25, "220 host Microsoft ESMTP MAIL Service ready")["product"] == "Microsoft ESMTP"
    fp = fingerprint(25, "220 mx ESMTP Zimbra 8.8.15_GA_3869 ready")
    assert fp["product"] == "Zimbra" and fp["version"].startswith("8.8.15")


def test_diff_detecta_mudanca_de_versao():
    old = {"port": 22, "banner": "SSH-2.0-OpenSSH_9.6p1", "service": "ssh",
           "product": "OpenSSH", "version": "9.6p1"}
    new = {"port": 22, "banner": "SSH-2.0-OpenSSH_9.7p1", "service": "ssh",
           "product": "OpenSSH", "version": "9.7p1"}
    ch = field_changes(Kind.PORT, "open · x", old, "open · y", new)
    assert "version" in ch and ch["version"]["new"] == "9.7p1"
    assert "service" not in ch          # serviço não mudou

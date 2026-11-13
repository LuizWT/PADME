"""CLI de uso diário: comando padrão (monitor + painel), ajuda completa,
`padme init`, busca do config e `--update`."""

import os

import pytest

from padme import cli, initcfg, paths, updater
from padme.__main__ import run as entry
from padme.config import Config


# ── ajuda ────────────────────────────────────────────────────────────────────
def test_ajuda_completa_lista_todos_os_comandos_e_opcoes(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["-h"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    parser = cli.build_parser()
    sub = next(a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction")
    for name, sp in sub.choices.items():
        assert f"  {name} " in out                        # todo comando aparece
        for a in sp._actions:
            for opt in a.option_strings:
                if opt not in ("-h", "--help"):
                    assert opt in out, (name, opt)          # e todas as opções dele
    for opt in ("--config", "--update", "--force", "--version", "--verbose"):
        assert opt in out
    assert "test-notify" not in out and "uso:" in out


def test_ajuda_de_comando_em_portugues(capsys):
    with pytest.raises(SystemExit):
        cli.main(["monitor", "-h"])
    out = capsys.readouterr().out
    assert out.startswith("uso: padme monitor") and "opções:" in out and "--no-web" in out


# ── comando padrão ───────────────────────────────────────────────────────────
def _cfg_file(tmp_path, extra=""):
    p = tmp_path / "config.yaml"
    p.write_text("scope_confirmed: true\ntargets: [a.com]\n" + extra, encoding="utf-8")
    return p


def test_sem_comando_roda_o_monitor_com_painel(tmp_path, monkeypatch):
    chamadas = {}

    async def fake_monitor(cfg, once=False):
        chamadas["once"] = once

    def fake_start(cfg, host, port, exposed=False, token=None):
        chamadas["painel"] = (host, port, exposed)

    monkeypatch.setattr(cli, "run_monitor", fake_monitor)
    monkeypatch.setattr("padme.webpanel.start_background", fake_start)
    assert cli.main(["-c", str(_cfg_file(tmp_path))]) == 0
    assert chamadas == {"once": False, "painel": ("127.0.0.1", 8787, False)}


@pytest.mark.parametrize("argv, esperado", [
    ([], ["monitor"]),
    (["--no-web"], ["monitor", "--no-web"]),
    (["-c", "x.yaml", "--level", "high"], ["-c", "x.yaml", "monitor", "--level", "high"]),
    (["--config=x.yaml", "-v", "--once"], ["--config=x.yaml", "-v", "monitor", "--once"]),
    (["-cx.yaml"], ["-cx.yaml", "monitor"]),
    (["--update"], ["--update", "monitor"]),
    (["scan", "--notify"], ["scan", "--notify"]),      # comando escrito: não mexe
    (["-c", "x.yaml", "init"], ["-c", "x.yaml", "init"]),
    (["scna"], ["scna"]),                              # erro de digitação: argparse reclama
    (["-h"], ["-h"]),
    (["--version"], ["--version"]),
    (["-c"], ["-c"]),                                  # sem valor: argparse reclama
])
def test_opcoes_do_monitor_valem_sem_escrever_monitor(argv, esperado):
    assert cli._with_default_command(argv) == esperado


def test_padme_no_web_direto(tmp_path, monkeypatch):
    abriu = []

    async def fake_monitor(cfg, once=False):
        return None

    monkeypatch.setattr(cli, "run_monitor", fake_monitor)
    monkeypatch.setattr("padme.webpanel.start_background", lambda *a, **k: abriu.append(1))
    assert cli.main(["-c", str(_cfg_file(tmp_path)), "--no-web", "--level", "high"]) == 0
    assert abriu == []


def test_comando_errado_nao_vira_monitor(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["scna"])
    assert exc.value.code == 2
    assert "scna" in capsys.readouterr().err


def test_no_web_e_once_nao_abrem_o_painel(tmp_path, monkeypatch):
    abriu = []

    async def fake_monitor(cfg, once=False):
        return None

    monkeypatch.setattr(cli, "run_monitor", fake_monitor)
    monkeypatch.setattr("padme.webpanel.start_background", lambda *a, **k: abriu.append(1))
    cfg = str(_cfg_file(tmp_path))
    assert cli.main(["-c", cfg, "monitor", "--no-web"]) == 0
    assert cli.main(["-c", cfg, "monitor", "--once"]) == 0
    assert abriu == []


def test_painel_exposto_sem_token_nao_abre_mas_o_monitor_segue(tmp_path, monkeypatch, capsys):
    rodou, abriu = [], []

    async def fake_monitor(cfg, once=False):
        rodou.append(1)

    monkeypatch.delenv("PADME_WEB_TOKEN", raising=False)
    monkeypatch.setattr(cli, "run_monitor", fake_monitor)
    monkeypatch.setattr("padme.webpanel.start_background", lambda *a, **k: abriu.append(1))
    cfg = str(_cfg_file(tmp_path, "web: {bind: 0.0.0.0}\n"))
    assert cli.main(["-c", cfg]) == 0
    assert rodou == [1] and abriu == []
    assert "SEM autenticação" in capsys.readouterr().err


def test_porta_ocupada_avisa_e_o_monitor_segue(tmp_path, monkeypatch, capsys):
    rodou = []

    async def fake_monitor(cfg, once=False):
        rodou.append(1)

    def ocupada(*a, **k):
        raise OSError(98, "Address already in use")

    monkeypatch.setattr(cli, "run_monitor", fake_monitor)
    monkeypatch.setattr("padme.webpanel.start_background", ocupada)
    assert cli.main(["-c", str(_cfg_file(tmp_path))]) == 0
    assert rodou == [1] and "não abriu" in capsys.readouterr().err


def test_painel_sobe_de_verdade_numa_thread(tmp_path):
    import urllib.request

    from padme.webpanel import start_background
    cfg = Config.load(_cfg_file(tmp_path))
    srv = start_background(cfg, "127.0.0.1", 0)
    try:
        port = srv.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            assert r.status == 200
    finally:
        srv.shutdown()
        srv.server_close()


# ── config: busca e init ─────────────────────────────────────────────────────
def test_busca_do_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PADME_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    if os.name != "nt":
        assert paths.find_config(None) == tmp_path / "xdg" / "padme" / "config.yaml"
    (tmp_path / "config.yaml").write_text("x", encoding="utf-8")
    assert paths.find_config(None).name == "config.yaml" and paths.find_config(None).parent == paths.Path(".")
    monkeypatch.setenv("PADME_CONFIG", str(tmp_path / "outro.yaml"))
    assert paths.find_config(None) == tmp_path / "outro.yaml"
    assert paths.find_config("x.yaml") == paths.Path("x.yaml")


def test_sem_config_orienta_o_init(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["-c", str(tmp_path / "nao-existe.yaml"), "events"]) == 2
    assert "padme init" in capsys.readouterr().err


def test_init_sem_perguntas_cria_config_valido(tmp_path):
    p = tmp_path / "padme" / "config.yaml"
    assert cli.main(["-c", str(p), "init", "--target", "https://Acme.com/x",
                     "--target", "b.org,acme.com", "--yes"]) == 0
    cfg = Config.load(p)
    assert cfg.targets == ["acme.com", "b.org"] and cfg.scope_confirmed is True
    assert cli.main(["-c", str(p), "init", "--target", "c.com", "--yes"]) == 1   # já existe
    assert cli.main(["-c", str(p), "init", "--target", "c.com", "--force"]) == 0
    assert Config.load(p).scope_confirmed is False      # sem --yes, escopo não confirmado


def test_init_sem_terminal_e_sem_alvo_falha_claro(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert initcfg.run(tmp_path / "c.yaml") == 2
    assert "--target" in capsys.readouterr().err


def test_env_ao_lado_do_config_e_lido(tmp_path, monkeypatch):
    p = _cfg_file(tmp_path, "telegram:\n  enabled: true\n  bot_token: ${PADME_TG_T}\n  chat_id: '1'\n")
    (tmp_path / ".env").write_text("PADME_TG_T=segredo123\n", encoding="utf-8")
    monkeypatch.delenv("PADME_TG_T", raising=False)
    monkeypatch.chdir(tmp_path.parent)        # rodando de outra pasta
    visto = {}

    async def fake_events(cfg, args):
        visto["token"] = cfg.telegram.bot_token
        return 0

    monkeypatch.setattr(cli, "_cmd_events", fake_events)
    parser_real = cli.build_parser

    def parser_com_fake():
        p_ = parser_real()
        sub = next(a for a in p_._actions if a.__class__.__name__ == "_SubParsersAction")
        sub.choices["events"].set_defaults(func=fake_events)
        return p_

    monkeypatch.setattr(cli, "build_parser", parser_com_fake)
    assert cli.main(["-c", str(p), "events"]) == 0
    assert visto["token"] == "segredo123"


# ── --update ─────────────────────────────────────────────────────────────────
def test_update_e_tratado_antes_de_importar_a_cli(monkeypatch):
    chamado = {}
    monkeypatch.setattr(updater, "run", lambda force=False: chamado.setdefault("force", force) and 0)
    entry(["--update", "--force"])
    assert chamado == {"force": True}


def test_update_pip_ja_atualizado_nao_baixa(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(updater, "_in_docker", lambda: False)
    monkeypatch.setattr(updater, "install_kind", lambda: ("pip", None))
    monkeypatch.setattr(updater, "latest_commit", lambda timeout=10.0: "b" * 40)
    monkeypatch.setattr(updater, "data_dir", lambda: tmp_path)
    updater._save_commit("b" * 40)
    monkeypatch.setattr(updater, "_pip", lambda *a: pytest.fail("não devia chamar o pip"))
    assert updater.run() == 0
    assert "mais recente" in capsys.readouterr().out


def test_update_pip_baixa_o_commit_exato_e_so_deps_faltantes(monkeypatch, tmp_path):
    chamadas = []
    monkeypatch.setattr(updater, "_in_docker", lambda: False)
    monkeypatch.setattr(updater, "install_kind", lambda: ("pip", None))
    monkeypatch.setattr(updater, "latest_commit", lambda timeout=10.0: "c" * 40)
    monkeypatch.setattr(updater, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(updater, "_running_from_exe", lambda: False)
    monkeypatch.setattr(updater, "_pip", lambda *a: chamadas.append(a) or 0)
    assert updater.run() == 0
    primeiro = chamadas[0]
    assert "--force-reinstall" in primeiro and "--no-deps" in primeiro
    assert primeiro[-1] == f"https://github.com/LuizWT/PADME/archive/{'c' * 40}.zip"
    assert "--upgrade" not in chamadas[1] and "--force-reinstall" not in chamadas[1]
    assert updater.installed_commit() == "c" * 40


def test_update_em_clone_usa_git_pull(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    cmds = []
    monkeypatch.setattr(updater, "_in_docker", lambda: False)
    monkeypatch.setattr(updater, "install_kind", lambda: ("editable", tmp_path))
    monkeypatch.setattr(updater.subprocess, "call", lambda c, *a, **k: cmds.append(c) or 0)
    assert updater.run() == 0
    assert cmds[0] == ["git", "-C", str(tmp_path), "pull", "--ff-only"]
    assert "-e" in cmds[1]


def test_update_no_docker_orienta_pela_imagem(monkeypatch, capsys):
    monkeypatch.setattr(updater, "_in_docker", lambda: True)
    assert updater.run() == 1
    assert "docker compose build" in capsys.readouterr().out


def test_update_no_windows_pelo_exe_continua_em_processo_filho(monkeypatch):
    abertos = []
    monkeypatch.setattr(updater, "_in_docker", lambda: False)
    monkeypatch.setattr(updater, "install_kind", lambda: ("pip", None))
    monkeypatch.setattr(updater, "latest_commit", lambda timeout=10.0: None)
    monkeypatch.setattr(updater, "_running_from_exe", lambda: True)
    monkeypatch.delenv(updater._CHILD_ENV, raising=False)
    monkeypatch.setattr(updater.subprocess, "Popen", lambda args, env=None: abertos.append((args, env)))
    monkeypatch.setattr(updater, "_pip", lambda *a: pytest.fail("o pai não instala nada"))
    assert updater.run() == 0
    args, env = abertos[0]
    assert args[1:] == ["-m", "padme", "--update"] and env[updater._CHILD_ENV] == "1"


def test_update_sem_api_cai_para_o_branch(monkeypatch, tmp_path):
    chamadas = []
    monkeypatch.setattr(updater, "_in_docker", lambda: False)
    monkeypatch.setattr(updater, "install_kind", lambda: ("pip", None))
    monkeypatch.setattr(updater, "latest_commit", lambda timeout=10.0: None)
    monkeypatch.setattr(updater, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(updater, "_running_from_exe", lambda: False)
    monkeypatch.setattr(updater, "_pip", lambda *a: chamadas.append(a) or 0)
    assert updater.run() == 0
    assert chamadas[0][-1].endswith("/archive/main.zip")

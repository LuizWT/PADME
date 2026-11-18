"""Versão e changelog: a fonte única da versão, a seção do CHANGELOG que vira a
nota da release e o script que a extrai."""

import importlib.util
import tomllib
from pathlib import Path

import padme

RAIZ = Path(__file__).resolve().parent.parent


def _changelog():
    spec = importlib.util.spec_from_file_location("changelog", RAIZ / "scripts" / "changelog.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_versao_vem_de_um_lugar_so():
    proj = tomllib.loads((RAIZ / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" not in proj["project"]
    assert "version" in proj["project"]["dynamic"]
    assert proj["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "padme.__version__"}


def test_changelog_tem_a_versao_atual():
    # subiu o __version__ sem escrever o changelog: a release nem começa
    corpo = _changelog().section((RAIZ / "CHANGELOG.md").read_text(encoding="utf-8"),
                                 padme.__version__)
    assert corpo, f"CHANGELOG.md sem a seção [{padme.__version__}]"
    assert f"[{padme.__version__}]: https://github.com/LuizWT/PADME/releases/tag/v{padme.__version__}" \
        in (RAIZ / "CHANGELOG.md").read_text(encoding="utf-8")


TEXTO = """# Changelog

## [Não lançado]

## [0.3.0] - 2026-12-01

### Adicionado
- coisa nova

## [0.2.0] - 2026-11-16

### Corrigido
- coisa velha

[Não lançado]: https://exemplo/compare
[0.3.0]: https://exemplo/0.3.0
"""


def test_secao_vai_ate_a_proxima_e_para_nos_links():
    cl = _changelog()
    assert cl.section(TEXTO, "0.3.0") == "### Adicionado\n- coisa nova"
    assert cl.section(TEXTO, "0.2.0") == "### Corrigido\n- coisa velha"
    assert cl.section(TEXTO, "0.4.0") is None
    assert cl.section(TEXTO, "Não lançado") is None          # vazia não serve de nota
    assert cl.section(TEXTO, "0.3") is None                  # não casa por prefixo


def test_script_aceita_a_tag_e_falha_sem_secao(tmp_path, capsys):
    cl = _changelog()
    arq = tmp_path / "CHANGELOG.md"
    arq.write_text(TEXTO, encoding="utf-8")
    assert cl.main(["changelog.py", "v0.3.0", str(arq)]) == 0
    assert capsys.readouterr().out.strip() == "### Adicionado\n- coisa nova"
    assert cl.main(["changelog.py", "v9.9.9", str(arq)]) == 1
    assert "[9.9.9]" in capsys.readouterr().err


def test_workflow_publica_no_testpypi_e_no_pypi_sem_conflito_de_atestacao():
    """As duas publicações usam o mesmo dist/: a atestação que a primeira grava
    lá faz a segunda recusar ("already have publish attestations"). E a release
    do GitHub leva só o pacote, não as atestações."""
    import yaml
    wf = yaml.safe_load((RAIZ / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    steps = wf["jobs"]["publicar"]["steps"]
    pubs = [s for s in steps if str(s.get("uses", "")).startswith("pypa/gh-action-pypi-publish")]
    assert len(pubs) == 2
    teste, real = pubs
    assert "test.pypi.org" in teste["with"]["repository-url"]
    assert "repository-url" not in real.get("with", {})
    assert teste["with"].get("attestations") is False
    assert real.get("with", {}).get("attestations", True) is not False   # PyPI com atestação
    run = next(s for s in steps if s.get("name") == "Release no GitHub")["run"]
    assert "dist/*.whl dist/*.tar.gz" in run
    assert "dist/* " not in run and not run.rstrip().endswith("dist/*")


def test_imagem_docker_sai_para_amd64_e_arm64():
    """A release publica as duas arquiteturas numa tag só, depois de um smoke
    test em cada uma; o CI das PRs constrói e testa as mesmas duas."""
    import yaml
    wf = (RAIZ / ".github" / "workflows")
    rel = yaml.safe_load((wf / "release.yml").read_text(encoding="utf-8"))
    steps = rel["jobs"]["docker"]["steps"]
    usados = {str(s.get("uses", "")).split("@")[0] for s in steps}
    assert {"docker/setup-qemu-action", "docker/setup-buildx-action"} <= usados
    runs = "\n".join(s.get("run", "") for s in steps)
    for arch in ("amd64", "arm64"):
        assert f"--platform linux/{arch} --load" in runs
        assert f"docker-smoke.sh padme:release-{arch}" in runs
    assert "--platform linux/amd64,linux/arm64" in runs and "--push" in runs
    ci = yaml.safe_load((wf / "tests.yml").read_text(encoding="utf-8"))
    assert ci["jobs"]["docker"]["strategy"]["matrix"]["platform"] == ["linux/amd64", "linux/arm64"]

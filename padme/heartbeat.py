"""Heartbeat / dead-man's switch — a Padmé avisa que está viva.

No escopo pessoal o pior estado não é a máquina "não ser distribuída": é a
**morte silenciosa** — o loop cai, a máquina dorme, e você para de receber
alerta sem perceber. Um processo morto não consegue avisar que morreu; então
o sinal de vida vai pra **fora**: a cada N ciclos a Padmé faz um ping numa URL
de watchdog (healthchecks.io, Uptime Kuma, cronitor…). Se o ping some, é o
serviço externo que te alerta — esse é o dead-man's switch.

Além do ping, grava um arquivo local com o timestamp da última vida (útil pra
um `systemctl`/cron checar staleness, ou pro painel mostrar "visto por último").

Defensivo: qualquer falha (rede, disco) é logada mas nunca derruba o monitor —
o heartbeat não pode virar o motivo da queda que ele deveria detectar.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

log = logging.getLogger("padme")


class Heartbeat:
    def __init__(self, url: str = "", every_cycles: int = 1,
                 file: str = "", timeout: float = 10.0):
        self.url = url.strip()
        self.every_cycles = max(1, int(every_cycles))
        self.file = file.strip()
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.url or self.file)

    def should_beat(self, cycle: int) -> bool:
        """Bate no 1º ciclo e a cada `every_cycles` (cycle é 1-based)."""
        return cycle >= 1 and (cycle - 1) % self.every_cycles == 0

    def ping_url(self, ok: bool) -> str | None:
        """URL do ping. Convenção healthchecks.io: sucesso -> url; falha ->
        url/fail (o watchdog registra a falha sem esperar o timeout)."""
        if not self.url:
            return None
        return self.url if ok else self.url.rstrip("/") + "/fail"

    def _write_file(self, cycle: int, ok: bool, when: datetime) -> None:
        if not self.file:
            return
        line = f"{when.isoformat()} cycle={cycle} status={'ok' if ok else 'fail'}\n"
        try:
            with open(self.file, "w", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            log.warning("heartbeat: falha ao gravar %s: %s", self.file, exc)

    async def beat(self, cycle: int, ok: bool = True,
                   client: httpx.AsyncClient | None = None) -> bool:
        """Emite o sinal de vida do ciclo (arquivo + ping). Devolve True se o
        ping foi bem-sucedido (ou se não há URL, só arquivo)."""
        if not self.enabled or not self.should_beat(cycle):
            return False
        self._write_file(cycle, ok, datetime.now(timezone.utc))

        url = self.ping_url(ok)
        if not url:
            return True
        try:
            if client is not None:
                r = await client.get(url, timeout=self.timeout)
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as c:
                    r = await c.get(url)
            r.raise_for_status()
            return True
        except Exception as exc:  # noqa: BLE001 — heartbeat nunca derruba o loop
            log.warning("heartbeat: ping falhou (%s): %s", url, exc)
            return False


def from_config(cfg) -> Heartbeat | None:
    """Monta o Heartbeat a partir de cfg.heartbeat, ou None se desligado."""
    hb = getattr(cfg, "heartbeat", None)
    if not hb or not hb.enabled:
        return None
    h = Heartbeat(url=hb.url, every_cycles=hb.every_cycles,
                  file=hb.file, timeout=cfg.timeout)
    return h if h.enabled else None

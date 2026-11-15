"""Compatibilidade: o painel web agora vive no pacote `padme.web`.

Este módulo só reexporta os nomes públicos e sai numa próxima versão. Código
novo importa de `padme.web` (ex.: `from padme.web import start_background`).
"""

import warnings

from .web import (
    PanelServer,
    make_handler,
    render_export,
    render_vantage,
    serve,
    start_background,
)

warnings.warn("padme.webpanel foi substituído por padme.web e sai numa próxima versão",
              DeprecationWarning, stacklevel=2)

__all__ = ["PanelServer", "make_handler", "render_export", "render_vantage", "serve",
           "start_background"]

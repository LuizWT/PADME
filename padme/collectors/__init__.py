"""Collectors: cada um observa uma faceta da superfície de ataque.

- subdomains: passivo, via Certificate Transparency logs (crt.sh)
- wildcard:   detecta curinga de DNS (catch-all) p/ filtrar falso-positivo
- dns:        passivo, resolução A/AAAA/CNAME/MX
- http:       ativo leve, um GET por host (status, server, título)
- tls:        ativo leve, handshake para ler o certificado
- ports:      ativo, connect-scan (DESLIGADO por padrão)

Todos operam apenas sobre alvos que VOCÊ está autorizado a monitorar.
"""

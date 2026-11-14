"""Estilo e script do painel (strings estáticas, sem lógica).

Fora dos módulos de renderização para eles caberem na cabeça: aqui só mora
o CSS (tokens de cor validados p/ fundo escuro), o JS do gráfico de tendência
e o logo (PNG em padme/data, servido inline como data: URI — a CSP só permite
`img-src data:`, então nada é buscado fora da página).
"""

from base64 import b64encode
from importlib import resources


def _logo_data_uri() -> str:
    """Logo como data: URI; '' se o arquivo não estiver no pacote (o painel cai
    para a marca em texto, nunca quebra)."""
    try:
        raw = resources.files("padme").joinpath("data/logo.png").read_bytes()
    except (FileNotFoundError, OSError, ModuleNotFoundError):
        return ""
    return "data:image/png;base64," + b64encode(raw).decode("ascii")


_LOGO = _logo_data_uri()

# ── cores (dataviz — validadas p/ superfície escura) ────────────────────────
_TREND_ADD, _TREND_CHG, _TREND_REM = "#2fb36d", "#d9a03a", "#e5534b"

_CSS = """
:root{
  color-scheme:dark;
  --bg:#0b0e13; --side:#0d1117; --surface:#121720; --inset:#0e131a; --hover:#18202b;
  --ink:#e8ebf0; --ink2:#b3bbc7; --muted:#7c8696;
  --border:#1f2632; --line:#2a3240;
  --accent:#5b8def;
  --ok:#2fb36d; --warn:#e5a93b; --serious:#ec835a; --crit:#e5534b; --info:#5b8def;
  --add:#2fb36d; --chg:#d9a03a; --rem:#e5534b;
  --r:10px;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;
  --mono:ui-monospace,SFMono-Regular,"JetBrains Mono",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink2);font:13.5px/1.5 var(--sans);
  -webkit-font-smoothing:antialiased}
a{color:inherit}
code{font-family:var(--mono);background:rgba(255,255,255,.06);padding:0 4px;border-radius:4px;font-size:.92em}
.tabnum{font-variant-numeric:tabular-nums}
.mono{font-family:var(--mono)}

/* ── shell: sidebar + conteúdo ───────────────────────────────────────── */
.app{display:grid;grid-template-columns:236px minmax(0,1fr);min-height:100vh}
.side{position:sticky;top:0;height:100vh;overflow-y:auto;background:var(--side);
  border-right:1px solid var(--border);display:flex;flex-direction:column;gap:20px;padding:18px 12px}
.logo{display:flex;gap:10px;align-items:center;padding:2px 8px 0}
.logo .mark{width:30px;height:30px;border-radius:8px;flex:0 0 auto;display:grid;place-items:center;
  background:linear-gradient(135deg,#5b8def,#3657a8);color:#fff;font-weight:700;font-size:14px}
.logo img.mark{width:36px;height:36px;background:none;border-radius:0}
.logo b{display:block;color:var(--ink);letter-spacing:.14em;font-size:13px}
.logo small{display:block;color:var(--muted);font-size:11px;margin-top:1px}
.navlabel{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);
  padding:0 10px;margin:0 0 6px;font-weight:600}
.nav{display:flex;flex-direction:column;gap:1px}
.nav a{display:flex;align-items:center;gap:10px;padding:7px 10px;border-radius:7px;
  color:var(--ink2);text-decoration:none;font-size:13px}
.nav a:hover{background:var(--hover);color:var(--ink)}
.nav a.on{background:var(--hover);color:var(--ink);box-shadow:inset 2px 0 0 var(--accent)}
.nav svg{width:15px;height:15px;flex:0 0 auto;opacity:.75}
.nav .cnt{margin-left:auto;font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums}
.nav .cnt.hot{color:#fff;background:var(--crit);border-radius:999px;padding:0 7px;font-weight:600}
.tlist a{font-family:var(--mono);font-size:12px;padding:5px 10px}
.tlist a .dot{width:7px;height:7px;border-radius:50%;flex:0 0 auto}
.tlist a span.n{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sidefoot{margin-top:auto;border:1px solid var(--border);border-radius:var(--r);background:var(--inset);
  padding:12px;font-size:11.5px;color:var(--muted);display:flex;flex-direction:column;gap:5px}
.sidefoot .row2{display:flex;justify-content:space-between;gap:8px}
.sidefoot b{color:var(--ink2);font-weight:600;font-variant-numeric:tabular-nums}
.pill{font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:2px 9px}
.pill .ldot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;
  vertical-align:middle;background:var(--muted)}
.pill.live-on{color:#90d9b1}.pill.live-on .ldot{background:var(--ok);box-shadow:0 0 0 3px rgba(47,179,109,.18)}
.pill.live-wait{color:#f0cf8a}.pill.live-wait .ldot{background:var(--warn)}
.pill.live-err{color:#f2a3a3}.pill.live-err .ldot{background:var(--crit)}
.pill b{color:var(--ink2);font-weight:600}

.main{min-width:0;padding:24px 28px 48px;max-width:1440px}
.pagehead{display:flex;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:18px}
.pagehead h1{margin:0;font-size:20px;color:var(--ink);font-weight:650;letter-spacing:-.01em}
.pagehead p{margin:3px 0 0;color:var(--muted);font-size:12.5px}
.pagehead .actions{margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.sectitle{display:flex;align-items:baseline;gap:10px;margin:30px 0 10px}
.sectitle h2{margin:0;font-size:14px;color:var(--ink);font-weight:600}
.sectitle span{font-size:12px;color:var(--muted)}

/* ── KPIs ────────────────────────────────────────────────────────────── */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:14px 16px}
.kpi .l{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:7px}
.kpi .l::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--line)}
.kpi.accent .l::before{background:var(--accent)} .kpi.ok .l::before{background:var(--ok)}
.kpi.warn .l::before{background:var(--warn)} .kpi.crit .l::before{background:var(--crit)}
.kpi .n{font-size:28px;font-weight:650;color:var(--ink);line-height:1.15;margin-top:6px;
  font-variant-numeric:tabular-nums;letter-spacing:-.01em}
.kpi.crit .n{color:#f08a84} .kpi.warn .n{color:#efc06a}
.kpi .s{font-size:11.5px;color:var(--muted);margin-top:2px}

/* ── status chip: ponto + rótulo (nunca cor sozinha) ─────────────────── */
.chip{display:inline-flex;align-items:center;gap:6px;font-size:10.5px;font-weight:600;
  letter-spacing:.05em;text-transform:uppercase;white-space:nowrap;padding:2px 8px;
  border-radius:999px;background:rgba(255,255,255,.04);border:1px solid var(--border)}
.chip .dot,.dot{width:7px;height:7px;border-radius:50%;flex:0 0 auto;display:inline-block}
.s-crit{color:#f2a3a3}.s-crit .dot,.dot.s-crit{background:var(--crit)}
.chip.s-crit{background:rgba(229,83,75,.10);border-color:rgba(229,83,75,.35)}
.s-serious{color:#f4bea6}.s-serious .dot,.dot.s-serious{background:var(--serious)}
.chip.s-serious{background:rgba(236,131,90,.10);border-color:rgba(236,131,90,.35)}
.s-warn{color:#f0cf8a}.s-warn .dot,.dot.s-warn{background:var(--warn)}
.chip.s-warn{background:rgba(229,169,59,.09);border-color:rgba(229,169,59,.32)}
.s-info{color:#a9c4f5}.s-info .dot,.dot.s-info{background:var(--info)}
.s-ok{color:#90d9b1}.s-ok .dot,.dot.s-ok{background:var(--ok)}
.chip.s-ok{background:rgba(47,179,109,.08);border-color:rgba(47,179,109,.30)}
.s-muted{color:var(--muted)}.s-muted .dot,.dot.s-muted{background:var(--muted)}

/* ── cards e tabelas ─────────────────────────────────────────────────── */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
  overflow:hidden;min-width:0}
.cardhd{display:flex;align-items:baseline;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border)}
.cardhd h3{margin:0;font-size:13px;color:var(--ink);font-weight:600}
.cardhd .sub{font-size:11.5px;color:var(--muted)}
.cardhd .right{margin-left:auto;font-size:11.5px;color:var(--muted)}
.grid2{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(0,1fr);gap:14px;margin-top:14px;
  align-items:start}
.stack{display:flex;flex-direction:column;gap:14px;min-width:0}
.scroll{overflow-x:auto}
table.t{width:100%;border-collapse:collapse;font-size:12.5px}
.t th{text-align:left;font-weight:600;font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted);padding:8px 16px;border-bottom:1px solid var(--border);background:var(--inset);
  white-space:nowrap}
.t td{padding:10px 16px;border-bottom:1px solid var(--border);vertical-align:top}
.t tbody tr:last-child td{border-bottom:0}
.t tbody tr:hover td{background:rgba(255,255,255,.015)}
.t .r{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.t .nw{white-space:nowrap}
.t a{color:var(--ink);text-decoration:none}
.t a:hover{color:var(--accent)}
.who{font-family:var(--mono);font-size:12.5px;color:var(--ink);word-break:break-all}
.who .kd{font-family:var(--sans);font-size:10.5px;font-weight:600;letter-spacing:.06em;color:var(--muted);
  margin-right:6px}
.det{font-size:12px;color:var(--ink2);margin-top:1px;word-break:break-word}
.proof{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:3px;word-break:break-all}
.tgt{font-family:var(--mono);font-size:11.5px;color:var(--muted)}
.calm{padding:16px;display:flex;align-items:center;gap:10px;color:var(--ink2)}
.fid{font-family:var(--mono);font-size:10.5px;color:var(--muted);margin-left:8px;opacity:.8;
  white-space:nowrap;display:inline-block;word-break:normal}
table.pt{table-layout:fixed}
table.pt col.c-sev{width:118px} table.pt col.c-st{width:230px} table.pt col.c-tgt{width:130px}
.acth{font-size:10.5px;color:var(--muted)}
.chip.s-info{background:rgba(91,141,239,.09);border-color:rgba(91,141,239,.32)}
td.st{min-width:150px}
@media(max-width:820px){table.pt{table-layout:auto}}
.stx{font-size:11.5px;color:var(--muted);margin-top:4px}
.late{color:#f08a84;font-weight:600}
details.act{margin-top:6px}
details.act>summary{list-style:none;cursor:pointer;font-size:11.5px;color:var(--accent);user-select:none;
  display:inline-block}
details.act>summary::-webkit-details-marker{display:none}
details.act[open]>summary{color:var(--muted)}
.actf{margin-top:6px;display:flex;flex-direction:column;gap:6px;min-width:210px}
.actr{background:var(--inset);border:1px solid var(--border);border-radius:6px;color:var(--ink);
  font:12px var(--sans);padding:5px 8px}
.actr:focus{outline:none;border-color:var(--accent)}
.actr.need{border-color:var(--crit)}
.actb{display:flex;flex-wrap:wrap;gap:6px}
.actbtn{background:var(--surface);border:1px solid var(--line);color:var(--ink2);border-radius:6px;
  font:600 11.5px var(--sans);padding:4px 9px;cursor:pointer}
.actbtn:hover{border-color:var(--accent);color:var(--ink)}
.empty{color:var(--muted);padding:16px}
details.more>summary{list-style:none;cursor:pointer;padding:9px 16px;font-size:12px;color:var(--accent);
  border-top:1px solid var(--border);user-select:none}
details.more>summary::-webkit-details-marker{display:none}
details.more[open]>summary{color:var(--muted)}
.bar{height:5px;background:var(--line);border-radius:3px;overflow:hidden;min-width:60px}
.bar i{display:block;height:100%;background:var(--ok)}
.bar.warn i{background:var(--warn)} .bar.crit i{background:var(--crit)}

/* ── tendência / atividade ───────────────────────────────────────────── */
.trend{padding:12px 16px 14px}
.trend .hd{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.trend .hd b{color:var(--ink);font-size:13px;font-weight:600}
.trend .net{font-size:11.5px;color:var(--muted);margin-left:auto}
.trend .net b2{color:var(--ink2);font-weight:600}
.trend svg{width:100%;height:auto;display:block;margin-top:10px}
.legend{color:var(--muted);font-size:11px;margin-top:6px}
.lg{background:transparent;border:1px solid var(--border);border-radius:999px;color:var(--muted);
  font:11px var(--sans);padding:2px 9px;margin-right:6px;cursor:pointer;display:inline-flex;align-items:center}
.lg i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:5px;opacity:.35}
.lg.on{color:var(--ink2);border-color:var(--line)}
.lg.on i{opacity:1}
.lghint{font-size:11px;color:var(--muted)}

/* ── dossiê por alvo ─────────────────────────────────────────────────── */
.dossier{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
  margin-top:14px;overflow:hidden;scroll-margin-top:16px}
.doshd{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid var(--border);
  flex-wrap:wrap}
.doshd .name{font-family:var(--mono);color:var(--ink);font-size:15px;font-weight:600;word-break:break-all}
.doshd .meta{margin-left:auto;font-size:11.5px;color:var(--muted)}
.dosbody{display:grid;grid-template-columns:290px minmax(0,1fr)}
.dosside{border-right:1px solid var(--border);background:var(--inset);min-width:0}
.dosmain{min-width:0}
.blk{padding:14px 16px;border-bottom:1px solid var(--border)}
.blk:last-child{border-bottom:0}
.blk h4{margin:0 0 10px;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);
  font-weight:600;display:flex;gap:8px;align-items:baseline}
.blk h4 .c{margin-left:auto;letter-spacing:0;text-transform:none;font-weight:500}
.kv{display:grid;grid-template-columns:auto 1fr;gap:5px 12px;font-size:12px;margin:0}
.kv dt{color:var(--muted)}
.kv dd{margin:0;color:var(--ink2);text-align:right;font-variant-numeric:tabular-nums}
.health{margin-bottom:10px}
.collhealth{display:flex;flex-direction:column;gap:5px;margin-top:12px;padding-top:10px;
  border-top:1px dashed var(--line)}
.collhealth .chp{display:flex;align-items:center;justify-content:space-between;gap:8px;
  font-family:var(--mono);font-size:11.5px;color:var(--ink2)}
.risk{display:flex;flex-direction:column;gap:8px}
.risk .ri{display:flex;gap:8px;align-items:flex-start;font-size:12px}
.risk .ri .dot{margin-top:5px}
.risk .ri .w{font-family:var(--mono);color:var(--ink);word-break:break-all}
.risk .ri .d{color:var(--muted);font-size:11.5px}
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:9px 11px}
.tile .num{font-size:19px;font-weight:650;color:var(--ink);line-height:1.1;font-variant-numeric:tabular-nums}
.tile .lab{font-size:10.5px;color:var(--muted);margin-top:2px}
.tile .sub{font-size:10.5px;color:var(--ink2);margin-top:1px}
.tile.crit{border-color:rgba(229,83,75,.45)}.tile.crit .num{color:#f08a84}
.tile.warn{border-color:rgba(229,169,59,.4)}.tile.warn .num{color:#efc06a}

.dosmain .trend{border-top:1px solid var(--border)}
.panehd{display:flex;align-items:baseline;gap:10px;padding:12px 18px;border-bottom:1px solid var(--border)}
.panehd h4{margin:0;font-size:13px;color:var(--ink);font-weight:600}
.panehd span{font-size:11.5px;color:var(--muted)}
.ev{padding:12px 18px;border-bottom:1px solid var(--border);box-shadow:inset 3px 0 0 transparent}
.ev.lv-crit{box-shadow:inset 3px 0 0 var(--crit)} .ev.lv-serious{box-shadow:inset 3px 0 0 var(--serious)}
.ev.lv-warn{box-shadow:inset 3px 0 0 var(--warn)}
.evhd{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.evkind{font-size:10.5px;font-weight:600;letter-spacing:.06em;color:var(--muted);text-transform:uppercase}
.evkey{font-family:var(--mono);color:var(--ink);font-size:12.5px;word-break:break-all}
.evhd .when{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted);white-space:nowrap}
.diff{margin-top:8px;border:1px solid var(--border);border-radius:6px;overflow:hidden;
  font-family:var(--mono);font-size:12px}
.diff>div,.diff .chgdet{padding:3px 10px;white-space:pre-wrap;word-break:break-all}
.diff .da{background:rgba(47,179,109,.07);color:#a3e2c0}
.diff .dr{background:rgba(229,83,75,.07);color:#f2b0ab}
.diff .chgdet{display:block;color:var(--ink2);background:var(--inset);font-size:11.5px;
  border-top:1px solid var(--border)}
.diff .mk{display:inline-block;width:14px;opacity:.8}
.evmeta{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.tag{font-size:10.5px;border:1px solid var(--border);border-radius:999px;padding:1px 8px;color:var(--muted);
  white-space:nowrap;font-family:var(--sans)}
.tag.why{color:#f2aaa5;border-color:rgba(229,83,75,.35)}
.tag.prov{font-family:var(--mono)}

details.kinds{border-top:1px solid var(--border)}
details.kinds>summary{list-style:none;cursor:pointer;padding:12px 18px;font-size:13px;color:var(--ink);
  font-weight:600;user-select:none;display:flex;gap:8px;align-items:center}
details.kinds>summary::-webkit-details-marker{display:none}
details.kinds>summary::before{content:"";width:6px;height:6px;border-right:1.5px solid var(--muted);
  border-bottom:1.5px solid var(--muted);transform:rotate(-45deg);margin-right:4px;transition:transform .15s}
details.kinds[open]>summary::before{transform:rotate(45deg)}
details.kinds>summary span{font-weight:400;font-size:11.5px;color:var(--muted)}
.kfilter{display:block;width:calc(100% - 36px);margin:0 18px 8px;padding:7px 10px;font:inherit;font-size:12.5px;
  color:var(--ink);background:var(--inset);border:1px solid var(--border);border-radius:7px}
.kfilter:focus{outline:none;border-color:var(--accent)}
.kfilter.nomatch{border-color:var(--crit)}
.kind{padding:6px 18px 10px}
.kind>b{display:block;color:var(--muted);font-size:10.5px;letter-spacing:.1em;font-weight:600;
  padding-bottom:4px;border-bottom:1px solid var(--border);margin-bottom:4px}
.kind.hide,.row.hide{display:none}
.row{display:flex;gap:10px;align-items:baseline;padding:3px 0;font-family:var(--mono);font-size:12.5px;
  word-break:break-all}
.row .k{color:var(--ink)} .row .v{color:var(--muted)}
.row .fp{margin-left:auto;display:inline-flex;gap:6px;flex:0 0 auto}
.row .fp .svc{color:var(--accent);font-size:11px}
.row .fp .prod{color:var(--ink2);font-size:11px}

/* ── controles ───────────────────────────────────────────────────────── */
.filterform{display:flex;gap:6px;align-items:center}
.finput{background:var(--inset);border:1px solid var(--border);border-radius:7px;color:var(--ink);
  font:12.5px var(--mono);padding:6px 11px;min-width:220px}
.finput:focus{outline:none;border-color:var(--accent)}
.fbtn{background:var(--accent);border:1px solid var(--accent);color:#fff;border-radius:7px;
  font:600 12px var(--sans);padding:6px 12px;cursor:pointer}
.fclear{color:var(--muted);font-size:12px;text-decoration:none}
.fclear:hover{color:var(--ink2)}
.exports{display:inline-flex;align-items:center;gap:6px}
.xbtn{color:var(--ink2);border:1px solid var(--border);background:var(--surface);border-radius:7px;
  padding:5px 10px;text-decoration:none;font-size:12px}
.xbtn:hover{border-color:var(--accent);color:var(--ink)}
.banner,.note{border-radius:var(--r);padding:11px 14px;margin:0 0 16px;font-size:12.5px;
  display:flex;gap:10px;align-items:flex-start}
.banner{background:rgba(229,83,75,.08);border:1px solid rgba(229,83,75,.4);color:#f2b0ab}
.note{background:rgba(91,141,239,.07);border:1px solid rgba(91,141,239,.35);color:#b5cbf5}
footer{color:var(--muted);font-size:11.5px;margin-top:36px;padding-top:14px;border-top:1px solid var(--border)}

@media(max-width:1100px){
  .grid2{grid-template-columns:1fr}
  .dosbody{grid-template-columns:1fr}
  .dosside{border-right:0;border-bottom:1px solid var(--border)}
}
@media(max-width:820px){
  .app{grid-template-columns:minmax(0,1fr)}
  .side{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:10px 16px;
    padding:12px 16px;border-right:0;border-bottom:1px solid var(--border)}
  .side .navlabel,.side .tlistwrap{display:none}
  .nav{flex-direction:row;flex-wrap:wrap}
  .sidefoot{margin:0;flex-direction:row;flex-wrap:wrap;gap:4px 14px;width:100%}
  .main{padding:16px}
  .pagehead .actions{margin-left:0;width:100%}
  .filterform{flex:1 1 100%}
  .finput{min-width:0;flex:1}
  .kpis{grid-template-columns:repeat(2,minmax(0,1fr))}
  .kpi .n{font-size:24px}
  .t th,.t td{padding:8px 10px}
  .ev,.panehd{padding-left:14px;padding-right:14px}
}
"""


_TREND_JS = """<script>
(function(){
  var COL={added:'#2fb36d',changed:'#d9a03a',removed:'#e5534b'};
  var KS=['added','changed','removed'];
  function svg(series, active, W){
    W=Math.max(260, Math.round(W||720)); var H=132,pl=26,pr=8,pt=10,pb=20,pw=W-pl-pr,ph=H-pt-pb,base=pt+ph;
    var tot=series.map(function(d){var s=0;KS.forEach(function(k){if(active.has(k))s+=d[k];});return s;});
    var max=Math.max.apply(null,[0].concat(tot));
    var p='<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none">';
    p+='<line x1="'+pl+'" y1="'+base+'" x2="'+(W-pr)+'" y2="'+base+'" stroke="#2a3240"/>';
    if(max>0) p+='<text x="'+(pl-4)+'" y="'+(pt+4)+'" text-anchor="end" font-size="9" fill="#7c8696">'+max+'</text>';
    var n=series.length, slot=n?pw/n:pw, bw=Math.max(1,slot-2), sc=max>0?ph/max:0;
    series.forEach(function(d,i){
      var x=pl+i*slot+(slot-bw)/2, yb=base;
      KS.forEach(function(k){ if(!active.has(k))return; var h=d[k]*sc; if(h>0){var dr=h>2?h-2:h;
        p+='<rect x="'+x.toFixed(1)+'" y="'+(yb-dr).toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+dr.toFixed(1)+'" fill="'+COL[k]+'" rx="1.5"><title>'+d.day+': +'+d.added+' ~'+d.changed+' -'+d.removed+'</title></rect>';
        yb-=h;} });
    });
    if(n){ var idxs=[0,n>>1,n-1].filter(function(v,i,a){return a.indexOf(v)===i;});
      idxs.forEach(function(idx){ var lab=series[idx].day.slice(5), cx=pl+idx*slot+slot/2,
        anc=idx===0?'start':(idx===n-1?'end':'middle');
        p+='<text x="'+cx.toFixed(1)+'" y="'+(H-6)+'" text-anchor="'+anc+'" font-size="9" fill="#7c8696">'+lab+'</text>'; }); }
    return p+'</svg>';
  }

  var charts=[];          // redesenho no resize (um listener só, não um por atualização)
  var legend={};          // séries ligadas/desligadas por gráfico, sobrevivem à atualização
  window.addEventListener('resize', function(){ charts.forEach(function(f){ f(); }); });

  // Liga o comportamento do conteúdo. Roda no carregamento e de novo a cada
  // atualização ao vivo (o conteúdo é trocado, os listeners precisam voltar).
  function initPage(){
    // aberto/fechado de cada <details> lembrado entre atualizações
    document.querySelectorAll('details[data-persist]').forEach(function(d){
      var key='padme:'+d.getAttribute('data-persist');
      try{ if(localStorage.getItem(key)==='1') d.open=true; }catch(e){}
      d.addEventListener('toggle', function(){
        try{ localStorage.setItem(key, d.open?'1':'0'); }catch(e){}
      });
    });

    // busca local por categoria: filtra as linhas e esconde grupos sem match.
    // O texto é lembrado e reaplicado depois de cada atualização ao vivo.
    document.querySelectorAll('.kfilter').forEach(function(inp){
      var det=inp.closest('details');
      var key='padme:f-'+(det&&det.getAttribute('data-persist')||'');
      function apply(){
        var q=inp.value.trim().toLowerCase();
        if(q && det) det.open=true;
        var any=false;
        det.querySelectorAll('.kind').forEach(function(g){
          var kind=(g.getAttribute('data-kind')||'').toLowerCase();
          var shown=0;
          g.querySelectorAll('.row').forEach(function(r){
            var hit=!q || kind.indexOf(q)!==-1 || r.textContent.toLowerCase().indexOf(q)!==-1;
            r.classList.toggle('hide', !hit);
            if(hit) shown++;
          });
          g.classList.toggle('hide', shown===0);
          if(shown) any=true;
        });
        inp.classList.toggle('nomatch', !!q && !any);
      }
      try{ var saved=localStorage.getItem(key); if(saved){ inp.value=saved; } }catch(e){}
      inp.addEventListener('input', function(){
        try{ localStorage.setItem(key, inp.value); }catch(e){}
        apply();
      });
      if(inp.value) apply();
    });

    // falso positivo / aceitar risco exigem motivo (o servidor também valida)
    document.querySelectorAll('form.actf').forEach(function(f){
      f.addEventListener('submit', function(ev){
        var btn=ev.submitter, r=f.querySelector('.actr');
        var need=btn && (btn.value==='suppress'||btn.value==='accept');
        if(need && r && !r.value.trim()){
          ev.preventDefault(); r.classList.add('need'); r.focus();
        }
      });
    });

    charts=[];
    document.querySelectorAll('.trend').forEach(function(el, i){
      var dataEl=el.querySelector('.tdata'), chart=el.querySelector('.chart');
      if(!dataEl||!chart) return;
      var series; try{ series=JSON.parse(dataEl.textContent); }catch(e){ return; }
      var id=(el.getAttribute('data-days')||'')+':'+i;
      if(legend[id]) el.querySelectorAll('.lg').forEach(function(b){
        b.classList.toggle('on', legend[id].indexOf(b.dataset.t)!==-1); });
      function redraw(){
        var active=new Set();
        el.querySelectorAll('.lg.on').forEach(function(b){active.add(b.dataset.t);});
        legend[id]=Array.from(active);
        chart.innerHTML=svg(series, active, chart.clientWidth);
      }
      el.querySelectorAll('.lg').forEach(function(b){
        b.addEventListener('click', function(){ b.classList.toggle('on'); redraw(); });
      });
      redraw();
      charts.push(redraw);
    });
  }
  initPage();

  // ── ao vivo ───────────────────────────────────────────────────────────────
  // O servidor avisa por /live (Server-Sent Events) quando o banco muda; aqui a
  // página é buscada de novo e só o conteúdo é trocado: sem recarregar, sem
  // perder a rolagem, o filtro ou o que estava aberto. Espera só enquanto você
  // digita ou está com um menu de ação aberto. Sem /live (navegador antigo ou
  // proxy que corta a conexão), cai para atualizar a cada 30 s.
  function pill(state, text){
    var p=document.getElementById('autopill');
    if(!p) return;
    p.className='pill live-'+state;
    p.innerHTML='<span class=ldot></span>'+text;
  }
  function interacting(){
    var a=document.activeElement;
    var typing=a && (a.tagName==='INPUT'||a.tagName==='TEXTAREA'||a.tagName==='SELECT');
    return typing || !!document.querySelector('details.act[open]');
  }
  var pending=false, busy=false, last=0, broken=0;
  function refresh(){
    if(busy) return;
    if(interacting()){ pill('wait','em espera'); return; }
    busy=true; pending=false;
    fetch(location.href, {cache:'no-store', credentials:'same-origin'})
      .then(function(r){ if(!r.ok) throw new Error(r.status); return r.text(); })
      .then(function(html){
        var doc=new DOMParser().parseFromString(html, 'text/html');
        var fresh=doc.querySelector('.app'), cur=document.querySelector('.app');
        if(!fresh||!cur) throw new Error('sem conteúdo');
        var y=window.scrollY;
        cur.replaceWith(fresh);
        initPage();
        window.scrollTo(0, y);
        last=Date.now();
        pill('on', broken ? 'atualizando a cada 30 s' : 'ao vivo');
      })
      .catch(function(){ pill('err','sem conexão'); pending=true; })
      .then(function(){ busy=false; });
  }
  setInterval(function(){
    if(pending && Date.now()-last > 1500) refresh();       // agrupa rajadas de mudança
    else if(broken && Date.now()-broken > 30000){ broken=Date.now(); refresh(); }
  }, 1000);
  if('EventSource' in window){
    var es=new EventSource('/live');
    es.addEventListener('change', function(){ pending=true; });
    es.onopen=function(){ broken=0; pill('on','ao vivo'); };
    es.onerror=function(){ if(!broken) broken=Date.now(); pill('err','reconectando'); };
  } else {
    broken=Date.now(); pill('on','atualizando a cada 30 s');
  }
})();
</script>"""

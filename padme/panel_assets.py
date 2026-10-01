"""Estilo e script do painel (strings estáticas, sem lógica).

Fora do `webpanel` para o módulo de renderização caber na cabeça: aqui só mora
o CSS (tokens de cor validados p/ fundo escuro) e o JS do gráfico de tendência.
"""

# ── cores (dataviz — validadas p/ superfície escura) ────────────────────────
_TREND_ADD, _TREND_CHG, _TREND_REM = "#199e70", "#c98500", "#e66767"

_CSS = """
:root{
  color-scheme:dark;
  --plane:#0d0d0d; --surface:#1a1a19; --inset:#111110;
  --ink:#ffffff; --ink2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --line:#383835; --border:rgba(255,255,255,.10);
  --ok:#0ca30c; --warn:#fab219; --serious:#ec835a; --crit:#d03b3b; --info:#3987e5;
  --add:#199e70; --chg:#c98500; --rem:#e66767;
  --r:12px;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--plane);color:var(--ink2);font:14px/1.55 var(--sans)}
a{color:inherit}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px 40px}
.tabnum{font-variant-numeric:tabular-nums}

/* topbar */
header{position:sticky;top:0;z-index:5;background:rgba(13,13,13,.86);
  backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}
.top{max-width:1180px;margin:0 auto;padding:14px 16px;display:flex;align-items:baseline;
  gap:12px;flex-wrap:wrap}
.brand{font-weight:700;letter-spacing:.02em;color:var(--ink);font-size:17px}
.brand small{font-weight:500;color:var(--muted);font-size:12px;letter-spacing:.04em;margin-left:8px}
.top .spacer{flex:1}
.pill{font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:999px;
  padding:3px 10px;letter-spacing:.03em}
.pill b{color:var(--ink2);font-weight:600}

/* section title */
.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);
  margin:26px 2px 10px;font-weight:600}

/* KPI row */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:10px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
  padding:14px 16px;position:relative;overflow:hidden}
.kpi .n{font-size:30px;font-weight:650;color:var(--ink);line-height:1;font-variant-numeric:tabular-nums}
.kpi .l{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:7px}
.kpi .s{font-size:11px;color:var(--ink2);margin-top:3px}
.kpi.accent::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--info)}
.kpi.ok::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--ok)}
.kpi.crit::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--crit)}
.kpi.warn::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--warn)}
.kpi.crit .n{color:var(--crit)} .kpi.warn .n{color:var(--warn)} .kpi.ok .n{color:var(--ok)}

/* status chip: ponto + rótulo (nunca cor sozinha) */
.chip{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:600;
  letter-spacing:.04em;text-transform:uppercase;white-space:nowrap}
.chip .dot{width:8px;height:8px;border-radius:50%;flex:0 0 auto}
.s-crit{color:#f2a3a3}.s-crit .dot{background:var(--crit)}
.s-serious{color:#f2c1ab}.s-serious .dot{background:var(--serious)}
.s-warn{color:#f4d68a}.s-warn .dot{background:var(--warn)}
.s-info{color:#a9c9f2}.s-info .dot{background:var(--info)}
.s-ok{color:#8fd48f}.s-ok .dot{background:var(--ok)}
.s-muted{color:var(--muted)}.s-muted .dot{background:var(--muted)}

/* problems panel */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.prow{display:grid;grid-template-columns:120px 1fr auto;gap:12px;align-items:center;
  padding:11px 16px;border-top:1px solid var(--border)}
.prow:first-child{border-top:0}
.prow .who{font-family:var(--mono);font-size:12.5px;color:var(--ink);word-break:break-all}
.prow .det{font-size:12px;color:var(--ink2);word-break:break-all}
.prow .proof{font-family:var(--mono);font-size:10.5px;color:var(--muted);margin-top:2px;word-break:break-all}
.prow .tgt{font-size:11px;color:var(--muted);font-family:var(--mono);text-align:right}
.calm{padding:16px;display:flex;align-items:center;gap:10px;color:var(--ink2)}

/* host card */
.host{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
  margin-top:12px;overflow:hidden;scroll-margin-top:70px}
.host>h2{margin:0;padding:13px 16px;display:flex;align-items:center;gap:10px;
  border-bottom:1px solid var(--border);font-size:15px;color:var(--ink);font-weight:650}
.host>h2 .name{font-family:var(--mono);letter-spacing:0}
.host>h2 .count{margin-left:auto;font-size:11px;color:var(--muted);font-weight:500;letter-spacing:.04em}
.health{display:flex;flex-wrap:wrap;gap:6px 16px;padding:9px 16px;border-bottom:1px solid var(--border);
  font-size:11.5px;color:var(--muted)}
.health b{color:var(--ink2);font-weight:600}
.collhealth{display:flex;flex-wrap:wrap;gap:6px 12px;padding:8px 16px 9px;border-bottom:1px solid var(--border);
  border-top:1px dashed var(--border);font-size:10.5px;color:var(--muted)}
.collhealth .chp{display:inline-flex;align-items:center;gap:4px;font-family:var(--mono)}
.kfilter{width:calc(100% - 32px);margin:8px 16px 4px;padding:6px 10px;font:inherit;font-size:12px;
  color:var(--ink2);background:var(--bg);border:1px solid var(--border);border-radius:6px}
.kfilter:focus{outline:none;border-color:var(--muted)}
.kind.hide,.row.hide{display:none}
.kfilter.nomatch{border-color:var(--s-crit,#e66767)}

.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:8px;padding:14px 16px}
.tile{background:var(--inset);border:1px solid var(--border);border-radius:10px;padding:10px 12px}
.tile .num{font-size:20px;font-weight:650;color:var(--ink);line-height:1.05;font-variant-numeric:tabular-nums}
.tile .lab{font-size:10px;letter-spacing:.05em;color:var(--muted);margin-top:3px;text-transform:uppercase}
.tile .sub{font-size:10px;color:var(--ink2);margin-top:2px}
.tile.crit{border-color:rgba(208,59,59,.5)}.tile.crit .num{color:var(--crit)}
.tile.warn{border-color:rgba(250,178,25,.45)}.tile.warn .num{color:var(--warn)}

details.kinds{border-top:1px solid var(--border)}
details.kinds>summary{list-style:none;cursor:pointer;padding:10px 16px;font-size:11px;
  letter-spacing:.1em;text-transform:uppercase;color:var(--muted);user-select:none}
details.kinds>summary::-webkit-details-marker{display:none}
details.kinds>summary::before{content:"▸ ";color:var(--muted)}
details.kinds[open]>summary::before{content:"▾ "}
.kind{padding:6px 16px 10px}
.kind b{color:var(--info);font-size:11px;letter-spacing:.06em}
.row{padding:2px 0 2px 12px;white-space:pre-wrap;word-break:break-all;font-family:var(--mono);font-size:12.5px}
.row .k{color:var(--ink)} .row .v{color:var(--muted)}
.row .fp{margin-left:8px}
.row .fp .svc{color:var(--info);font-size:11px;letter-spacing:.04em}
.row .fp .prod{color:var(--ink2);font-size:11px;margin-left:6px}

.trend{padding:12px 16px;border-top:1px solid var(--border)}
.trend .hd{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.trend b{color:var(--info);font-size:11px;letter-spacing:.06em;text-transform:uppercase}
.trend .net{font-size:11px;color:var(--muted)}
.trend .net b2{color:var(--ink2)}
.trend svg{width:100%;height:auto;display:block;margin-top:8px}
.legend{color:var(--muted);font-size:11px;margin-top:5px}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin:0 5px 0 12px;vertical-align:middle}

.events{padding:8px 16px 14px;border-top:1px solid var(--border)}
.events .line{padding:3px 0;display:flex;gap:8px;align-items:baseline;font-size:12.5px;border-top:1px solid rgba(255,255,255,.04)}
.events .line:first-of-type{border-top:0}
.events .when{color:var(--muted);font-family:var(--mono);font-size:11px;white-space:nowrap}
.events .body{font-family:var(--mono);word-break:break-all}
.events .add .mk{color:var(--add)} .events .rem .mk{color:var(--rem)} .events .chg .mk{color:var(--chg)}
.events .mk{font-weight:700}
.events .why{color:var(--crit);font-family:var(--sans);font-size:11px;margin-left:8px;font-weight:600}
.events .conf{color:var(--muted);font-family:var(--sans);font-size:10px;margin-left:8px}
.events .proof{color:var(--ink2);font-family:var(--sans);font-size:10px;margin-left:8px;opacity:.85}
.events .chgdet{display:block;color:var(--ink2);font-size:11px;margin:2px 0 0 18px}

.empty{color:var(--muted);padding:16px}
.toolbar{display:flex;flex-wrap:wrap;gap:10px 16px;align-items:center;margin:16px 0 0}
.filterform{display:flex;gap:6px;align-items:center}
.finput{background:var(--inset);border:1px solid var(--border);border-radius:8px;color:var(--ink);
  font:13px var(--mono);padding:6px 12px;min-width:230px}
.finput:focus{outline:none;border-color:var(--info)}
.fbtn{background:var(--info);border:1px solid var(--info);color:#fff;border-radius:8px;
  font-size:12px;font-weight:600;padding:6px 12px;cursor:pointer}
.fclear{color:var(--muted);font-size:12px;text-decoration:none}
.fclear:hover{color:var(--ink2)}
.exports{margin-left:auto;font-size:11px;color:var(--muted);display:inline-flex;align-items:center;gap:8px}
.xbtn{color:var(--ink2);border:1px solid var(--border);border-radius:8px;padding:5px 10px;
  text-decoration:none;font-family:var(--mono);font-size:11px}
.xbtn:hover{border-color:var(--info);color:var(--info)}
.lg{background:transparent;border:1px solid var(--border);border-radius:999px;color:var(--muted);
  font:11px var(--sans);padding:3px 10px;margin-right:6px;cursor:pointer;display:inline-flex;
  align-items:center;gap:0}
.lg i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:middle;opacity:.35}
.lg.on{color:var(--ink2);border-color:var(--muted)}
.lg.on i{opacity:1}
.lghint{font-size:10px;color:var(--muted);margin-left:4px}
.banner{background:#2a1414;border:1px solid var(--crit);color:#f2a3a3;border-radius:10px;
  padding:11px 14px;margin:16px 0 0;font-size:12.5px}
.banner code,.note code{font-family:var(--mono);background:rgba(255,255,255,.08);padding:0 4px;border-radius:4px}
.note{background:#12211a;border:1px solid var(--add);color:#8fd4b3;border-radius:10px;
  padding:10px 14px;margin:16px 0 0;font-size:12.5px}
footer{color:var(--muted);font-size:11px;margin-top:30px;text-align:center;padding-top:16px;
  border-top:1px solid var(--border)}
@media(max-width:560px){.prow{grid-template-columns:1fr;gap:4px}.prow .tgt{text-align:left}}
"""


_TREND_JS = """<script>
(function(){
  var COL={added:'#199e70',changed:'#c98500',removed:'#e66767'};
  var KS=['added','changed','removed'];
  function svg(series, active){
    var W=720,H=132,pl=26,pr=8,pt=10,pb=20,pw=W-pl-pr,ph=H-pt-pb,base=pt+ph;
    var tot=series.map(function(d){var s=0;KS.forEach(function(k){if(active.has(k))s+=d[k];});return s;});
    var max=Math.max.apply(null,[0].concat(tot));
    var p='<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none">';
    p+='<line x1="'+pl+'" y1="'+base+'" x2="'+(W-pr)+'" y2="'+base+'" stroke="#383835"/>';
    if(max>0) p+='<text x="'+(pl-4)+'" y="'+(pt+4)+'" text-anchor="end" font-size="9" fill="#898781">'+max+'</text>';
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
        p+='<text x="'+cx.toFixed(1)+'" y="'+(H-6)+'" text-anchor="'+anc+'" font-size="9" fill="#898781">'+lab+'</text>'; }); }
    return p+'</svg>';
  }
  // lembra aberto/fechado de cada <details> entre os auto-refreshes de 30s
  document.querySelectorAll('details[data-persist]').forEach(function(d){
    var key='padme:'+d.getAttribute('data-persist');
    try{ if(localStorage.getItem(key)==='1') d.open=true; }catch(e){}
    d.addEventListener('toggle', function(){
      try{ localStorage.setItem(key, d.open?'1':'0'); }catch(e){}
    });
  });

  // busca local por categoria: filtra as linhas (host/porta/kind/valor) e
  // esconde grupos sem match; abre o <details> ao digitar.
  document.querySelectorAll('.kfilter').forEach(function(inp){
    var det=inp.closest('details');
    inp.addEventListener('input', function(){
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
    });
  });

  document.querySelectorAll('.trend').forEach(function(el){
    var dataEl=el.querySelector('.tdata'), chart=el.querySelector('.chart');
    if(!dataEl||!chart) return;
    var series; try{ series=JSON.parse(dataEl.textContent); }catch(e){ return; }
    function redraw(){
      var active=new Set();
      el.querySelectorAll('.lg.on').forEach(function(b){active.add(b.dataset.t);});
      chart.innerHTML=svg(series, active);
    }
    el.querySelectorAll('.lg').forEach(function(b){
      b.addEventListener('click', function(){ b.classList.toggle('on'); redraw(); });
    });
    redraw();
  });
})();
</script>"""

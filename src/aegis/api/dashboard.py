"""Self-contained SOC dashboard (single HTML string, no external CDN).

Vanilla JS polls the AEGIS REST API and renders a live security-operations
console: risk leaderboard, alert feed, JIT approval queue, MITRE coverage,
quantum-crypto posture, and one-click insider-threat scenario injection.
"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>AEGIS — Insider Threat & Privileged Access Defense</title>
<style>
  :root{
    --bg:#f4f3ef; --panel:#ffffff; --panel2:#ffffff;
    --line:#e2dfd8; --line2:#eceae4; --ink:#141414; --mut:#6d6d6d;
    --navy:#1f3a5f; --steel:#7a9cc6;
    --grn:#256d46; --amb:#a07618; --org:#b04a17; --red:#9e1b32;
    --serif:Georgia,'Times New Roman',Times,serif;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
    font:14px/1.55 'Helvetica Neue',-apple-system,'Segoe UI',Roboto,Arial,sans-serif}
  a{color:var(--navy)}
  .top{display:flex;align-items:center;gap:18px;padding:16px 28px;
    border-bottom:1px solid var(--line);background:#fff;
    position:sticky;top:0;z-index:5}
  .brand{display:flex;align-items:center;gap:14px}
  .logo{width:38px;height:38px;display:grid;place-items:center;
    background:var(--navy);color:#fff;font-family:var(--serif);font-size:20px}
  .brand h1{font-size:22px;margin:0;letter-spacing:.2px;font-family:var(--serif);font-weight:600}
  .brand span{color:var(--mut);font-size:11.5px;letter-spacing:.3px}
  .badges{display:flex;gap:8px;margin-left:auto;flex-wrap:wrap}
  .badge{padding:5px 12px;font-size:11px;font-weight:600;letter-spacing:.5px;
    border:1px solid var(--line);background:#fff;white-space:nowrap;color:#444;text-transform:uppercase}
  .badge.qs{color:var(--navy);border-color:#b9c9de;background:#eef2f8}
  .badge.cl{color:var(--amb);border-color:#e0d2ae;background:#faf6ea}
  .badge.ok{color:var(--grn);border-color:#bcd8c8;background:#eef6f1}
  .badge.bad{color:var(--red);border-color:#e3bcc4;background:#faeef0}
  .wrap{max-width:1500px;margin:0 auto;padding:24px 28px;
    display:grid;grid-template-columns:1.55fr 1fr;gap:18px}
  .kpis{grid-column:1/-1;display:grid;grid-template-columns:repeat(6,1fr);gap:18px}
  .kpi{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--navy);
    padding:18px 16px 14px}
  .kpi .n{font-size:30px;font-weight:400;font-family:var(--serif)}
  .kpi .l{color:var(--mut);font-size:10.5px;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
  .card{background:var(--panel);border:1px solid var(--line);overflow:hidden}
  .card h2{margin:0;padding:14px 18px;font-size:12px;letter-spacing:1.2px;
    text-transform:uppercase;color:var(--ink);font-weight:700;background:#fbfaf8;
    border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px}
  .card .body{padding:8px 12px}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:10px;font-size:13px;border-bottom:1px solid var(--line2)}
  th{color:var(--mut);font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.8px}
  tr.row{cursor:pointer}
  tr.row:hover{background:#f6f4ef}
  .tier{padding:3px 10px;font-size:10.5px;font-weight:700;letter-spacing:.6px}
  .LOW{color:var(--grn);background:#eaf3ee;border:1px solid #cfe3d7}
  .ELEVATED{color:var(--amb);background:#f8f3e4;border:1px solid #e7d9b0}
  .HIGH{color:var(--org);background:#f9ede4;border:1px solid #ecd0ba}
  .CRITICAL{color:#fff;background:var(--red);border:1px solid var(--red)}
  .bar{height:6px;background:#e9e7e1;overflow:hidden;min-width:90px}
  .bar > i{display:block;height:100%}
  .pager{display:flex;align-items:center;justify-content:space-between;gap:10px;
    padding:10px 8px 8px;border-top:1px solid var(--line2)}
  .pager span{font-size:11px;letter-spacing:.3px}
  .pager .pbtns{display:flex;gap:6px}
  .pager button{cursor:pointer;border:1px solid var(--line);background:#fff;color:var(--ink);
    padding:5px 12px;font-weight:600;font-size:11.5px;letter-spacing:.3px;transition:.15s}
  .pager button:hover:not(:disabled){background:var(--navy);border-color:var(--navy);color:#fff}
  .pager button:disabled{opacity:.35;cursor:default}
  .who{display:flex;flex-direction:column}
  .who b{font-weight:650}.who small{color:var(--mut)}
  .feed{max-height:340px;overflow:auto}
  .alert{display:flex;gap:10px;padding:10px 14px;border-bottom:1px solid var(--line2);align-items:flex-start}
  .dot{width:8px;height:8px;border-radius:50%;margin-top:6px;flex:0 0 auto}
  .sev-CRITICAL{background:var(--red)} .sev-HIGH{background:var(--org)}
  .sev-MEDIUM{background:var(--amb)} .sev-LOW{background:var(--steel)} .sev-INFO{background:#9a9a9a}
  .alert .m{font-size:11px;color:var(--mut)}
  .scn{display:flex;flex-wrap:wrap;gap:8px;padding:14px}
  .scn button{cursor:pointer;border:1px solid var(--ink);background:#fff;color:var(--ink);
    padding:9px 14px;font-weight:600;font-size:12px;letter-spacing:.3px;transition:.15s}
  .scn button:hover{background:var(--navy);border-color:var(--navy);color:#fff}
  .jit{padding:12px 14px;border-bottom:1px solid var(--line2)}
  .jit .h{display:flex;justify-content:space-between;gap:8px}
  .jit .btns{display:flex;gap:8px;margin-top:9px}
  .jit button{cursor:pointer;padding:7px 14px;font-weight:600;font-size:12px;border:1px solid;transition:.15s}
  .approve{color:#fff;background:var(--navy);border-color:var(--navy)}
  .approve:hover{background:#16304f}
  .deny{background:#fff;border-color:var(--red);color:var(--red)}
  .deny:hover{background:var(--red);color:#fff}
  .chips{display:flex;flex-wrap:wrap;gap:7px;padding:14px}
  .chip{font-size:11px;padding:4px 10px;background:#f4f3ef;
    border:1px solid var(--line);color:#4a4a4a}
  .mut{color:var(--mut)} .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
  .drawer{position:fixed;top:0;right:0;height:100%;width:400px;background:var(--panel2);
    border-left:1px solid var(--line);transform:translateX(100%);transition:.25s;z-index:20;
    overflow:auto;box-shadow:-16px 0 40px rgba(20,20,20,.14)}
  .drawer.open{transform:translateX(0)}
  .drawer .dh{padding:16px 18px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;background:#fbfaf8}
  .drawer .dh b{font-family:var(--serif);font-size:16px;font-weight:600}
  .drawer .db{padding:18px}
  .drawer h3{font-family:var(--serif);font-weight:600;font-size:15px}
  .drawer .x{cursor:pointer;color:var(--mut);font-size:20px;border:none;background:none}
  .kv{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--line2);font-size:13px}
  .drivers li{margin:4px 0}
  .foot{grid-column:1/-1;color:var(--mut);font-size:11px;text-align:center;padding:12px}
  @media(max-width:1050px){.wrap{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(3,1fr)}}
</style>
</head>
<body>
<div class="top">
  <div class="brand">
    <div class="logo">Æ</div>
    <div><h1>AEGIS</h1><span>Insider Threat &amp; Privileged Access Defense · SOC Console</span></div>
  </div>
  <div class="badges" id="badges"></div>
</div>

<div class="wrap">
  <div class="kpis" id="kpis"></div>

  <div class="card" style="grid-row:span 2">
    <h2>User Risk Leaderboard <span class="mut" id="lbcount"></span></h2>
    <div class="body"><table>
      <thead><tr><th>User</th><th>Role</th><th>Risk</th><th>Tier</th>
      <th>B / R / C</th><th>Alerts</th></tr></thead>
      <tbody id="lb"></tbody>
    </table>
    <div class="pager">
      <span class="mut" id="lbinfo"></span>
      <div class="pbtns">
        <button id="lbprev" onclick="lbNav(-1)">Previous</button>
        <button id="lbnext" onclick="lbNav(1)">Next</button>
      </div>
    </div></div>
  </div>

  <div class="card">
    <h2>Inject Insider-Threat Scenario <span class="mut">(live demo)</span></h2>
    <div class="scn" id="scn"></div>
  </div>

  <div class="card">
    <h2>JIT Elevation — Maker/Checker Queue</h2>
    <div id="jit"><div class="jit mut">No pending requests.</div></div>
  </div>

  <div class="card">
    <h2>Live Alert Feed</h2>
    <div class="feed" id="alerts"></div>
  </div>

  <div class="card">
    <h2>MITRE ATT&CK Coverage</h2>
    <div class="chips" id="mitre"></div>
  </div>

  <div class="card">
    <h2>Quantum-Safe Posture &amp; Vault</h2>
    <div class="body" id="pqc" style="padding:14px"></div>
  </div>

  <div class="foot" id="foot"></div>
</div>

<div class="drawer" id="drawer">
  <div class="dh"><b id="dname">User</b><button class="x" onclick="closeDrawer()">✕</button></div>
  <div class="db" id="dbody"></div>
</div>

<script>
const $=id=>document.getElementById(id);
const api=(p,o)=>fetch(p,o).then(r=>r.json());
function pct(v){return Math.max(0,Math.min(100,v));}
function riskColor(v){return v>=80?'#9e1b32':v>=60?'#b04a17':v>=40?'#a07618':'#256d46';}

let lbData=[],lbPage=0;const LB_PS=10;
function renderLb(){
  const total=lbData.length,pages=Math.max(1,Math.ceil(total/LB_PS));
  lbPage=Math.max(0,Math.min(lbPage,pages-1));
  const start=lbPage*LB_PS;
  $('lb').innerHTML=lbData.slice(start,start+LB_PS).map(u=>{
    const c=u.components;
    return `<tr class="row" onclick="openUser('${u.user_id}')">
      <td><div class="who"><b>${u.name}</b><small class="mono">${u.user_id}</small></div></td>
      <td class="mut">${u.role}</td>
      <td><div style="display:flex;align-items:center;gap:8px">
        <div class="bar"><i style="width:${pct(u.risk_score)}%;background:${riskColor(u.risk_score)}"></i></div>
        <b>${u.risk_score}</b></div></td>
      <td><span class="tier ${u.tier}">${u.tier}</span></td>
      <td class="mono mut">${c.behavior}/${c.rules}/${c.context}</td>
      <td>${u.open_alerts?`<b style="color:var(--org)">${u.open_alerts}</b>`:'<span class="mut">0</span>'}</td>
    </tr>`;}).join('');
  $('lbinfo').textContent=total?`Showing ${start+1}–${Math.min(start+LB_PS,total)} of ${total}`:'No users';
  $('lbprev').disabled=lbPage===0;
  $('lbnext').disabled=lbPage>=pages-1;
}
function lbNav(d){lbPage+=d;renderLb();}

async function refresh(){
  const s=await api('/api/snapshot');
  // badges
  const qs=s.pqc.quantum_safe;
  const au=await api('/api/audit?limit=1');
  $('badges').innerHTML=
    `<span class="badge ${qs?'qs':'cl'}">${s.pqc.kem_algorithm} · ${qs?'QUANTUM-SAFE':'CLASSICAL FALLBACK'}</span>`+
    `<span class="badge ${au.integrity_valid?'ok':'bad'}">Audit ${au.integrity_valid?'INTACT':'TAMPERED'} · ${au.length} blocks</span>`+
    `<span class="badge">${s.pqc.signature_algorithm}</span>`;
  // kpis
  const crit=s.leaderboard.filter(u=>u.tier==='CRITICAL'||u.tier==='HIGH').length;
  $('kpis').innerHTML=[
    ['Monitored Users',s.monitored_users],['Events Ingested',s.events_ingested.toLocaleString()],
    ['High/Critical Users',crit],['Open Alerts',s.open_alerts],
    ['Pending JIT',s.pending_jit],['Audit Blocks',s.audit_blocks]
  ].map(([l,n])=>`<div class="kpi"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');
  // leaderboard
  $('lbcount').textContent=`(${s.leaderboard.length})`;
  lbData=s.leaderboard;renderLb();
  // mitre
  $('mitre').innerHTML=s.mitre_coverage.map(m=>
    `<span class="chip" title="${m.tactic}">${m.technique} · ${m.name}</span>`).join('');
  // pqc + vault
  const vault=await api('/api/vault');
  $('pqc').innerHTML=
    `<div class="kv"><span class="mut">Backend</span><span class="mono">${s.pqc.backend}</span></div>`+
    `<div class="kv"><span class="mut">KEM</span><span class="mono">${s.pqc.kem_algorithm}</span></div>`+
    `<div class="kv"><span class="mut">Signature</span><span class="mono">${s.pqc.signature_algorithm}</span></div>`+
    `<div class="kv"><span class="mut">Hybrid mode</span><span>${s.pqc.hybrid_mode?'Enabled':'—'}</span></div>`+
    `<div class="kv"><span class="mut">Sealed credentials</span><span>${vault.sealed_secrets} (AES-256-GCM, PQC-wrapped)</span></div>`+
    `<div class="mut" style="margin-top:8px;font-size:12px">${s.pqc.posture}</div>`;
}

async function refreshAlerts(){
  const a=await api('/api/alerts?limit=25');
  $('alerts').innerHTML=a.length?a.map(x=>
    `<div class="alert"><div class="dot sev-${x.severity}"></div>
      <div><div><b>${x.title}</b></div>
      <div class="m">${x.user_id} · ${x.severity} · ${x.mitre_technique||''}</div></div></div>`
  ).join(''):'<div class="alert mut">No alerts yet — inject a scenario.</div>';
}

async function refreshJit(){
  const j=await api('/api/jit');
  $('jit').innerHTML=j.pending.length?j.pending.map(r=>
    `<div class="jit"><div class="h"><b>${r.user_id}</b>
       <span class="tier HIGH">risk ${r.risk_at_request}</span></div>
     <div class="mut">${r.role_requested} → ${r.resource} · "${r.justification}"</div>
     <div class="btns">
       <button class="approve" onclick="jitAct('${r.request_id}','approve')">Approve (checker)</button>
       <button class="deny" onclick="jitAct('${r.request_id}','deny')">Deny</button>
     </div></div>`).join(''):'<div class="jit mut">No pending requests.</div>';
}

async function jitAct(id,act){
  await api(`/api/jit/${id}/${act}`,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({approver:'soc-analyst',reason:'reviewed'})});
  refreshJit();
}

async function loadScenarios(){
  const list=await api('/api/scenarios');
  $('scn').innerHTML=list.map(n=>
    `<button onclick="inject('${n}')">${n.replace(/_/g,' ')}</button>`).join('');
}
async function inject(name){
  const r=await api(`/api/scenario/${name}`,{method:'POST'});
  await Promise.all([refresh(),refreshAlerts(),refreshJit()]);
  $('foot').textContent=`Injected ${name} on ${r.target_name} (${r.role}) → risk ${r.new_risk} [${r.tier}]`;
}

async function openUser(id){
  const d=await api('/api/users/'+id);
  $('dname').textContent=d.user.name+' · '+d.user.role;
  const b=d.behavior.components;
  $('dbody').innerHTML=
    `<div class="kv"><span class="mut">User ID</span><span class="mono">${d.user.user_id}</span></div>`+
    `<div class="kv"><span class="mut">Risk score</span><b>${d.risk?d.risk.risk_score:'-'} (${d.risk?d.risk.tier:'-'})</b></div>`+
    `<div class="kv"><span class="mut">Privilege level</span><span>${d.user.privilege_level}/5</span></div>`+
    `<div class="kv"><span class="mut">MFA</span><span>${d.user.mfa_enrolled?'enrolled':'none'}</span></div>`+
    `<div class="kv"><span class="mut">Employment</span><span>${d.user.employment_status}</span></div>`+
    `<h3 style="margin:14px 0 6px">Behavioral components</h3>`+
    `<div class="kv"><span class="mut">Autoencoder</span><span>${b.autoencoder}</span></div>`+
    `<div class="kv"><span class="mut">Isolation Forest</span><span>${b.isolation_forest}</span></div>`+
    `<div class="kv"><span class="mut">Self deviation</span><span>${b.self_deviation}</span></div>`+
    `<div class="kv"><span class="mut">Peer deviation</span><span>${b.peer_deviation}</span></div>`+
    `<h3 style="margin:14px 0 6px">Why flagged</h3>`+
    `<ul class="drivers">${(d.behavior.drivers||[]).map(x=>`<li>${x}</li>`).join('')||'<li class="mut">nominal</li>'}</ul>`+
    `<h3 style="margin:14px 0 6px">Recent alerts</h3>`+
    (d.recent_alerts.length?d.recent_alerts.map(a=>
      `<div class="alert"><div class="dot sev-${a.severity}"></div><div><b>${a.title}</b>
       <div class="m">${a.mitre_technique}</div></div></div>`).join(''):'<div class="mut">none</div>');
  $('drawer').classList.add('open');
}
function closeDrawer(){$('drawer').classList.remove('open');}

loadScenarios();refresh();refreshAlerts();refreshJit();
setInterval(()=>{refresh();refreshAlerts();refreshJit();},4000);
</script>
</body></html>
"""

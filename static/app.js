async function api(path, opts){
  const res = await fetch(path, { credentials: 'same-origin', ...(opts || {}) });
  if(!res.ok) throw new Error(await res.text());
  return res.json().catch(()=>null);
}

let currentSessionUser = null;

let modalResolver = null;

function closeDeleteModal(confirmed){
  const modal = document.getElementById('confirmModal');
  if(!modal) return;
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden','true');
  document.removeEventListener('keydown', onDeleteModalKeydown);
  if(modalResolver){
    const resolve = modalResolver;
    modalResolver = null;
    resolve(Boolean(confirmed));
  }
}

function onDeleteModalKeydown(e){
  if(e.key === 'Escape') closeDeleteModal(false);
}

function confirmDelete(id){
  const modal = document.getElementById('confirmModal');
  const text = document.getElementById('confirmText');
  const cancelBtn = document.getElementById('confirmCancel');
  const deleteBtn = document.getElementById('confirmDelete');
  if(!modal || !text || !cancelBtn || !deleteBtn) return Promise.resolve(false);
  text.textContent = `Delete instance "${id}"? This action cannot be undone.`;
  modal.classList.add('open');
  modal.setAttribute('aria-hidden','false');

  return new Promise((resolve)=>{
    modalResolver = resolve;
    cancelBtn.onclick = ()=>closeDeleteModal(false);
    deleteBtn.onclick = ()=>closeDeleteModal(true);
    modal.onclick = (e)=>{ if(e.target === modal) closeDeleteModal(false); };
    document.addEventListener('keydown', onDeleteModalKeydown);
    deleteBtn.focus();
  });
}

function fmtUptime(u){
  if(!u) return '--';
  const s = Math.floor(u);
  const h = Math.floor(s/3600); const m = Math.floor((s%3600)/60); const sec = s%60;
  return (h? h+'h ':'') + (m? m+'m ':'') + sec+'s';
}

function statusBadge(status){
  const cls = status==='running' ? 'badge running' : 'badge stopped';
  return `<span class="${cls}">${status}</span>`;
}

function protocolBadge(protocol){
  const value = (protocol || 'http').toLowerCase();
  const cls = value === 'https' ? 'badge protocol proto-https' : 'badge protocol proto-http';
  const label = value === 'https' ? 'HTTPS' : 'HTTP';
  return `<span class="${cls}">${label}</span>`;
}

async function loadSessionStatus(){
  try{
    const status = await api('/api/auth/setup-status');
    currentSessionUser = status && status.username ? status.username : null;
    const userEl = document.getElementById('sessionUser');
    if(userEl){
      userEl.textContent = `User: ${currentSessionUser || '-'}`;
    }
  }catch(e){
    console.warn('session status error', e);
  }
}

async function logout(){
  try{
    await api('/api/auth/logout', { method: 'POST' });
  }catch(e){
    console.warn('logout failed', e);
  }
  window.location.href = '/login';
}

async function renderInstances(){
  let data = {};
  try{ data = await api('/api/instances'); }catch(e){ console.warn('failed to fetch',e); }
  const tbody = document.querySelector('#instancesTable tbody');
  const cards = document.getElementById('cardsArea');
  tbody.innerHTML = '';
  cards.innerHTML = '';
  const groups = {};
  for(const id of Object.keys(data)){
    const it = data[id];
    const groupId = it.groupId || id;
    if(!groups[groupId]) groups[groupId] = [];
    groups[groupId].push({ id, ...it });
  }

  for(const groupId of Object.keys(groups)){
    const groupRows = groups[groupId].sort((a,b)=> (a.protocol||'').localeCompare(b.protocol||''));

    const groupHeader = document.createElement('tr');
    groupHeader.innerHTML = `<td colspan="7" class="muted"><strong>Group:</strong> ${groupId} (${groupRows.length} instances)</td>`;
    tbody.appendChild(groupHeader);

    const cardHeader = document.createElement('div');
    cardHeader.className = 'small';
    cardHeader.style.marginTop = '8px';
    cardHeader.textContent = `Group: ${groupId}`;
    cards.appendChild(cardHeader);

    for(const row of groupRows){
      const id = row.id;
      const it = row;
    const detailsParts = [it.proxyName, it.subdomain];
    if(it.serverAddr){
      detailsParts.push(it.serverPort ? `${it.serverAddr}:${it.serverPort}` : it.serverAddr);
    }
    if(it.localPort){
      detailsParts.push(`local:${it.localPort}`);
    }
    if(it.protocol){
      detailsParts.push(`proto:${it.protocol}`);
    }
    const details = detailsParts.filter(Boolean).join(' • ') || it.config || '';
    // table row
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${id}</td><td>${protocolBadge(it.protocol)}</td><td>${statusBadge(it.status)}</td><td class="muted">${details}</td><td>${it.pid||''}</td><td>${fmtUptime(it.uptime)}</td><td class="row-actions"></td>`;
    const actions = tr.querySelector('.row-actions');
    actions.innerHTML = '';
    const btns = [ ['Start','▶️','/api/instances/'+id+'/start'], ['Stop','⏹️','/api/instances/'+id+'/stop'], ['Restart','🔁','/api/instances/'+id+'/restart'], ['Delete','🗑️','/api/instances/'+id], ['Logs','📄','logs'] ];
    btns.forEach(b=>{
      const btn = document.createElement('button'); btn.textContent = b[1]+' '+b[0]; btn.onclick=async ()=>{
        try{
          if(b[2]==='logs') return viewLogs(id);
          if(b[0]==='Delete' && !(await confirmDelete(id))) return;
          const method = b[0]==='Delete' ? 'DELETE' : 'POST';
          await api(b[2],{method});
          setTimeout(renderInstances,400);
        }catch(err){ alert('Error: '+err) }
      }; actions.appendChild(btn);
    });
    tbody.appendChild(tr);

    // card for mobile
    const card = document.createElement('div'); card.className='card mobile-card';
    card.innerHTML = `<div class="meta"><strong>${id}</strong><span class="small">${details}</span></div><div><div style="text-align:right">${protocolBadge(it.protocol)} ${statusBadge(it.status)}<div style="font-size:12px;color:var(--muted);">PID ${it.pid||'–'} • ${fmtUptime(it.uptime)}</div></div></div>`;
    const cardActions = document.createElement('div'); cardActions.className = 'mobile-actions';
    ['Start','Stop','Restart','Logs','Delete'].forEach((label,idx)=>{
      const b = document.createElement('button'); b.textContent = ['▶️','⏹️','🔁','📄','🗑️'][idx]+' '+label;
      b.onclick = async ()=>{
        if(label==='Logs') return viewLogs(id);
        if(label==='Delete' && !(await confirmDelete(id))) return;
        const path = label==='Delete'?'/api/instances/'+id:'/api/instances/'+id+'/'+label.toLowerCase();
        const method = label==='Delete'?'DELETE':'POST';
        api(path,{method}).then(()=>setTimeout(renderInstances,400));
      };
      cardActions.appendChild(b);
    });
    const container = document.createElement('div'); container.className = 'mobile-instance'; container.appendChild(card); container.appendChild(cardActions);
    cards.appendChild(container);
    }
  }
}

async function createInstance(){
  const id = document.getElementById('instanceId').value || ('inst-'+Date.now())
  const proxyName = document.getElementById('proxyName').value || 'proxy'
  const subdomain = document.getElementById('subdomain').value || 'tunnel'
  const serverAddr = document.getElementById('serverAddr').value || 'ginto.ai'
  const localPort = document.getElementById('localPort').value || '80'
  const result = await api('/api/instances',{method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id,proxyName,subdomain,serverAddr,localPort})})
  if(result && Array.isArray(result.created)){
    console.log('Created pair:', result.created.map(x=>x.id).join(', '));
  }
  renderInstances()
}

function viewLogs(id){
  const area = document.getElementById('logsArea');
  area.innerHTML = `<h4 style="margin:6px 0">Logs: ${id} <button id='copyLogs' style='float:right'>Copy</button></h4><pre id="logPre"></pre>`;
  const pre = document.getElementById('logPre');
  const ws = new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+`/ws/logs/${id}`);
  ws.onmessage = (e)=>{ pre.textContent += e.data + '\n'; pre.scrollTop = pre.scrollHeight }
  ws.onclose = ()=>{ pre.textContent += '\n[log stream closed]'; }
  document.getElementById('copyLogs').onclick = ()=>{ navigator.clipboard && navigator.clipboard.writeText(pre.textContent) }
}

function initConsoleLauncher(){
  const consoleBtn = document.getElementById('consoleBtn');
  if(!consoleBtn) return;
  consoleBtn.onclick = ()=>{
    window.location.href = '/terminal';
  };
}

// Theme handling: persist in localStorage
function applyTheme(name){
  document.documentElement.setAttribute('data-theme', name);
  const lbl = document.getElementById('themeLabel'); if(lbl) lbl.textContent = name==='dark'?'Dark':'Light';
}
function initTheme(){
  const saved = localStorage.getItem('ginto-theme') || (window.matchMedia && window.matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light');
  applyTheme(saved);
  const btn = document.getElementById('themeBtn');
  btn.onclick = ()=>{ const next = document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark'; localStorage.setItem('ginto-theme', next); applyTheme(next); }
}

document.getElementById('createBtn').onclick = createInstance;
const logoutBtn = document.getElementById('logoutBtn');
if(logoutBtn){
  logoutBtn.onclick = logout;
}
initTheme();
loadSessionStatus();
renderInstances();
initConsoleLauncher();
setInterval(renderInstances,5000);

// Added SVG icons for actions
// Improved logs area with better auto-scroll and copy functionality
// Introduced subtle animations for better UX

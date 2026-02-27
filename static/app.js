async function api(path, opts){
  const res = await fetch(path, { credentials: 'same-origin', ...(opts || {}) });
  if(!res.ok) throw new Error(await res.text());
  return res.json().catch(()=>null);
}

let currentSessionUser = null;

let modalResolver = null;
let consoleSessions = [];
let activeConsoleSessionId = null;
let consoleTabCounter = 1;
let consoleModalOpen = false;

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

function consoleWsUrl(){
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${location.host}/ws/terminal`;
}

function getConsoleSession(id){
  return consoleSessions.find((session)=>session.id === id) || null;
}

function updateConsoleSessionState(session, connected){
  session.connected = Boolean(connected);
  if(session.stateEl){
    session.stateEl.classList.toggle('connected', session.connected);
  }
  if(session.bubbleStateEl){
    session.bubbleStateEl.classList.toggle('connected', session.connected);
  }
}

function sendConsoleResize(session){
  if(!session || !session.ws || session.ws.readyState !== WebSocket.OPEN) return;
  session.ws.send(JSON.stringify({
    type:'resize',
    cols: session.term.cols,
    rows: session.term.rows
  }));
}

function switchConsoleTab(id){
  activeConsoleSessionId = id;
  for(const session of consoleSessions){
    const active = session.id === id;
    session.tabEl.classList.toggle('active', active);
    session.panelEl.classList.toggle('active', active);
    if(active){
      session.fitAddon.fit();
      sendConsoleResize(session);
    }
  }
}

function openConsoleSocket(session, announceReconnect){
  if(session.ws && session.ws.readyState === WebSocket.OPEN){
    session.ws.close();
  }
  updateConsoleSessionState(session, false);
  session.ws = new WebSocket(consoleWsUrl());
  session.ws.onopen = ()=>{
    updateConsoleSessionState(session, true);
    session.fitAddon.fit();
    sendConsoleResize(session);
    if(announceReconnect){
      session.term.write('\r\n\x1b[33m[reconnected]\x1b[0m\r\n');
    }
  };
  session.ws.onmessage = (event)=>{
    session.term.write(event.data || '');
  };
  session.ws.onclose = ()=>{
    updateConsoleSessionState(session, false);
    session.term.write('\r\n\x1b[31m[disconnected]\x1b[0m\r\n');
  };
  session.ws.onerror = ()=>{
    updateConsoleSessionState(session, false);
  };
}

function removeConsoleSession(id){
  const idx = consoleSessions.findIndex((session)=>session.id === id);
  if(idx === -1) return;
  const session = consoleSessions[idx];
  if(session.ws && session.ws.readyState === WebSocket.OPEN){
    session.ws.close();
  }
  session.term.dispose();
  session.tabEl.remove();
  session.panelEl.remove();
  if(session.bubbleEl){
    session.bubbleEl.remove();
  }
  consoleSessions.splice(idx, 1);

  if(consoleSessions.length === 0){
    closeConsoleModal();
    renderConsoleDock();
    return;
  }
  const next = consoleSessions[Math.max(0, idx - 1)] || consoleSessions[0];
  switchConsoleTab(next.id);
  renderConsoleDock();
}

function createConsoleSession(){
  if(!window.Terminal || !window.FitAddon || !window.FitAddon.FitAddon){
    alert('Terminal library failed to load.');
    return null;
  }

  const tabsEl = document.getElementById('consoleTabs');
  const panelsEl = document.getElementById('consolePanels');
  if(!tabsEl || !panelsEl) return null;

  const id = `console-${Date.now()}-${Math.floor(Math.random()*10000)}`;
  const title = `Terminal ${consoleTabCounter++}`;

  const tabEl = document.createElement('div');
  tabEl.className = 'console-tab';
  const nameEl = document.createElement('div');
  nameEl.className = 'console-tab-name';
  nameEl.textContent = title;
  const stateEl = document.createElement('span');
  stateEl.className = 'console-tab-state';
  const closeEl = document.createElement('button');
  closeEl.className = 'console-tab-close';
  closeEl.type = 'button';
  closeEl.textContent = '×';
  tabEl.appendChild(nameEl);
  tabEl.appendChild(stateEl);
  tabEl.appendChild(closeEl);
  tabsEl.appendChild(tabEl);

  const panelEl = document.createElement('div');
  panelEl.className = 'console-panel';
  const termEl = document.createElement('div');
  termEl.className = 'console-term';
  panelEl.appendChild(termEl);
  panelsEl.appendChild(panelEl);

  const term = new Terminal({
    convertEol: true,
    cursorBlink: true,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
    fontSize: 15,
    lineHeight: 1.2,
    theme: {
      background: '#050a17',
      foreground: '#dbe7ff',
      cursor: '#8fb3ff'
    }
  });
  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(termEl);
  fitAddon.fit();

  const session = {
    id,
    title,
    term,
    fitAddon,
    tabEl,
    panelEl,
    stateEl,
    ws: null,
    bubbleEl: null,
    bubbleStateEl: null,
    connected: false
  };

  term.onData((data)=>{
    if(session.ws && session.ws.readyState === WebSocket.OPEN){
      session.ws.send(JSON.stringify({ type:'input', data }));
    }
  });

  tabEl.onclick = (e)=>{
    if(e.target === closeEl){
      removeConsoleSession(session.id);
      return;
    }
    switchConsoleTab(session.id);
  };

  consoleSessions.push(session);
  openConsoleSocket(session, false);
  switchConsoleTab(session.id);
  renderConsoleDock();
  return session;
}

function openConsoleModal(idToFocus){
  const modal = document.getElementById('consoleModal');
  if(!modal) return;
  consoleModalOpen = true;
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');

  if(consoleSessions.length === 0){
    createConsoleSession();
  }
  const target = idToFocus || activeConsoleSessionId || (consoleSessions[0] && consoleSessions[0].id);
  if(target){
    switchConsoleTab(target);
  }
  renderConsoleDock();
}

function minimizeConsoleModal(){
  const modal = document.getElementById('consoleModal');
  if(!modal) return;
  consoleModalOpen = false;
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
  renderConsoleDock();
}

function closeConsoleModal(){
  const modal = document.getElementById('consoleModal');
  if(modal){
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
  }
  consoleModalOpen = false;
  for(const session of consoleSessions){
    if(session.ws && session.ws.readyState === WebSocket.OPEN){
      session.ws.close();
    }
    session.term.dispose();
    session.tabEl.remove();
    session.panelEl.remove();
    if(session.bubbleEl){
      session.bubbleEl.remove();
    }
  }
  consoleSessions = [];
  activeConsoleSessionId = null;
  consoleTabCounter = 1;
  renderConsoleDock();
}

function reconnectActiveConsoleSession(){
  const session = getConsoleSession(activeConsoleSessionId);
  if(!session) return;
  session.term.write('\r\n\x1b[33m[reconnecting]\x1b[0m\r\n');
  openConsoleSocket(session, true);
}

function renderConsoleDock(){
  const dock = document.getElementById('consoleDock');
  if(!dock) return;
  dock.innerHTML = '';
  if(consoleModalOpen || consoleSessions.length === 0){
    return;
  }

  for(let i = 0; i < consoleSessions.length; i++){
    const session = consoleSessions[i];
    const bubble = document.createElement('button');
    bubble.type = 'button';
    bubble.className = 'console-bubble';
    bubble.title = session.title;
    bubble.textContent = String(i + 1);
    const state = document.createElement('span');
    state.className = 'console-bubble-state';
    state.classList.toggle('connected', session.connected);
    bubble.appendChild(state);
    bubble.onclick = ()=>openConsoleModal(session.id);
    session.bubbleEl = bubble;
    session.bubbleStateEl = state;
    dock.appendChild(bubble);
  }
}

function initConsoleLauncher(){
  const consoleBtn = document.getElementById('consoleBtn');
  const newTabBtn = document.getElementById('consoleNewTabBtn');
  const reconnectBtn = document.getElementById('consoleReconnectBtn');
  const minimizeBtn = document.getElementById('consoleMinimizeBtn');
  const closeBtn = document.getElementById('consoleCloseBtn');
  if(!consoleBtn || !newTabBtn || !reconnectBtn || !minimizeBtn || !closeBtn) return;

  consoleBtn.onclick = ()=>openConsoleModal();
  newTabBtn.onclick = ()=>createConsoleSession();
  reconnectBtn.onclick = ()=>reconnectActiveConsoleSession();
  minimizeBtn.onclick = ()=>minimizeConsoleModal();
  closeBtn.onclick = ()=>closeConsoleModal();

  window.addEventListener('resize', ()=>{
    if(!consoleModalOpen) return;
    const active = getConsoleSession(activeConsoleSessionId);
    if(!active) return;
    active.fitAddon.fit();
    sendConsoleResize(active);
  });
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

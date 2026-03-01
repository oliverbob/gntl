<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import {
    cleanupDeletedInstances,
    createInstance,
    deleteInstance,
    getInstanceLogs,
    getInstances,
    runInstanceAction,
    type InstanceRecord
  } from '$lib/api';

  type Row = { id: string } & InstanceRecord;

  let rows: Row[] = [];
  let loading = false;
  let busy = false;
  let error = '';
  let selectedLogsId = '';
  let logsText = 'Select an instance then click Logs.';
  let refreshTimer: ReturnType<typeof setInterval> | null = null;

  let instanceId = '';
  let proxyName = 'proxy';
  let subdomain = 'tunnel';
  let localPort = '11434';
  let menuOpen = false;
  let isDark = true;
  const backendBaseUrl = (import.meta.env.VITE_GNTL_API_BASE || 'https://127.0.0.1:2026').toString().replace(/\/$/, '');

  function applyTheme(nextDark: boolean): void {
    isDark = nextDark;
    document.documentElement.dataset.theme = nextDark ? 'dark' : 'light';
    try {
      localStorage.setItem('gntl-frontend-theme', nextDark ? 'dark' : 'light');
    } catch {
    }
  }

  function toggleTheme(): void {
    applyTheme(!isDark);
  }

  function toggleMenu(): void {
    menuOpen = !menuOpen;
  }

  function openConsole(): void {
    window.open(`${backendBaseUrl}/terminal`, '_blank', 'noopener,noreferrer');
    menuOpen = false;
  }

  function onWindowClick(event: MouseEvent): void {
    const target = event.target as HTMLElement | null;
    if (!target) return;
    if (target.closest('[data-profile-menu]')) return;
    menuOpen = false;
  }

  function fmtUptime(value?: number): string {
    if (!value || value <= 0) return '--';
    const seconds = Math.floor(value);
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h > 0 ? `${h}h ` : ''}${m > 0 ? `${m}m ` : ''}${s}s`;
  }

  async function loadInstances(): Promise<void> {
    loading = true;
    try {
      const data = await getInstances();
      rows = Object.keys(data)
        .sort()
        .map((id) => ({ id, ...data[id] }));
      error = '';
    } catch (err) {
      error = String(err);
    } finally {
      loading = false;
    }
  }

  async function onCreate(): Promise<void> {
    busy = true;
    try {
      const id = instanceId.trim() || `inst-${Date.now()}`;
      const parsedPort = Number.parseInt(localPort.trim(), 10);
      await createInstance({
        id,
        proxyName: proxyName.trim() || 'proxy',
        subdomain: subdomain.trim() || 'tunnel',
        serverAddr: 'ginto.ai',
        localPort: Number.isFinite(parsedPort) ? parsedPort : undefined
      });
      instanceId = '';
      await loadInstances();
    } catch (err) {
      error = `Create failed: ${String(err)}`;
    } finally {
      busy = false;
    }
  }

  async function onAction(id: string, action: 'start' | 'stop' | 'restart' | 'delete'): Promise<void> {
    busy = true;
    try {
      if (action === 'delete') {
        await deleteInstance(id);
        await cleanupDeletedInstances();
      } else {
        await runInstanceAction(id, action);
      }
      await loadInstances();
    } catch (err) {
      error = `${action} failed: ${String(err)}`;
    } finally {
      busy = false;
    }
  }

  async function onLogs(id: string): Promise<void> {
    selectedLogsId = id;
    try {
      const lines = await getInstanceLogs(id, 220);
      logsText = lines.length > 0 ? lines.join('\n') : '[no logs]';
    } catch (err) {
      logsText = `[failed to load logs] ${String(err)}`;
    }
  }

  onMount(async () => {
    try {
      const saved = localStorage.getItem('gntl-frontend-theme');
      applyTheme(saved ? saved === 'dark' : true);
    } catch {
      applyTheme(true);
    }
    await loadInstances();
    refreshTimer = setInterval(loadInstances, 5000);
    window.addEventListener('click', onWindowClick);
  });

  onDestroy(() => {
    if (refreshTimer) clearInterval(refreshTimer);
    if (typeof window !== 'undefined') {
      window.removeEventListener('click', onWindowClick);
    }
  });
</script>

<main class="wrap">
  <header class="topbar">
    <div class="left">
      <button class="icon-btn" title="Menu" aria-label="Menu">☰</button>
      <div>
        <h1>Ginto Tunnel</h1>
        <p class="subtitle">My Websites</p>
      </div>
    </div>
    <div class="right" data-profile-menu>
      <button class="icon-btn console-btn" title="Console" aria-label="Console" on:click={openConsole}>_&lt;</button>
      <button class="icon-btn" title="Toggle theme" aria-label="Toggle theme" on:click={toggleTheme}>
        {#if isDark}☀️{:else}🌙{/if}
      </button>
      <button class="icon-btn profile" title="Profile" aria-label="Profile" on:click={toggleMenu}>👤</button>
      {#if menuOpen}
        <div class="menu">
          <a href="/codex" class="menu-item">🧱 <span>Codex Builder</span></a>
          <a href="/" class="menu-item">🛠️ <span>Profile / Admin</span></a>
          <a href="/logout" class="menu-item">🚪 <span>Logout</span></a>
        </div>
      {/if}
    </div>
  </header>

  <section class="intro card">
    <p>
      Create unlimited websites locally with Ginto Tunnel.
    </p>
  </section>

  <section class="card form">
    <h2>Create Website Tunnel</h2>
    <div class="grid">
      <label>
        <span>Instance ID</span>
        <input bind:value={instanceId} placeholder="instance id (optional)" />
      </label>
      <label>
        <span>Name</span>
        <input bind:value={proxyName} placeholder="proxy" />
      </label>
      <label>
        <span>Subdomain</span>
        <input bind:value={subdomain} placeholder="tunnel" />
      </label>
      <label>
        <span>App Port to expose</span>
        <input bind:value={localPort} placeholder="11434" />
      </label>
    </div>
    <div class="actions">
      <button on:click={onCreate} disabled={busy}>Create Instance</button>
      <button class="ghost" on:click={loadInstances} disabled={busy}>Refresh</button>
      <button class="ghost" on:click={cleanupDeletedInstances} disabled={busy}>Clean Deleted</button>
    </div>
  </section>

  {#if error}
    <p class="error">{error}</p>
  {/if}

  <section class="card">
    <h2>Instances {loading ? '(loading...)' : ''}</h2>
    <div class="rows">
      {#if rows.length === 0}
        <div class="empty">No instances.</div>
      {/if}
      {#each rows as row}
        <article class="instance">
          <div class="meta">
            <strong>{row.proxyName || 'proxy'}</strong>
            <div class="muted">{row.id}</div>
            <div class="muted">{row.subdomain ? `${row.subdomain}.${row.serverAddr || 'ginto.ai'}` : ''}</div>
            <div class="muted">{row.protocol || 'http'} • PID {row.pid || '–'} • {fmtUptime(row.uptime)}</div>
          </div>
          <div class="row-actions">
            <button on:click={() => onAction(row.id, 'start')} disabled={busy}>Start</button>
            <button on:click={() => onAction(row.id, 'stop')} disabled={busy}>Stop</button>
            <button on:click={() => onAction(row.id, 'restart')} disabled={busy}>Restart</button>
            <button class="ghost" on:click={() => onLogs(row.id)} disabled={busy}>Logs</button>
            <button class="danger" on:click={() => onAction(row.id, 'delete')} disabled={busy}>Delete</button>
          </div>
        </article>
      {/each}
    </div>
  </section>

  <section class="card">
    <h2>Logs {selectedLogsId ? `(${selectedLogsId})` : ''}</h2>
    <pre>{logsText}</pre>
  </section>
</main>

<style>
  .wrap { max-width: 1080px; margin: 0 auto; padding: 16px; }
  .topbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 12px; }
  .left { display: flex; align-items: center; gap: 10px; }
  h1 { margin: 0; font-size: 1.35rem; }
  .subtitle { margin: 2px 0 0 0; color: var(--muted); font-size: 0.95rem; }
  .right { position: relative; display: flex; align-items: center; gap: 8px; }
  .icon-btn {
    width: 40px;
    height: 40px;
    border-radius: 12px;
    border: 1px solid #334155;
    background: var(--surface-2);
    color: var(--text);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    padding: 0;
    font-size: 1rem;
  }
  .console-btn {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
    font-size: 1.05rem;
    font-weight: 700;
    letter-spacing: -0.04em;
  }
  .profile { font-size: 1.05rem; }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 8px);
    width: 220px;
    background: var(--surface);
    border: 1px solid #334155;
    border-radius: 12px;
    box-shadow: 0 12px 24px rgba(2, 6, 23, 0.45);
    padding: 8px;
    display: grid;
    gap: 6px;
    z-index: 8;
  }
  .menu-item {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 8px;
    text-decoration: none;
    color: var(--text);
    background: transparent;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 9px 10px;
    cursor: pointer;
  }
  .intro p { margin: 0; color: var(--muted); line-height: 1.45; }
  .card { background: var(--surface); border: 1px solid #1f2a3f; border-radius: 12px; padding: 14px; margin-bottom: 12px; }
  .form h2, .card h2 { margin: 0 0 10px 0; font-size: 1rem; }
  .grid { display: grid; grid-template-columns: 1fr; gap: 10px; }
  label span { display: block; margin-bottom: 6px; color: var(--muted); font-size: 0.88rem; }
  input { width: 100%; background: var(--surface-2); border: 1px solid #334155; border-radius: 10px; color: var(--text); padding: 10px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  button { background: linear-gradient(135deg, #3b82f6, #7c3aed); border: 0; color: #fff; padding: 10px 12px; border-radius: 10px; cursor: pointer; }
  button.ghost { background: transparent; border: 1px solid #334155; color: var(--text); }
  button.danger { background: linear-gradient(135deg, #ef4444, #b91c1c); }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  .error { color: #fecaca; background: rgba(127, 29, 29, 0.35); border: 1px solid rgba(220, 38, 38, 0.45); border-radius: 10px; padding: 10px; }
  .rows { display: grid; gap: 10px; }
  .instance { display: flex; justify-content: space-between; gap: 10px; background: var(--surface-2); border: 1px solid #1f2a3f; border-radius: 10px; padding: 10px; flex-wrap: wrap; }
  .meta .muted { color: var(--muted); font-size: 0.85rem; margin-top: 4px; }
  .row-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; width: 100%; }
  .empty { color: var(--muted); }
  pre { margin: 0; background: var(--surface-3); border: 1px solid #1f2a3f; border-radius: 10px; padding: 10px; max-height: 360px; overflow: auto; color: #cde8d9; white-space: pre-wrap; }

  :global(:root[data-theme='dark']) {
    --surface: #0b1220;
    --surface-2: #101a2d;
    --surface-3: #050a17;
    --text: #e6eef8;
    --muted: #9fb0c8;
  }
  :global(:root[data-theme='light']) {
    --surface: #ffffff;
    --surface-2: #f8fafc;
    --surface-3: #f1f5f9;
    --text: #0f172a;
    --muted: #64748b;
  }

  @media (max-width: 640px) {
    .menu {
      width: min(260px, calc(100vw - 24px));
      right: 0;
    }
  }

  @media (min-width: 860px) {
    .grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .row-actions { width: auto; grid-template-columns: repeat(5, auto); align-content: start; }
  }
</style>
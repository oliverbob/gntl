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
    await loadInstances();
    refreshTimer = setInterval(loadInstances, 5000);
  });

  onDestroy(() => {
    if (refreshTimer) clearInterval(refreshTimer);
  });
</script>

<main class="wrap">
  <header class="header">
    <div>
      <h1>Ginto Tunnel Dashboard (SvelteKit)</h1>
      <p>Frontend shell for the stable gntl API.</p>
    </div>
    <a class="link" href="/logout">Logout</a>
  </header>

  <section class="card form">
    <h2>Create Instance</h2>
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
  .header { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; margin-bottom: 12px; }
  .header h1 { margin: 0; font-size: 1.35rem; }
  .header p { margin: 6px 0 0 0; color: #98a0b3; }
  .link { color: #cddfff; text-decoration: none; padding: 8px 10px; border: 1px solid #2b3b5a; border-radius: 10px; }
  .card { background: #0b1220; border: 1px solid #1f2a3f; border-radius: 12px; padding: 14px; margin-bottom: 12px; }
  .form h2, .card h2 { margin: 0 0 10px 0; font-size: 1rem; }
  .grid { display: grid; grid-template-columns: 1fr; gap: 10px; }
  label span { display: block; margin-bottom: 6px; color: #9fb0c8; font-size: 0.88rem; }
  input { width: 100%; background: #1e293b; border: 1px solid #334155; border-radius: 10px; color: #e6eef8; padding: 10px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  button { background: linear-gradient(135deg, #3b82f6, #7c3aed); border: 0; color: #fff; padding: 10px 12px; border-radius: 10px; cursor: pointer; }
  button.ghost { background: transparent; border: 1px solid #334155; }
  button.danger { background: linear-gradient(135deg, #ef4444, #b91c1c); }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  .error { color: #fecaca; background: rgba(127, 29, 29, 0.35); border: 1px solid rgba(220, 38, 38, 0.45); border-radius: 10px; padding: 10px; }
  .rows { display: grid; gap: 10px; }
  .instance { display: flex; justify-content: space-between; gap: 10px; background: #101a2d; border: 1px solid #1f2a3f; border-radius: 10px; padding: 10px; flex-wrap: wrap; }
  .meta .muted { color: #95a5be; font-size: 0.85rem; margin-top: 4px; }
  .row-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; width: 100%; }
  .empty { color: #9fb0c8; }
  pre { margin: 0; background: #050a17; border: 1px solid #1f2a3f; border-radius: 10px; padding: 10px; max-height: 360px; overflow: auto; color: #cde8d9; white-space: pre-wrap; }
  @media (min-width: 860px) {
    .grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .row-actions { width: auto; grid-template-columns: repeat(5, auto); align-content: start; }
  }
</style>
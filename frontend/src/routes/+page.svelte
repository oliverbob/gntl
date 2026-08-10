<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import {
    bindTunnelKey,
    cleanupDeletedInstances,
    deleteBoundKey,
    deleteInstance,
    getBoundKeys,
    getInstanceLogs,
    getInstances,
    runInstanceAction,
    type BindKeyResult,
    type BoundKey,
    type InstanceRecord
  } from '$lib/api';

  type Row = { id: string } & InstanceRecord;

  // One website per row, whether it came from the key store, the instance
  // store, or both. Those two used to be shown as separate lists, which made a
  // single tunnel look like two unrelated things.
  type Site = {
    id: string;
    name: string;
    hostname: string;
    subdomain: string;
    localPort?: number;
    status: string;
    pid?: number | null;
    uptime?: number;
    protocol?: string;
    keyMasked?: string;
    expiresAt?: number | null;
    hasKey: boolean;
  };

  let rows: Row[] = [];
  let loading = false;
  let busy = false;
  let error = '';
  let selectedLogsId = '';
  let logsText = 'Select a website then click Logs.';
  let refreshTimer: ReturnType<typeof setInterval> | null = null;

  const defaultBindPort = 2026;
  let bindKey = '';
  let bindPort = '';
  let siteName = '';
  let bindBusy = false;
  let bindError = '';
  let bindResult: BindKeyResult | null = null;
  let boundKeys: BoundKey[] = [];
  let sites: Site[] = [];

  $: sites = mergeSites(rows, boundKeys);
  let menuOpen = false;
  let isDark = true;
  // The console must load from whatever origin is serving this page: localhost,
  // the LAN address, or the public tunnel hostname. A build-time absolute URL
  // pointed every viewer at their own 127.0.0.1, so the console only ever
  // worked when browsing from the machine itself. Dev is covered too - vite
  // proxies /terminal and /ws to the backend.
  const consoleUrl = '/terminal';

  type ConsoleWindow = {
    id: number;
    title: string;
    src: string;
    minimized: boolean;
  };

  type ConsoleLayout = 'window' | 'maximized';

  let consoleWindows: ConsoleWindow[] = [];
  let activeConsoleId: number | null = null;
  let consoleCounter = 1;
  let consoleIdSeq = 0;
  let activeConsole: ConsoleWindow | null = null;
  let consoleLayout: ConsoleLayout = 'window';
  let isConsoleFullscreen = false;
  let consoleModalEl: HTMLDivElement | null = null;

  $: activeConsole = consoleWindows.find((item) => item.id === activeConsoleId) || null;

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

  async function syncConsoleFullscreenState(): Promise<void> {
    isConsoleFullscreen = Boolean(document.fullscreenElement);
  }

  function createConsoleSession(): void {
    // Monotonic: two clicks inside the same millisecond would otherwise collide
    // and break the keyed each block.
    const id = ++consoleIdSeq;
    const title = `Console ${consoleCounter++}`;
    consoleWindows = [
      ...consoleWindows,
      {
        id,
        title,
        src: consoleUrl,
        minimized: false
      }
    ];
    activeConsoleId = id;
  }

  function openConsole(): void {
    createConsoleSession();
    menuOpen = false;
  }

  function addConsoleTab(): void {
    createConsoleSession();
  }

  function maximizeConsole(): void {
    consoleLayout = 'maximized';
  }

  function windowConsole(): void {
    consoleLayout = 'window';
  }

  async function toggleConsoleFullscreen(): Promise<void> {
    try {
      if (document.fullscreenElement) {
        await document.exitFullscreen();
      } else if (consoleModalEl) {
        await consoleModalEl.requestFullscreen();
      }
    } catch {
    }
    await syncConsoleFullscreenState();
  }

  function activateConsole(id: number): void {
    const selected = consoleWindows.find((item) => item.id === id);
    if (!selected) return;
    if (selected.minimized) {
      restoreConsole(id);
      return;
    }
    activeConsoleId = id;
  }

  function minimizeActiveConsole(): void {
    if (activeConsoleId === null) return;
    const targetId = activeConsoleId;
    consoleWindows = consoleWindows.map((item) =>
      item.id === targetId ? { ...item, minimized: true } : item
    );
    const nextActive = consoleWindows.find((item) => !item.minimized && item.id !== targetId);
    activeConsoleId = nextActive?.id ?? null;
  }

  function restoreConsole(id: number): void {
    consoleWindows = consoleWindows.map((item) =>
      item.id === id ? { ...item, minimized: false } : item
    );
    activeConsoleId = id;
  }

  function closeConsole(id: number): void {
    const wasActive = activeConsoleId === id;
    consoleWindows = consoleWindows.filter((item) => item.id !== id);
    if (wasActive) {
      const nextActive = consoleWindows.find((item) => !item.minimized);
      activeConsoleId = nextActive?.id ?? null;
      return;
    }
    if (activeConsoleId !== null) {
      const stillExists = consoleWindows.some((item) => item.id === activeConsoleId);
      if (!stillExists) {
        const nextActive = consoleWindows.find((item) => !item.minimized);
        activeConsoleId = nextActive?.id ?? null;
      }
    }
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

  function fmtExpiry(value?: number | null): string {
    if (!value || value <= 0) return 'never';
    return new Date(value * 1000).toLocaleDateString();
  }

  async function loadBoundKeys(): Promise<void> {
    try {
      boundKeys = await getBoundKeys();
    } catch (err) {
      bindError = `Could not load bound keys: ${String(err)}`;
    }
  }

  function mergeSites(instances: Row[], keys: BoundKey[]): Site[] {
    const claimed = new Set<string>();
    const out: Site[] = instances.map((row) => {
      const sub = String(row.subdomain || '').toLowerCase();
      const key =
        keys.find((k) => k.instanceId === row.id) ||
        keys.find((k) => k.subdomain.toLowerCase() === sub);
      if (key) claimed.add(key.subdomain.toLowerCase());
      return {
        id: row.id,
        name: row.label || key?.name || row.subdomain || row.proxyName || row.id,
        hostname: key?.hostname || (row.subdomain ? `${row.subdomain}.${row.serverAddr || 'ginto.ai'}` : ''),
        subdomain: key?.subdomain || row.subdomain || '',
        localPort: row.localPort ?? key?.localPort,
        status: row.status || 'unknown',
        pid: row.pid,
        uptime: row.uptime,
        protocol: row.protocol,
        keyMasked: key?.keyMasked,
        expiresAt: key?.expiresAt ?? row.keyExpiresAt,
        hasKey: Boolean(key)
      };
    });

    // A key whose instance is gone still owns its subdomain, so it has to stay
    // visible - otherwise the tunnel is unreachable and unremovable.
    for (const key of keys) {
      if (claimed.has(key.subdomain.toLowerCase())) continue;
      out.push({
        id: key.instanceId || '',
        name: key.name || key.subdomain,
        hostname: key.hostname,
        subdomain: key.subdomain,
        localPort: key.localPort,
        status: key.status || 'missing',
        keyMasked: key.keyMasked,
        expiresAt: key.expiresAt,
        hasKey: true
      });
    }

    return out.sort((a, b) => a.name.localeCompare(b.name));
  }

  async function onCreateTunnel(): Promise<void> {
    bindBusy = true;
    bindError = '';
    bindResult = null;
    try {
      const parsedPort = Number.parseInt(bindPort.trim(), 10);
      bindResult = await bindTunnelKey(
        bindKey.trim(),
        Number.isFinite(parsedPort) ? parsedPort : defaultBindPort,
        siteName.trim()
      );
      bindKey = '';
      siteName = '';
      await Promise.all([loadBoundKeys(), loadInstances()]);
    } catch (err) {
      bindError = String(err instanceof Error ? err.message : err);
    } finally {
      bindBusy = false;
    }
  }

  async function onUnbind(target: string): Promise<void> {
    bindBusy = true;
    bindError = '';
    try {
      await deleteBoundKey(target);
      await Promise.all([loadBoundKeys(), loadInstances()]);
    } catch (err) {
      bindError = `Unbind failed: ${String(err)}`;
    } finally {
      bindBusy = false;
    }
  }

  async function refreshAll(): Promise<void> {
    await Promise.all([loadInstances(), loadBoundKeys()]);
  }

  async function onAction(id: string, action: 'start' | 'stop' | 'restart'): Promise<void> {
    if (!id) return;
    busy = true;
    try {
      await runInstanceAction(id, action);
      await refreshAll();
    } catch (err) {
      error = `${action} failed: ${String(err)}`;
    } finally {
      busy = false;
    }
  }

  // Deleting a website has to take its key with it. Dropping only the instance
  // left the key bound to a subdomain with nothing serving it, and the next
  // bind of that key then adopted a half-deleted tunnel.
  async function onDeleteSite(site: Site): Promise<void> {
    if (site.hasKey) {
      await onUnbind(site.subdomain);
      return;
    }
    busy = true;
    try {
      await deleteInstance(site.id);
      await cleanupDeletedInstances();
      await refreshAll();
    } catch (err) {
      error = `delete failed: ${String(err)}`;
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
    await loadBoundKeys();
    refreshTimer = setInterval(loadInstances, 5000);
    window.addEventListener('click', onWindowClick);
    document.addEventListener('fullscreenchange', syncConsoleFullscreenState);
    await syncConsoleFullscreenState();
  });

  onDestroy(() => {
    if (refreshTimer) clearInterval(refreshTimer);
    if (typeof window !== 'undefined') {
      window.removeEventListener('click', onWindowClick);
    }
    document.removeEventListener('fullscreenchange', syncConsoleFullscreenState);
  });
</script>

<main class="wrap">
  <header class="topbar">
    <div class="left">
      <button class="icon-btn" title="Menu" aria-label="Menu">
        <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
        </svg>
      </button>
      <div>
        <h1>Ginto Tunnel</h1>
        <p class="subtitle">My Websites</p>
      </div>
    </div>
    <div class="right" data-profile-menu>
      <button class="icon-btn console-btn" title="Console" aria-label="Console" on:click={openConsole}>
        <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <rect x="3" y="4" width="18" height="16" rx="2" stroke="currentColor" stroke-width="1.8" />
          <path d="M7 10l3 2-3 2M12.5 14H17" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </button>
      <a class="icon-btn" title="Open Codex" aria-label="Open Codex" href="/codex">
        <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M8 8L4 12l4 4M16 8l4 4-4 4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
          <path d="M13 6l-2 12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
        </svg>
      </a>
      <button class="icon-btn" title="Toggle theme" aria-label="Toggle theme" on:click={toggleTheme}>
        {#if isDark}
          <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="1.8" />
            <path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.64 5.64l1.41 1.41M16.95 16.95l1.41 1.41M18.36 5.64l-1.41 1.41M7.05 16.95l-1.41 1.41" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
          </svg>
        {:else}
          <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        {/if}
      </button>
      <button class="icon-btn profile" title="Profile" aria-label="Profile" on:click={toggleMenu}>
        <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle cx="12" cy="8" r="3.5" stroke="currentColor" stroke-width="1.8" />
          <path d="M5 19c1.7-2.9 4.1-4.3 7-4.3s5.3 1.4 7 4.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
        </svg>
      </button>
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
      Create unlimited websites locally with Ginto Tunnel. Don't have a website? Don't worry, build one here. Open <a href="/codex" class="intro-link">Codex</a>
    </p>
  </section>

  <section class="card form">
    <h2>Create Website Tunnel</h2>
    <p class="key-help">
      Generate a key for your website at
      <a href="https://ginto.ai/account/keys" target="_blank" rel="noreferrer">ginto.ai/account/keys</a>
      and paste it here. The key carries its own subdomain, so that is all a tunnel needs - no admin
      approval, and one key per website.
    </p>
    <div class="grid key-grid">
      <label class="key-field">
        <span>Account key (or the copied link)</span>
        <input bind:value={bindKey} placeholder="gtnl-..." autocomplete="off" spellcheck="false" />
      </label>
      <label>
        <span>Name (optional)</span>
        <input bind:value={siteName} placeholder="my site" />
      </label>
      <label>
        <span>App port to expose</span>
        <input bind:value={bindPort} placeholder={String(defaultBindPort)} />
      </label>
    </div>
    <div class="actions">
      <button class="primary-action" on:click={onCreateTunnel} disabled={bindBusy || !bindKey.trim()}>
        {bindBusy ? 'Creating...' : 'Create tunnel'}
      </button>
      <button class="icon-action" title="Refresh" aria-label="Refresh" on:click={refreshAll} disabled={bindBusy}>
        <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M20 11a8 8 0 1 0 2.2 5.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
          <path d="M20 4v7h-7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </button>
    </div>

    {#if bindError}
      <p class="bind-msg bind-error">{bindError}</p>
    {/if}
    {#if bindResult}
      <p class="bind-msg bind-ok">
        <a href={bindResult.url} target="_blank" rel="noreferrer">{bindResult.hostname}</a>
        &rarr; local port {bindResult.localPort}{bindResult.localTlsDetected ? ' (TLS origin)' : ''}.
        {bindResult.started ? 'Tunnel started.' : `Not started: ${bindResult.startError ?? 'unknown error'}`}
        {bindResult.metaVerified ? 'Key verified on the server.' : ''}
      </p>
    {/if}
  </section>

  {#if error}
    <p class="error">{error}</p>
  {/if}

  <section class="card">
    <h2>My Websites {loading ? '(loading...)' : ''}</h2>
    <div class="rows">
      {#if sites.length === 0}
        <div class="empty">No websites yet. Paste an account key above to publish one.</div>
      {/if}
      {#each sites as site (site.subdomain || site.id)}
        <article class="instance">
          <div class="meta">
            <strong>{site.name}</strong>
            <div class="muted">
              {#if site.hostname}
                <a href={`https://${site.hostname}`} target="_blank" rel="noreferrer">{site.hostname}</a>
              {:else}
                {site.id}
              {/if}
              &nbsp;&rarr;&nbsp;port {site.localPort ?? '--'}
            </div>
            <div class="muted">{site.status} • PID {site.pid || '–'} • {fmtUptime(site.uptime)}</div>
            <div class="muted mono">{site.keyMasked ?? 'no key'} • expires {fmtExpiry(site.expiresAt)}</div>
          </div>
          <div class="row-actions">
            <button class="icon-action" title="Start" aria-label="Start" on:click={() => onAction(site.id, 'start')} disabled={busy || !site.id}>
              <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M8 6l10 6-10 6V6z" fill="currentColor" />
              </svg>
            </button>
            <button class="icon-action" title="Stop" aria-label="Stop" on:click={() => onAction(site.id, 'stop')} disabled={busy || !site.id}>
              <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <rect x="7" y="7" width="10" height="10" rx="1.5" fill="currentColor" />
              </svg>
            </button>
            <button class="icon-action" title="Restart" aria-label="Restart" on:click={() => onAction(site.id, 'restart')} disabled={busy || !site.id}>
              <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M20 12a8 8 0 1 1-2.3-5.7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
                <path d="M20 4v6h-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </button>
            <button class="icon-action" title="Logs" aria-label="Logs" on:click={() => onLogs(site.id)} disabled={busy || !site.id}>
              <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M7 4h8l3 3v13H7z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" />
                <path d="M15 4v3h3M9.5 11h6M9.5 15h6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
              </svg>
            </button>
            <button class="icon-action danger-icon" title="Delete" aria-label="Delete" on:click={() => onDeleteSite(site)} disabled={busy || bindBusy}>
              <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M3 7h18M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M8 7l1 12a1 1 0 0 0 1 .9h4a1 1 0 0 0 1-.9L16 7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </button>
          </div>
        </article>
      {/each}
    </div>
    {#if sites.length > 0}
      <p class="key-help site-note">
        These websites are saved on this machine. Run <code>./run.sh install-service</code> once so they
        come back after a reboot.
      </p>
    {/if}
  </section>

  <section class="card">
    <h2>Logs {selectedLogsId ? `(${selectedLogsId})` : ''}</h2>
    <pre>{logsText}</pre>
  </section>

  {#if activeConsole}
    <div class="console-overlay" role="presentation">
      <div
        class="console-modal"
        class:console-modal-window={consoleLayout === 'window'}
        class:console-modal-maximized={consoleLayout === 'maximized'}
        role="dialog"
        aria-modal="true"
        aria-label={activeConsole.title}
        bind:this={consoleModalEl}
      >
        <header class="console-header">
          <div class="console-title">_&lt; {activeConsole.title}</div>
          <div class="console-controls">
            <button class="icon-btn" title="New session" aria-label="Add console session" on:click={addConsoleTab}>
              <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
              </svg>
            </button>
            <button class="icon-btn" title="Minimize" aria-label="Minimize console" on:click={minimizeActiveConsole}>
              <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M5 12h14" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
              </svg>
            </button>
            <button class="icon-btn" title="Maximize" aria-label="Maximize console" on:click={maximizeConsole}>
              <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <rect x="6" y="6" width="12" height="12" rx="1.8" stroke="currentColor" stroke-width="1.8" />
              </svg>
            </button>
            <button class="icon-btn" title="Window mode" aria-label="Set console window mode" on:click={windowConsole}>
              <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <rect x="5" y="7" width="14" height="10" rx="1.8" stroke="currentColor" stroke-width="1.8" />
                <path d="M5 10h14" stroke="currentColor" stroke-width="1.8" />
              </svg>
            </button>
            <button class="icon-btn" title={isConsoleFullscreen ? 'Exit full screen' : 'Full screen'} aria-label={isConsoleFullscreen ? 'Exit full screen' : 'Enter full screen'} on:click={toggleConsoleFullscreen}>
              {#if isConsoleFullscreen}
                <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M9 9H5V5M15 9h4V5M9 15H5v4M15 15h4v4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
                </svg>
              {:else}
                <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M9 5H5v4M15 5h4v4M9 19H5v-4M15 19h4v-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
                </svg>
              {/if}
            </button>
            <button class="icon-btn" title="Close" aria-label="Close console" on:click={() => closeConsole(activeConsole.id)}>
              <svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M7 7l10 10M17 7L7 17" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
              </svg>
            </button>
          </div>
        </header>
        <div class="console-tabs" role="tablist" aria-label="Console sessions">
          {#each consoleWindows as item (item.id)}
            <div class="console-tab" class:is-active={item.id === activeConsoleId} class:is-minimized={item.minimized}>
              <button
                class="console-tab-main"
                title={item.minimized ? `Restore ${item.title}` : `Switch to ${item.title}`}
                aria-label={item.minimized ? `Restore ${item.title}` : `Switch to ${item.title}`}
                on:click={() => activateConsole(item.id)}
              >
                {item.title}
              </button>
              <button class="console-tab-close" title={`Close ${item.title}`} aria-label={`Close ${item.title}`} on:click={() => closeConsole(item.id)}>
                ×
              </button>
            </div>
          {/each}
        </div>
        <!--
          One iframe per session, hidden rather than swapped. A single iframe
          whose src was reassigned never reloaded (every console has the same
          /terminal src, so Svelte saw no change and showed session one
          forever), and reassigning it would have killed the previous shell on
          every tab switch. Hiding keeps each pty alive in the background.
        -->
        {#each consoleWindows as item (item.id)}
          <iframe
            class="console-frame"
            class:is-hidden={item.id !== activeConsoleId}
            src={item.src}
            title={item.title}
          ></iframe>
        {/each}
      </div>
    </div>
  {/if}

  {#if consoleWindows.some((item) => item.minimized)}
    <div class="console-stack">
      {#each consoleWindows.filter((item) => item.minimized) as item (item.id)}
        <div class="console-chip">
          <button class="console-chip-main" title={`Restore ${item.title}`} aria-label={`Restore ${item.title}`} on:click={() => restoreConsole(item.id)}>
            _&lt; {item.title}
          </button>
          <button class="console-chip-close" title={`Close ${item.title}`} aria-label={`Close ${item.title}`} on:click={() => closeConsole(item.id)}>
            ×
          </button>
        </div>
      {/each}
    </div>
  {/if}
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
    border: 0;
    background: transparent;
    color: var(--icon);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    padding: 0;
    font-size: 1rem;
  }
  .icon-btn:hover { color: var(--text); }
  .icon-btn:focus-visible,
  .icon-action:focus-visible {
    outline: 2px solid var(--focus-ring);
    outline-offset: 2px;
  }
  .icon-svg {
    width: 18px;
    height: 18px;
    display: block;
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
    border: 1px solid var(--border);
    border-radius: 12px;
    box-shadow: var(--menu-shadow);
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
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 9px 10px;
    cursor: pointer;
  }
  .intro p { margin: 0; color: var(--muted); line-height: 1.45; }
  .intro-link {
    color: var(--text);
    font-weight: 700;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .intro-link:hover { color: var(--icon); }
  .card { background: var(--surface); border: 1px solid var(--border-strong); border-radius: 12px; padding: 14px; margin-bottom: 12px; }
  .form h2, .card h2 { margin: 0 0 10px 0; font-size: 1rem; }
  .grid { display: grid; grid-template-columns: 1fr; gap: 10px; }
  label span { display: block; margin-bottom: 6px; color: var(--muted); font-size: 0.88rem; }
  input { width: 100%; background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; color: var(--text); padding: 10px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  button { background: linear-gradient(135deg, #3b82f6, #7c3aed); border: 0; color: #fff; padding: 10px 12px; border-radius: 10px; cursor: pointer; }
  .icon-action {
    width: 36px;
    height: 36px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0;
    font-size: 1rem;
    background: transparent;
    border: 0;
    color: var(--icon);
    border-radius: 8px;
  }
  .icon-action:hover { color: var(--text); }
  .danger-icon { color: var(--danger); }
  .primary-action { padding: 10px 16px; font-size: 0.92rem; }
  .key-help { color: var(--muted); font-size: 0.86rem; margin: 0 0 12px 0; }
  .key-help code { background: var(--surface-3); border-radius: 6px; padding: 1px 5px; }
  .key-grid { grid-template-columns: 1fr; }
  .bind-msg { border-radius: 10px; padding: 10px; margin: 12px 0 0 0; font-size: 0.88rem; }
  .bind-error { color: var(--error-text); background: var(--error-bg); border: 1px solid var(--error-border); }
  .bind-ok { color: var(--text); background: var(--surface-2); border: 1px solid var(--border-strong); }
  .site-note { margin: 14px 0 0 0; }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  .error { color: var(--error-text); background: var(--error-bg); border: 1px solid var(--error-border); border-radius: 10px; padding: 10px; }
  .rows { display: grid; gap: 10px; }
  .instance { display: flex; justify-content: space-between; gap: 10px; background: var(--surface-2); border: 1px solid var(--border-strong); border-radius: 10px; padding: 10px; flex-wrap: wrap; }
  .meta .muted { color: var(--muted); font-size: 0.85rem; margin-top: 4px; }
  .meta .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .row-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; width: 100%; }
  .empty { color: var(--muted); }
  pre { margin: 0; background: var(--surface-3); border: 1px solid var(--border-strong); border-radius: 10px; padding: 10px; max-height: 360px; overflow: auto; color: var(--code-text); white-space: pre-wrap; }
  .console-overlay {
    position: fixed;
    inset: 0;
    background: rgba(2, 6, 23, 0.64);
    backdrop-filter: blur(2px);
    z-index: 90;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 12px;
  }
  .console-modal {
    background: var(--surface);
    border: 1px solid var(--border-strong);
    border-radius: 14px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    box-shadow: var(--menu-shadow);
  }
  .console-modal-window {
    width: min(1200px, 100%);
    height: min(86vh, 900px);
  }
  .console-modal-maximized {
    width: calc(100vw - 24px);
    height: calc(100vh - 24px);
    border-radius: 10px;
  }
  .console-header {
    height: 50px;
    border-bottom: 1px solid var(--border);
    background: var(--surface-2);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 10px 0 14px;
  }
  .console-title {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
    font-size: 0.95rem;
    font-weight: 700;
    color: var(--text);
  }
  .console-controls {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .console-frame {
    width: 100%;
    flex: 1;
    border: 0;
    background: #000;
  }
  /* Inactive sessions stay in the DOM so their shell keeps running. */
  .console-frame.is-hidden {
    display: none;
  }
  .console-tabs {
    display: flex;
    align-items: center;
    gap: 6px;
    overflow-x: auto;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    padding: 8px 10px;
  }
  .console-tab {
    min-width: 0;
    display: inline-flex;
    align-items: center;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    background: var(--surface-2);
  }
  .console-tab.is-active {
    border-color: var(--focus-ring);
    box-shadow: 0 0 0 1px color-mix(in oklab, var(--focus-ring) 50%, transparent);
  }
  .console-tab.is-minimized {
    opacity: 0.72;
  }
  .console-tab-main {
    border: 0;
    background: transparent;
    color: var(--text);
    font-size: 0.8rem;
    line-height: 1;
    padding: 7px 10px;
    cursor: pointer;
    max-width: 180px;
    text-overflow: ellipsis;
    overflow: hidden;
    white-space: nowrap;
  }
  .console-tab-main:hover {
    background: var(--surface-3);
  }
  .console-tab-close {
    border: 0;
    border-left: 1px solid var(--border);
    background: transparent;
    color: var(--muted);
    width: 28px;
    height: 28px;
    padding: 0;
    border-radius: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    line-height: 1;
    font-size: 1rem;
    font-weight: 500;
  }
  .console-tab-close:hover {
    color: var(--text);
    background: var(--surface-3);
  }
  .console-stack {
    position: fixed;
    right: 12px;
    bottom: 12px;
    z-index: 95;
    display: flex;
    flex-direction: column-reverse;
    align-items: flex-end;
    gap: 8px;
    max-width: calc(100vw - 24px);
  }
  .console-chip {
    display: inline-flex;
    align-items: center;
    border: 1px solid var(--border-strong);
    background: var(--surface);
    border-radius: 10px;
    box-shadow: var(--menu-shadow);
    overflow: hidden;
  }
  .console-chip-main {
    border: 0;
    background: transparent;
    color: var(--text);
    padding: 8px 10px;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    max-width: 210px;
    white-space: nowrap;
    text-overflow: ellipsis;
    overflow: hidden;
  }
  .console-chip-main:hover { background: var(--surface-2); }
  .console-chip-close {
    border: 0;
    border-left: 1px solid var(--border);
    background: transparent;
    color: var(--muted);
    width: 32px;
    height: 32px;
    padding: 0;
    border-radius: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    font-size: 1rem;
    line-height: 1;
  }
  .console-chip-close:hover {
    color: var(--text);
    background: var(--surface-2);
  }

  :global(:root[data-theme='dark']) {
    --surface: #0b1220;
    --surface-2: #101a2d;
    --surface-3: #050a17;
    --text: #e6eef8;
    --muted: #9fb0c8;
    --icon: #a9b8cf;
    --focus-ring: #60a5fa;
    --danger: #f87171;
    --border: #334155;
    --border-strong: #1f2a3f;
    --menu-shadow: 0 12px 24px rgba(2, 6, 23, 0.45);
    --error-text: #fecaca;
    --error-bg: rgba(127, 29, 29, 0.35);
    --error-border: rgba(220, 38, 38, 0.45);
    --code-text: #cde8d9;
  }
  :global(:root[data-theme='light']) {
    --surface: #ffffff;
    --surface-2: #f8fafc;
    --surface-3: #eef2ff;
    --text: #0f172a;
    --muted: #475569;
    --icon: #334155;
    --focus-ring: #2563eb;
    --danger: #b91c1c;
    --border: #cbd5e1;
    --border-strong: #94a3b8;
    --menu-shadow: 0 10px 22px rgba(15, 23, 42, 0.16);
    --error-text: #7f1d1d;
    --error-bg: rgba(254, 226, 226, 0.9);
    --error-border: rgba(248, 113, 113, 0.7);
    --code-text: #134e4a;
  }

  @media (max-width: 640px) {
    .menu {
      width: min(260px, calc(100vw - 24px));
      right: 0;
    }
    .console-modal {
      height: min(78vh, 640px);
      border-radius: 12px;
    }
    .console-modal-maximized {
      width: calc(100vw - 10px);
      height: calc(100vh - 10px);
      border-radius: 8px;
    }
    .console-chip-main {
      max-width: 170px;
      font-size: 0.8rem;
    }
    .console-tab-main {
      max-width: 130px;
    }
  }

  @media (min-width: 860px) {
    .grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .key-grid { grid-template-columns: 2fr 1fr 1fr; }
    .row-actions { width: auto; grid-template-columns: repeat(5, auto); align-content: start; }
  }
</style>
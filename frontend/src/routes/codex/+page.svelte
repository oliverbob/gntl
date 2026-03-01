<script lang="ts">
  import { onDestroy, onMount } from 'svelte';

  type MonacoEditor = {
    getValue: () => string;
    setValue: (value: string) => void;
    layout: () => void;
    onDidChangeModelContent: (callback: () => void) => { dispose: () => void };
    dispose: () => void;
  };

  let editor: MonacoEditor | null = null;
  let editorContainer: HTMLDivElement | null = null;
  let previewFrame: HTMLIFrameElement | null = null;
  let prompt = '';
  let loading = false;
  let error = '';
  let lineCount = 1;
  let charCount = 0;
  let isDragging = false;
  let dragDisposer: (() => void) | null = null;
  let showComposer = true;
  let showCodePane = true;

  const starterCode = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Ginto Codex</title>
  <script src="https://cdn.tailwindcss.com"><\/script>
</head>
<body class="min-h-screen bg-slate-100 text-slate-800">
  <main class="mx-auto max-w-3xl px-6 py-16">
    <h1 class="text-4xl font-bold text-slate-900">Ginto Codex Builder</h1>
    <p class="mt-3 text-lg text-slate-600">Describe your website and iterate instantly.</p>
    <button class="mt-8 rounded-xl bg-indigo-600 px-5 py-3 font-semibold text-white hover:bg-indigo-500">Start Building</button>
  </main>
</body>
</html>`;

  function injectTailwind(): void {
    if (document.getElementById('codex-tailwind-cdn')) return;
    const script = document.createElement('script');
    script.id = 'codex-tailwind-cdn';
    script.src = 'https://cdn.tailwindcss.com';
    document.head.appendChild(script);
  }

  function loadMonacoLoader(): Promise<void> {
    return new Promise((resolve, reject) => {
      if ((window as any).require?.config) {
        resolve();
        return;
      }
      const existing = document.getElementById('codex-monaco-loader') as HTMLScriptElement | null;
      if (existing) {
        existing.addEventListener('load', () => resolve(), { once: true });
        existing.addEventListener('error', () => reject(new Error('Failed to load Monaco loader script.')), { once: true });
        return;
      }
      const script = document.createElement('script');
      script.id = 'codex-monaco-loader';
      script.src = 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs/loader.min.js';
      script.onload = () => resolve();
      script.onerror = () => reject(new Error('Failed to load Monaco loader script.'));
      document.head.appendChild(script);
    });
  }

  function updatePreview(content: string): void {
    if (!previewFrame) return;
    previewFrame.srcdoc = content;
  }

  function updateStats(content: string): void {
    lineCount = content.split('\n').length;
    charCount = content.length;
  }

  function initMonaco(): void {
    const win = window as any;
    if (!editorContainer || !win.require) return;

    win.require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs' } });
    win.require(['vs/editor/editor.main'], () => {
      editor = win.monaco.editor.create(editorContainer, {
        value: starterCode,
        language: 'html',
        theme: 'vs-dark',
        fontSize: 14,
        wordWrap: 'on',
        minimap: { enabled: true },
        automaticLayout: true,
        scrollBeyondLastLine: false
      }) as MonacoEditor;

      updatePreview(starterCode);
      updateStats(starterCode);

      editor.onDidChangeModelContent(() => {
        const value = editor?.getValue() || '';
        updatePreview(value);
        updateStats(value);
      });
    });
  }

  async function generateFromPrompt(): Promise<void> {
    if (!prompt.trim()) {
      error = 'Please enter a prompt';
      return;
    }
    if (!editor) {
      error = 'Editor not ready';
      return;
    }

    loading = true;
    error = '';
    try {
      const response = await fetch('/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ prompt: prompt.trim(), html: editor.getValue(), userID: 'gntl-codex' })
      });

      if (!response.ok) {
        throw new Error(`API Error: ${response.status}`);
      }

      const text = await response.text();
      if (!text.trim()) {
        throw new Error('Generation returned empty output');
      }
      editor.setValue(text);
      prompt = '';
    } catch (err) {
      error = String(err);
    } finally {
      loading = false;
    }
  }

  function clearPrompt(): void {
    prompt = '';
    error = '';
  }

  function refreshPreview(): void {
    if (!editor) return;
    updatePreview(editor.getValue());
  }

  function toggleComposer(): void {
    showComposer = !showComposer;
    setTimeout(() => editor?.layout(), 30);
  }

  function toggleCodePane(): void {
    showCodePane = !showCodePane;
    setTimeout(() => editor?.layout(), 30);
  }

  function setupDragbar(): void {
    const dragbar = document.getElementById('codex-dragbar');
    const leftPane = document.getElementById('codex-left-pane');
    const container = document.getElementById('codex-container');
    const rightPane = document.getElementById('codex-right-pane');
    if (!dragbar || !leftPane || !container || !rightPane) return;

    const onMove = (event: MouseEvent) => {
      if (!isDragging || !showCodePane) return;
      const containerRect = container.getBoundingClientRect();
      const nextLeft = Math.max(280, Math.min(event.clientX - containerRect.left, containerRect.width - 360));
      leftPane.style.width = `${nextLeft}px`;
      rightPane.style.width = `${containerRect.width - nextLeft - 6}px`;
      editor?.layout();
    };

    const onUp = () => {
      if (!isDragging) return;
      isDragging = false;
      document.body.style.cursor = '';
    };

    const onDown = (event: MouseEvent) => {
      if (window.innerWidth < 900 || !showCodePane) return;
      event.preventDefault();
      isDragging = true;
      document.body.style.cursor = 'ew-resize';
    };

    dragbar.addEventListener('mousedown', onDown);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);

    dragDisposer = () => {
      dragbar.removeEventListener('mousedown', onDown);
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }

  const onResize = () => editor?.layout();

  onMount(async () => {
    injectTailwind();
    try {
      await loadMonacoLoader();
      initMonaco();
      setupDragbar();
      window.addEventListener('resize', onResize);
    } catch (err) {
      error = String(err);
    }
  });

  onDestroy(() => {
    editor?.dispose();
    dragDisposer?.();
    window.removeEventListener('resize', onResize);
  });
</script>

<main class="codex-shell">
  <header class="codex-header">
    <div class="brand-block">
      <div class="brand-icon">&lt;/&gt;</div>
      <h1>Sai Chat Pro</h1>
      <a href="/" class="home-link" title="Back to Dashboard">Home</a>
    </div>

    <div class="user-pill">
      <span>admin</span>
      <span class="dot">•</span>
      <span>Plan: free</span>
    </div>

    <div class="header-right">
      <button class="deploy-btn" type="button" title="Deploy on Sai Cloud">▶ Deploy <span class="desktop-only">on Sai Cloud</span></button>
      <span class="powered">⚡ By AI Connect Solutions</span>
    </div>
  </header>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  <section id="codex-container" class="codex-container">
    {#if showCodePane}
      <div id="codex-left-pane" class="left-pane">
        <div class="editor-wrap">
          <div bind:this={editorContainer} class="editor-host"></div>
          {#if loading}
            <div class="typing-chip">AI is generating…</div>
          {/if}
        </div>

        {#if showComposer}
          <footer class="composer">
            <div class="composer-head">
              <div class="composer-label">
                <span>AI PROMPT</span>
                <svg class="svg-inline--fa fa-hand-point-down w-5 h-5 text-[var(--primary)] pointing-hand-indicator" aria-hidden="true" focusable="false" data-prefix="fas" data-icon="hand-point-down" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512" data-fa-i2svg=""><path fill="currentColor" d="M32 480c0 17.7 14.3 32 32 32s32-14.3 32-32V272H32V480zM224 320c0 17.7 14.3 32 32 32s32-14.3 32-32V256c0-17.7-14.3-32-32-32s-32 14.3-32 32v64zm-64 64c17.7 0 32-14.3 32-32V304c0-17.7-14.3-32-32-32s-32 14.3-32 32v48c0 17.7 14.3 32 32 32zm160-96c0 17.7 14.3 32 32 32s32-14.3 32-32V224c0-17.7-14.3-32-32-32s-32 14.3-32 32v64zm-96-88l0 .6c9.4-5.4 20.3-8.6 32-8.6c13.2 0 25.4 4 35.6 10.8c8.7-24.9 32.5-42.8 60.4-42.8c11.7 0 22.6 3.1 32 8.6V160C384 71.6 312.4 0 224 0H162.3C119.8 0 79.1 16.9 49.1 46.9L37.5 58.5C13.5 82.5 0 115.1 0 149v27c0 35.3 28.7 64 64 64h88c22.1 0 40-17.9 40-40s-17.9-40-40-40H96c-8.8 0-16-7.2-16-16s7.2-16 16-16h56c39.8 0 72 32.2 72 72z"></path></svg>
                <span class="prompt-help">What to build?</span>
              </div>
              <div class="composer-tools">
                <button on:click={toggleComposer} type="button">Hide</button>
                <button on:click={clearPrompt} type="button">Clear</button>
              </div>
            </div>
            <div class="composer-body">
              <textarea bind:value={prompt} placeholder="Ask AI to build UI (e.g. 'Create a responsive navbar with dark mode toggle')"></textarea>
              <button class="send-btn" on:click={generateFromPrompt} disabled={loading} title="Send Prompt" aria-label="Send Prompt">
                <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M4 12.5l15-8.5-3.5 16-4-5-7.5-2.5z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" />
                </svg>
              </button>
            </div>
            <div class="composer-foot">{lineCount} lines &nbsp;•&nbsp; {charCount} chars</div>
          </footer>
        {:else}
          <button class="show-composer" type="button" on:click={toggleComposer}>Show Prompt</button>
        {/if}
      </div>
    {/if}

    <div id="codex-dragbar" class={`dragbar ${showCodePane ? '' : 'hidden'}`}></div>

    <div id="codex-right-pane" class={`right-pane ${showCodePane ? '' : 'full'}`}>
      <div class="preview-toolbar">
        <button title="Refresh Preview" aria-label="Refresh Preview" on:click={refreshPreview}>
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M20 11a8 8 0 1 0 2.2 5.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
            <path d="M20 4v7h-7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </button>
        <span>Preview</span>
        <div class="preview-tools-right">
          <button title={showCodePane ? 'Hide code view' : 'Show code view'} aria-label={showCodePane ? 'Hide code view' : 'Show code view'} on:click={toggleCodePane}>
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M8 7l-5 5 5 5M16 7l5 5-5 5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
          </button>
          <button title="Reload" aria-label="Reload" on:click={refreshPreview}>
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M20 11a8 8 0 1 0 2.2 5.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
              <path d="M20 4v7h-7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
          </button>
        </div>
      </div>
      <iframe bind:this={previewFrame} title="Codex Preview"></iframe>
    </div>
  </section>
</main>

<style>
  .codex-shell {
    min-height: 100vh;
    background: #0d1117;
    color: #e5e7eb;
    display: flex;
    flex-direction: column;
  }
  .codex-header {
    height: 58px;
    border-bottom: 1px solid #1f2937;
    background: #111827;
    display: grid;
    grid-template-columns: auto 1fr auto;
    align-items: center;
    gap: 14px;
    padding: 0 14px;
  }
  .brand-block {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }
  .brand-icon {
    width: 32px;
    height: 32px;
    border-radius: 999px;
    background: linear-gradient(135deg, #ec4899, #7c3aed);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8rem;
    font-weight: 700;
    color: #fff;
  }
  .brand-block h1 {
    margin: 0;
    font-size: 1.05rem;
    font-weight: 700;
    white-space: nowrap;
  }
  .home-link {
    color: #9ca3af;
    text-decoration: none;
    font-size: 0.95rem;
  }
  .home-link:hover { color: #fff; }
  .user-pill {
    justify-self: center;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 0.95rem;
    color: #d1d5db;
    background: #030712;
    border: 1px solid #1f2937;
    border-radius: 9px;
    padding: 6px 14px;
    min-width: 260px;
    justify-content: center;
  }
  .user-pill .dot { color: #6b7280; }
  .header-right {
    display: flex;
    align-items: center;
    gap: 10px;
    justify-self: end;
  }
  .deploy-btn {
    border: 0;
    border-radius: 7px;
    background: #16a34a;
    color: #fff;
    padding: 7px 12px;
    font-size: 0.88rem;
    font-weight: 600;
    cursor: pointer;
  }
  .deploy-btn:hover { background: #15803d; }
  .powered {
    color: #9ca3af;
    font-size: 0.9rem;
    white-space: nowrap;
  }
  .error-banner {
    margin: 10px 14px 0;
    border: 1px solid rgba(220, 38, 38, 0.45);
    background: rgba(127, 29, 29, 0.35);
    color: #fecaca;
    border-radius: 10px;
    padding: 10px 12px;
    font-size: 0.92rem;
  }
  .codex-container {
    flex: 1;
    min-height: 0;
    display: flex;
    overflow: hidden;
  }
  .left-pane {
    width: 40%;
    min-width: 280px;
    background: #030712;
    border-right: 1px solid #1f2937;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .editor-wrap {
    flex: 1;
    position: relative;
    min-height: 0;
  }
  .editor-host {
    width: 100%;
    height: 100%;
  }
  .typing-chip {
    position: absolute;
    left: 12px;
    bottom: 12px;
    background: rgba(17, 24, 39, 0.94);
    border: 1px solid #374151;
    border-radius: 8px;
    padding: 8px 10px;
    font-size: 0.82rem;
    color: #cbd5e1;
  }
  .composer {
    border-top: 1px solid #1f2937;
    background: #020617;
    padding: 8px 10px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .composer-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }
  .composer-label {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 0.74rem;
    letter-spacing: 0.05em;
    color: #9ca3af;
    font-weight: 700;
  }
  .pointing-hand-indicator {
    width: 20px;
    height: 20px;
    color: #ec4899;
    display: inline-block;
    vertical-align: middle;
  }
  .prompt-help {
    color: #a78bfa;
    font-weight: 600;
    letter-spacing: 0;
    text-transform: none;
  }
  .composer-tools {
    display: inline-flex;
    gap: 8px;
  }
  .composer-tools button {
    border: 0;
    background: transparent;
    color: #9ca3af;
    font-size: 0.8rem;
    cursor: pointer;
    padding: 0;
  }
  .composer-tools button:hover { color: #f3f4f6; }
  .composer-body {
    position: relative;
  }
  .composer-body textarea {
    width: 100%;
    min-height: 88px;
    resize: none;
    border-radius: 8px;
    border: 1px solid #374151;
    background: #1f2937;
    color: #e5e7eb;
    padding: 10px 46px 10px 10px;
    font: inherit;
    font-size: 0.92rem;
    line-height: 1.45;
  }
  .composer-body textarea:focus {
    outline: 2px solid #a855f7;
    outline-offset: 1px;
  }
  .send-btn {
    position: absolute;
    right: 8px;
    bottom: 8px;
    width: 34px;
    height: 34px;
    border-radius: 999px;
    border: 0;
    background: linear-gradient(135deg, #ec4899, #8b5cf6);
    color: #fff;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
  }
  .send-btn svg { width: 17px; height: 17px; }
  .send-btn:disabled { opacity: 0.55; cursor: not-allowed; }
  .composer-foot {
    font-size: 0.8rem;
    color: #6b7280;
  }
  .show-composer {
    border: 0;
    border-top: 1px solid #1f2937;
    background: #020617;
    color: #cbd5e1;
    font-size: 0.85rem;
    padding: 9px;
    cursor: pointer;
  }
  .dragbar {
    width: 6px;
    background: #1f2937;
    cursor: ew-resize;
    transition: background 0.15s ease;
  }
  .dragbar:hover { background: #a855f7; }
  .dragbar.hidden { display: none; }
  .right-pane {
    flex: 1;
    min-width: 0;
    background: #fff;
    display: flex;
    flex-direction: column;
  }
  .right-pane.full { width: 100%; }
  .preview-toolbar {
    height: 36px;
    border-bottom: 1px solid #d1d5db;
    background: #f3f4f6;
    color: #374151;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 9px;
    font-size: 0.9rem;
  }
  .preview-toolbar button {
    border: 0;
    background: transparent;
    color: inherit;
    width: 24px;
    height: 24px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    border-radius: 6px;
  }
  .preview-toolbar button:hover { background: rgba(15, 23, 42, 0.08); }
  .preview-toolbar button svg {
    width: 16px;
    height: 16px;
  }
  .preview-tools-right {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 2px;
  }
  .right-pane iframe {
    width: 100%;
    flex: 1;
    border: 0;
    background: #fff;
  }

  @media (max-width: 1080px) {
    .user-pill { min-width: 210px; }
    .powered { display: none; }
  }

  @media (max-width: 899px) {
    .codex-header {
      grid-template-columns: 1fr;
      height: auto;
      padding: 10px;
      gap: 8px;
    }
    .brand-block,
    .user-pill,
    .header-right {
      justify-self: stretch;
    }
    .user-pill { width: 100%; }
    .header-right { justify-content: space-between; }
    .desktop-only { display: none; }
    .codex-container {
      flex-direction: column;
    }
    .left-pane {
      width: 100% !important;
      min-width: 0;
      height: 58vh;
      border-right: 0;
      border-bottom: 1px solid #1f2937;
    }
    .dragbar { display: none; }
    .right-pane {
      height: 42vh;
    }
  }
</style>
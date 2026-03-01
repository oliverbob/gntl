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
      error = 'Enter a prompt first.';
      return;
    }
    if (!editor) {
      error = 'Editor is not ready yet.';
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
        throw new Error(`Generation failed (${response.status}).`);
      }

      const text = await response.text();
      if (!text.trim()) {
        throw new Error('Generation returned empty output.');
      }
      editor.setValue(text);
      prompt = '';
    } catch (err) {
      error = `Codex request failed: ${String(err)}`;
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

  function downloadHtml(): void {
    if (!editor) return;
    const blob = new Blob([editor.getValue()], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'codex-page.html';
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function setupDragbar(): void {
    const dragbar = document.getElementById('codex-dragbar');
    const leftPane = document.getElementById('codex-left-pane');
    const container = document.getElementById('codex-container');
    const rightPane = document.getElementById('codex-right-pane');
    if (!dragbar || !leftPane || !container || !rightPane) return;

    const onMove = (event: MouseEvent) => {
      if (!isDragging) return;
      const containerRect = container.getBoundingClientRect();
      const nextLeft = Math.max(260, Math.min(event.clientX - containerRect.left, containerRect.width - 320));
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
      if (window.innerWidth < 1024) return;
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

  onMount(async () => {
    injectTailwind();
    try {
      await loadMonacoLoader();
      initMonaco();
      setupDragbar();
      window.addEventListener('resize', () => editor?.layout());
    } catch (err) {
      error = String(err);
    }
  });

  onDestroy(() => {
    editor?.dispose();
    dragDisposer?.();
  });
</script>

<main class="min-h-screen bg-slate-950 text-slate-100">
  <header class="border-b border-slate-800 bg-slate-900/95 px-4 py-3 backdrop-blur">
    <div class="mx-auto flex max-w-[1400px] items-center justify-between gap-3">
      <div class="flex items-center gap-3">
        <a href="/" class="rounded-xl border border-slate-700 px-3 py-2 text-sm font-medium text-slate-200 hover:bg-slate-800">← Dashboard</a>
        <div>
          <h1 class="text-xl font-semibold">Codex Builder</h1>
          <p class="text-xs text-slate-400">Monaco + Tailwind website builder</p>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <button on:click={refreshPreview} class="rounded-xl border border-slate-700 px-3 py-2 text-sm hover:bg-slate-800">Refresh Preview</button>
        <button on:click={downloadHtml} class="rounded-xl bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-500">Download HTML</button>
      </div>
    </div>
  </header>

  <section class="mx-auto max-w-[1400px] p-4">
    <div class="mb-3 grid gap-3 rounded-2xl border border-slate-800 bg-slate-900 p-3 lg:grid-cols-[1fr_auto]">
      <div>
        <label for="codex-prompt" class="mb-2 block text-xs font-semibold uppercase tracking-wide text-slate-400">AI Prompt</label>
        <textarea
          id="codex-prompt"
          bind:value={prompt}
          class="h-28 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-indigo-500"
          placeholder="Describe what website to build..."
        ></textarea>
      </div>
      <div class="flex items-end gap-2 lg:flex-col lg:justify-end">
        <button on:click={generateFromPrompt} disabled={loading} class="rounded-xl bg-fuchsia-600 px-4 py-2 text-sm font-semibold text-white hover:bg-fuchsia-500 disabled:opacity-60">
          {loading ? 'Generating…' : 'Generate'}
        </button>
        <button on:click={clearPrompt} class="rounded-xl border border-slate-700 px-4 py-2 text-sm hover:bg-slate-800">Clear</button>
      </div>
    </div>

    {#if error}
      <p class="mb-3 rounded-xl border border-rose-600/50 bg-rose-950/40 px-3 py-2 text-sm text-rose-200">{error}</p>
    {/if}

    <div id="codex-container" class="flex h-[72vh] flex-col overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 lg:flex-row">
      <div id="codex-left-pane" class="relative h-[48%] w-full border-b border-slate-800 lg:h-full lg:w-[45%] lg:border-b-0 lg:border-r">
        <div bind:this={editorContainer} class="h-full w-full"></div>
      </div>
      <div id="codex-dragbar" class="hidden w-[6px] cursor-ew-resize bg-slate-800 transition hover:bg-indigo-500 lg:block"></div>
      <div id="codex-right-pane" class="h-[52%] w-full bg-white lg:h-full lg:flex-1">
        <iframe bind:this={previewFrame} title="Codex Preview" class="h-full w-full border-0"></iframe>
      </div>
    </div>

    <div class="mt-3 flex items-center justify-between text-xs text-slate-400">
      <p>{lineCount} lines • {charCount} chars</p>
      <p>Tailwind-enabled HTML preview</p>
    </div>
  </section>
</main>
# gntl SvelteKit Frontend

This is a SvelteKit frontend shell for the stable `gntl` API.

## Run via `./run.sh`

From repo root (`gntl/`):

```bash
./run.sh frontend-install
./run.sh frontend-dev
```

## Direct Run (optional)

```bash
cd frontend
npm install
npm run dev
```

Default dev URL: `http://127.0.0.1:5173`

The Vite dev server proxies these paths to `http://127.0.0.1:2026` by default:

- `/api/*`
- `/login`
- `/logout`

Override proxy target with:

```bash
GNTL_API_TARGET=http://127.0.0.1:2026 npm run dev
```

## Build

```bash
./run.sh frontend-build
npm run preview
```

The project uses static adapter output with SPA fallback (`index.html`).

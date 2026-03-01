import os
import sys
import json
import shutil
import urllib.request
import tarfile
import zipfile
import stat
from pathlib import Path

API_LATEST = "https://api.github.com/repos/fatedier/frp/releases/latest"
PROJECT_ROOT = str(Path(__file__).resolve().parents[3])
DEST_BIN = os.path.join(PROJECT_ROOT, "bin")

def platform_key():
    import platform
    system = platform.system().lower()
    machine = platform.machine().lower()
    # normalize
    if machine in ("x86_64", "amd64"): arch = "amd64"
    elif "aarch64" in machine or machine in ("arm64",): arch = "arm64"
    elif machine.startswith("arm"): arch = "arm"
    else: arch = machine
    return system, arch

def ensure_bin_dir():
    os.makedirs(DEST_BIN, exist_ok=True)

def fetch_latest_release_json():
    req = urllib.request.Request(API_LATEST, headers={"User-Agent": "frp-wrapper"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)

def find_asset_for_platform(release_json):
    system, arch = platform_key()
    names = []
    # common mapping
    # e.g. frp_0.67.0_linux_amd64.tar.gz
    for a in release_json.get("assets", []):
        n = a.get("name", "")
        names.append((n, a.get("browser_download_url")))
    # prefer match containing system and arch
    for n, url in names:
        if system in n and arch in n and (n.endswith('.tar.gz') or n.endswith('.zip')):
            return n, url
    # fallback: pick first tar/zip
    for n, url in names:
        if n.endswith('.tar.gz') or n.endswith('.zip'):
            return n, url
    return None, None

def download_file(url, outpath):
    req = urllib.request.Request(url, headers={"User-Agent": "frp-wrapper"})
    with urllib.request.urlopen(req) as r, open(outpath, 'wb') as f:
        shutil.copyfileobj(r, f)

def extract_and_place(fname, outdir=DEST_BIN):
    # extract archive and find frpc/frps
    tmpdir = os.path.join('/tmp', f"frp_extract_{os.getpid()}")
    os.makedirs(tmpdir, exist_ok=True)
    try:
        if fname.endswith('.zip'):
            with zipfile.ZipFile(fname, 'r') as z:
                z.extractall(tmpdir)
        else:
            with tarfile.open(fname, 'r:*') as t:
                t.extractall(tmpdir)
        # find frpc/frps
        for root, dirs, files in os.walk(tmpdir):
            for f in files:
                if f in ('frpc', 'frps') or f.lower().startswith('frp'):
                    src = os.path.join(root, f)
                    dst = os.path.join(outdir, f)
                    shutil.copy2(src, dst)
                    try:
                        os.chmod(dst, 0o755)
                    except Exception:
                        pass
        return True
    finally:
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

def ensure_frpc():
    ensure_bin_dir()
    # prefer frpc in DEST_BIN
    frpc_path = os.path.join(DEST_BIN, 'frpc')
    if os.path.exists(frpc_path):
        return frpc_path
    rel = fetch_latest_release_json()
    name, url = find_asset_for_platform(rel)
    if not url:
        raise RuntimeError('No suitable FRP asset found for this platform')
    out = os.path.join('/tmp', name)
    download_file(url, out)
    extract_and_place(out, DEST_BIN)
    if os.path.exists(frpc_path):
        return frpc_path
    # try executable in bin
    for f in os.listdir(DEST_BIN):
        fp = os.path.join(DEST_BIN, f)
        if os.path.isfile(fp) and os.access(fp, os.X_OK):
            return fp
    raise RuntimeError('frpc binary not found after extraction')

if __name__ == '__main__':
    print('Ensuring frpc...')
    p = ensure_frpc()
    print('frpc at', p)

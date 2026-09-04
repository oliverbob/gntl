export type InstanceRecord = {
  status?: 'running' | 'stopped' | string;
  pid?: number | null;
  uptime?: number;
  protocol?: string;
  proxyName?: string;
  label?: string;
  boundWithKey?: boolean;
  keyExpiresAt?: number | null;
  subdomain?: string;
  serverAddr?: string;
  serverPort?: number;
  localPort?: number;
  config?: string;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    ...init
  });
  const text = await response.text();
  if (!response.ok) {
    if (response.status >= 500) {
      const detail = text.trim();
      const looksLikeGenericServerError =
        !detail ||
        /^internal server error$/i.test(detail) ||
        /^request failed:\s*500$/i.test(detail);
      if (looksLikeGenericServerError) {
        throw new Error('Backend API unavailable. Start gntl backend on 127.0.0.1:2026 (run ./run.sh backend).');
      }
      throw new Error(`Backend API error (${response.status}): ${detail}`);
    }
    throw new Error(text || `Request failed: ${response.status}`);
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    return null as T;
  }
}

export async function getInstances(): Promise<Record<string, InstanceRecord>> {
  return request<Record<string, InstanceRecord>>('/api/instances');
}

// The tunnel publishing this webadmin. Read-only by design: it is the
// connection this page arrived over, so there is no action to offer on it.
export type ManagerTunnel = {
  found: boolean;
  id?: string;
  status?: string;
  pid?: number | null;
  subdomain?: string;
  serverAddr?: string;
  hostname?: string;
  localPort?: number;
  protocol?: string;
};

export async function getManagerTunnel(): Promise<ManagerTunnel> {
  return request<ManagerTunnel>('/api/manager/tunnel');
}

export async function runInstanceAction(id: string, action: 'start' | 'stop' | 'restart'): Promise<unknown> {
  return request(`/api/instances/${encodeURIComponent(id)}/${action}`, { method: 'POST' });
}

export async function deleteInstance(id: string): Promise<unknown> {
  return request(`/api/instances/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export async function cleanupDeletedInstances(): Promise<unknown> {
  return request('/api/instances/cleanup-deleted', { method: 'POST' });
}

export async function getInstanceLogs(id: string, lines = 200): Promise<string[]> {
  const payload = await request<{ lines?: string[] }>(`/api/instances/${encodeURIComponent(id)}/logs?lines=${lines}`);
  return Array.isArray(payload?.lines) ? payload.lines : [];
}

export type BoundKey = {
  subdomain: string;
  name?: string;
  hostname: string;
  keyMasked: string;
  localPort?: number;
  instanceId?: string;
  status?: string;
  expiresAt?: number | null;
  boundAt?: number;
};

export type BindKeyResult = {
  ok: boolean;
  subdomain: string;
  name?: string;
  hostname: string;
  url: string;
  instanceId: string;
  localPort: number;
  localTlsDetected: boolean;
  started: boolean;
  startError?: string | null;
  metaVerified: boolean;
  expiresAt?: number | null;
};

export async function getBoundKeys(): Promise<BoundKey[]> {
  const payload = await request<{ keys?: BoundKey[] }>('/api/tunnel/keys');
  return Array.isArray(payload?.keys) ? payload.keys : [];
}

export async function bindTunnelKey(key: string, localPort?: number, name?: string): Promise<BindKeyResult> {
  return request<BindKeyResult>('/api/tunnel/bind', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key, localPort, name })
  });
}

export async function deleteBoundKey(subdomain: string): Promise<unknown> {
  return request('/api/tunnel/keys/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subdomain })
  });
}
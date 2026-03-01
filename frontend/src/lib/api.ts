export type InstanceRecord = {
  status?: 'running' | 'stopped' | string;
  pid?: number | null;
  uptime?: number;
  protocol?: string;
  proxyName?: string;
  subdomain?: string;
  serverAddr?: string;
  serverPort?: number;
  localPort?: number;
  config?: string;
};

export type CreateInstancePayload = {
  id: string;
  proxyName: string;
  subdomain: string;
  serverAddr?: string;
  localPort?: number;
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

export async function createInstance(payload: CreateInstancePayload): Promise<unknown> {
  return request('/api/instances', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
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
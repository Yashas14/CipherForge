const API_BASE = '/v1';

export async function apiPost(endpoint, body) {
  const resp = await fetch(API_BASE + endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || data.message || JSON.stringify(data));
  return data;
}

export async function apiGet(endpoint) {
  const resp = await fetch(API_BASE + endpoint);
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || data.message || JSON.stringify(data));
  return data;
}

export function b64encode(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

export function b64decode(b64) {
  return decodeURIComponent(escape(atob(b64)));
}

export function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

const API_BASE =
  import.meta.env.VITE_API_BASE ||
  `${window.location.protocol}//${window.location.hostname}:8000`;

async function handle(res: Response) {
  if (res.status === 401) {
    const err: any = new Error("unauthorized");
    err.status = 401;
    throw err;
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function login(username: string, password: string) {
  const res = await fetch(`${API_BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return handle(res);
}

export async function uploadFile(token: string, file: File) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE}/api/upload`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  });
  return handle(res);
}

export async function runAnalysis(token: string, uploadId: number) {
  const res = await fetch(`${API_BASE}/api/analyze/${uploadId}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  return handle(res);
}

export async function getStatus(token: string, uploadId: number) {
  const res = await fetch(`${API_BASE}/api/status/${uploadId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return handle(res);
}

export async function getAnalysis(token: string, uploadId: number) {
  const res = await fetch(`${API_BASE}/api/analysis/${uploadId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return handle(res);
}

export async function getUploads(token: string) {
  const res = await fetch(`${API_BASE}/api/uploads`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return handle(res);
}

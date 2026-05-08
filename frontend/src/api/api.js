const API_BASE = "http://localhost:8000";

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/api/health`);
  return await res.json();
}

export async function fetchServices() {
  try {
    const res = await fetch(`${API_BASE}/api/services`);
    return await res.json();
  } catch {
    return [];
  }
}
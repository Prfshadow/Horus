import type { ApiError } from "@/types/api";

const EXPLICIT_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").trim();

function buildUrl(path: string): string {
  if (path.startsWith("http")) return path;
  const p = path.startsWith("/") ? path : `/${path}`;
  // Local dev: no explicit base URL -> same-origin relative URL, served
  // through the Vite `/api` proxy (avoids browser CORS to :8000).
  // Production/direct: set VITE_API_BASE_URL explicitly at build time.
  if (!EXPLICIT_BASE_URL) {
    return p;
  }
  return `${EXPLICIT_BASE_URL.replace(/\/$/, "")}${p}`;
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const url = buildUrl(path);
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(init?.headers || {}),
      },
    });
  } catch (err) {
    throw { status: 0, message: "Network error", details: err } as ApiError;
  }

  if (!res.ok) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      // ignore
    }
    const message =
      (body as { detail?: string })?.detail ||
      (body as { message?: string })?.message ||
      `Request failed: ${res.status} ${res.statusText}`;
    throw { status: res.status, message, details: body } as ApiError;
  }

  // Handle 204 No Content
  if (res.status === 204) {
    return undefined as T;
  }

  try {
    const data = (await res.json()) as T;
    return data;
  } catch (err) {
    throw { status: res.status, message: "Invalid JSON response", details: err } as ApiError;
  }
}

export function getApiBaseUrl(): string {
  return EXPLICIT_BASE_URL || "http://localhost:8000";
}

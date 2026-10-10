const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export class ApiError extends Error {
  constructor(public status: number, public message: string, public body?: unknown) {
    super(message);
    this.name = 'ApiError';
  }
}

export async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const headers = new Headers(options.headers);
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(url, { ...options, headers });

  let responseBody: unknown;
  try {
    // Attempt to parse JSON; fallback to text if parsing fails
    const text = await response.text();
    responseBody = text ? JSON.parse(text) : undefined;
  } catch (e) {
    // Keep responseBody as undefined or string depending on requirements
  }

  if (!response.ok) {
    throw new ApiError(
      response.status,
      `API request failed with status ${response.status}`,
      responseBody
    );
  }

  return responseBody as T;
}

// Explicit health check using the only verified endpoint
export async function checkBackendHealth(): Promise<{ status: string }> {
  return request<{ status: string }>('/health', { method: 'GET' });
}

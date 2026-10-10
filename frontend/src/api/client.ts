const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export class ApiError extends Error {
  constructor(
    public status: number,
    public message: string, // Developer/debug message
    public userMessage: string, // Safe for UI
    public body?: unknown
  ) {
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

  let response: Response;
  try {
    response = await fetch(url, { ...options, headers });
  } catch (err: any) {
    // Network or CORS error
    throw new ApiError(0, err.message, 'Unable to reach the server. Please check your connection and try again.');
  }

  let responseBody: any;
  try {
    const text = await response.text();
    responseBody = text ? JSON.parse(text) : undefined;
  } catch (e) {
    // Keep responseBody undefined if unparseable
  }

  if (!response.ok) {
    let userMessage = 'Analysis could not be completed. Please try again later.';
    
    if (response.status === 422 && responseBody?.detail) {
      // Handle FastAPI validation errors safely
      const details = Array.isArray(responseBody.detail) ? responseBody.detail : [];
      if (details.length > 0 && details[0].msg) {
        userMessage = `Validation Error: ${details[0].msg}`;
      } else {
        userMessage = 'Please check your input and try again.';
      }
    } else if (response.status >= 400 && response.status < 500) {
      userMessage = responseBody?.detail && typeof responseBody.detail === 'string'
        ? responseBody.detail // Assuming backend detail is safe for 4xx if it's a string
        : 'The request was invalid. Please check your input.';
    }

    throw new ApiError(
      response.status,
      `API request failed with status ${response.status}`,
      userMessage,
      responseBody
    );
  }

  return responseBody as T;
}

// Explicit health check using the only verified endpoint
export async function checkBackendHealth(): Promise<{ status: string }> {
  return request<{ status: string }>('/health', { method: 'GET' });
}

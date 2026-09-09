/**
 * Client-side API fetch utility for PLIŌRA Threat Monitor.
 * Automatically forwards HttpOnly session cookies (credentials: 'include')
 * and normalizes error envelopes.
 */

export class ApiError extends Error {
  public code: string;
  public status: number;
  public data?: any;

  constructor(message: string, code: string = 'UNKNOWN_ERROR', status: number = 500, data?: any) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.data = data;
  }
}

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: any;
  params?: Record<string, string | number | boolean | undefined | null>;
}

async function request<T = any>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { body, params, headers, ...customConfig } = options;

  let url = endpoint;
  if (params) {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.append(key, String(value));
      }
    });
    const queryString = searchParams.toString();
    if (queryString) {
      url += (url.includes('?') ? '&' : '?') + queryString;
    }
  }

  const config: RequestInit = {
    method: options.method || (body ? 'POST' : 'GET'),
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    ...customConfig,
  };

  if (body) {
    config.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  const response = await fetch(url, config);

  let responseData: any = null;
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    try {
      responseData = await response.json();
    } catch {
      responseData = null;
    }
  } else {
    try {
      responseData = await response.text();
    } catch {
      responseData = null;
    }
  }

  if (!response.ok) {
    const errorCode = responseData?.error?.code || `HTTP_${response.status}`;
    const errorMessage =
      responseData?.error?.message ||
      responseData?.message ||
      (typeof responseData === 'string' ? responseData : null) ||
      `Request failed with status ${response.status}`;

    throw new ApiError(errorMessage, errorCode, response.status, responseData);
  }

  // Handle PLIŌRA standard response envelope: { success: true, data: ... }
  if (responseData && typeof responseData === 'object' && 'success' in responseData) {
    if (responseData.success === false) {
      throw new ApiError(
        responseData.error?.message || 'Operation failed',
        responseData.error?.code || 'OPERATION_FAILED',
        response.status,
        responseData
      );
    }
    return responseData.data !== undefined ? responseData.data : responseData;
  }

  return responseData;
}

export const api = {
  get: <T = any>(endpoint: string, options?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(endpoint, { ...options, method: 'GET' }),

  post: <T = any>(endpoint: string, body?: any, options?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(endpoint, { ...options, method: 'POST', body }),

  patch: <T = any>(endpoint: string, body?: any, options?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(endpoint, { ...options, method: 'PATCH', body }),

  delete: <T = any>(endpoint: string, options?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(endpoint, { ...options, method: 'DELETE' }),
};

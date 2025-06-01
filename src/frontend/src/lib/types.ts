export interface EmailMessage {
  id: string;
  subject: string;
  from: string;
  date: string;
  snippet: string;
  body?: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  accessToken: string | null;
  refreshToken: string | null;
}
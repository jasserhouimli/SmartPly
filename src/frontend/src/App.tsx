import { useEffect, useState } from "react";
import { EmailList } from "./components/EmailList";

interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
}

export default function App() {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
  });

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const accessToken =
      urlParams.get("access_token") || localStorage.getItem("accessToken");

    if (accessToken) {
      setAuthState({
        isAuthenticated: true,
        isLoading: false,
      });

      if (urlParams.get("access_token")) {
        localStorage.setItem("accessToken", urlParams.get("access_token")!);

        if (urlParams.get("refresh_token")) {
          localStorage.setItem("refreshToken", urlParams.get("refresh_token")!);
        }

        window.history.replaceState(
          {},
          document.title,
          window.location.pathname,
        );
      }
    } else {
      setAuthState({
        isAuthenticated: false,
        isLoading: false,
      });
    }
  }, []);

  const handleGoogleLogin = async () => {
    try {
      setAuthState((prev) => ({ ...prev, isLoading: true }));
      const response = await fetch(
        "http://localhost:500/auth/google/authorize",
      );

      if (!response.ok) {
        throw new Error("Failed to initialize Google login");
      }

      const data = await response.json();
      window.location.href = data.authorizationUrl;
    } catch (error) {
      console.error("Login error:", error);
      setAuthState((prev) => ({ ...prev, isLoading: false }));
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
    setAuthState({
      isAuthenticated: false,
      isLoading: false,
    });
  };

  if (authState.isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        Loading...
      </div>
    );
  }

  if (!authState.isAuthenticated) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen gap-4 p-4">
        <h1 className="text-2xl font-bold mb-8">SmartPly Email Viewer</h1>
        <button
          onClick={handleGoogleLogin}
          className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md flex items-center gap-2"
          disabled={authState.isLoading}
        >
          {authState.isLoading ? "Connecting..." : "Sign in with Google"}
        </button>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-4">
      <header className="flex justify-between items-center mb-6 pb-4 border-b">
        <h1 className="text-xl font-bold">SmartPly Email Viewer</h1>
        <button
          onClick={handleLogout}
          className="px-3 py-1 bg-gray-200 hover:bg-gray-300 rounded text-sm"
        >
          Sign Out
        </button>
      </header>

      <main>
        <EmailList />
      </main>
    </div>
  );
}

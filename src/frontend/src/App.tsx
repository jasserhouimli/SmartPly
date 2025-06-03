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
    // Call a protected endpoint to verify authentication
    const checkAuth = async () => {
      try {
        const response = await fetch("http://localhost:5000/auth/me", {
          credentials: "include",
        });

        if (response.ok) {
          setAuthState({ isAuthenticated: true, isLoading: false });
        } else {
          setAuthState({ isAuthenticated: false, isLoading: false });
        }
      } catch (error) {
        console.error("Auth check failed", error);
        setAuthState({ isAuthenticated: false, isLoading: false });
      }
    };

    checkAuth();
  }, []);

  const handleGoogleLogin = async () => {
    try {
      setAuthState((prev) => ({ ...prev, isLoading: true }));
      const response = await fetch(
        "http://localhost:5000/auth/google/authorize",
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

  const handleLogout = async () => {
    try {
      await fetch("http://localhost:5000/auth/logout", {
        method: "POST",
        credentials: "include",
      });

      setAuthState({
        isAuthenticated: false,
        isLoading: false,
      });
    } catch (err) {
      console.error("Logout failed", err);
    }
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

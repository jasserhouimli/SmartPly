import { useEffect, useState } from "react";
import type { EmailMessage } from "../lib/types";

export function EmailList() {
  const [emails, setEmails] = useState<EmailMessage[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedEmail, setSelectedEmail] = useState<EmailMessage | null>(null);

  const fetchEmails = async () => {
    try {
      setLoading(true);
      setError(null);

      // Get access token from URL parameters or localStorage
      const urlParams = new URLSearchParams(window.location.search);
      const accessToken =
        urlParams.get("access_token") || localStorage.getItem("accessToken");

      if (!accessToken) {
        setError("Not authenticated. Please sign in with Google.");
        setLoading(false);
        return;
      }

      const response = await fetch("http://localhost:5000/gmail/messages", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch emails: ${response.statusText}`);
      }

      const data = await response.json();
      setEmails(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load emails");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const accessToken = urlParams.get("access_token");
    const refreshToken = urlParams.get("refresh_token");

    if (accessToken) {
      localStorage.setItem("accessToken", accessToken);
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    if (refreshToken) {
      localStorage.setItem("refreshToken", refreshToken);
    }

    fetchEmails();
  }, []);

  const handleRefresh = () => {
    fetchEmails();
  };

  const formatDate = (dateString: string) => {
    try {
      const date = new Date(dateString);
      return date.toLocaleString();
    } catch {
      return dateString;
    }
  };

  const extractSender = (from: string) => {
    const match = from.match(/([^<]+)?<?([^>]+)>?/);
    if (match && match[1]) {
      return match[1].trim();
    }
    return from;
  };

  if (loading) {
    return <div className="p-4 text-center">Loading emails...</div>;
  }

  if (error) {
    return (
      <div className="p-4">
        <div className="text-destructive mb-4">{error}</div>
        <button
          onClick={handleRefresh}
          className="px-4 py-2 bg-primary text-primary-foreground rounded"
        >
          Retry
        </button>
      </div>
    );
  }

  if (emails.length === 0) {
    return <div className="p-4 text-center">No emails found.</div>;
  }

  if (selectedEmail) {
    return (
      <div className="p-4">
        <button
          onClick={() => setSelectedEmail(null)}
          className="mb-4 px-3 py-1 bg-secondary text-secondary-foreground rounded flex items-center"
        >
          <span className="mr-1">←</span> Back to list
        </button>

        <div className="border rounded-md p-4">
          <h2 className="text-xl font-bold mb-2">{selectedEmail.subject}</h2>
          <div className="text-sm text-muted-foreground mb-4">
            <div>From: {selectedEmail.from}</div>
            <div>Date: {formatDate(selectedEmail.date)}</div>
          </div>

          <div className="border-t pt-4 mt-4">
            {selectedEmail.body ? (
              <div className="whitespace-pre-wrap">{selectedEmail.body}</div>
            ) : (
              <div className="italic text-muted-foreground">
                {selectedEmail.snippet}...
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4">
      <div className="flex justify-between items-center mb-4">
        <h1 className="text-2xl font-bold">Your Emails</h1>
        <button
          onClick={handleRefresh}
          className="px-3 py-1 bg-secondary text-secondary-foreground rounded"
        >
          Refresh
        </button>
      </div>

      <div className="space-y-2">
        {emails.map((email) => (
          <div
            key={email.id}
            className="border rounded-md p-3 cursor-pointer hover:bg-accent/10"
            onClick={() => setSelectedEmail(email)}
          >
            <div className="flex justify-between items-baseline">
              <div className="font-medium">{extractSender(email.from)}</div>
              <div className="text-xs text-muted-foreground">
                {formatDate(email.date)}
              </div>
            </div>
            <div className="text-sm font-semibold">{email.subject}</div>
            <div className="text-xs text-muted-foreground truncate">
              {email.snippet}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

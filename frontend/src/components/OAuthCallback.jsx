import React, { useEffect, useRef, useState } from "react";

export default function OAuthCallback() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const hasRun = useRef(false);

  useEffect(() => {
    if (hasRun.current) return;   // Prevent double execution
    hasRun.current = true;

    const handleCallback = async () => {
      try {
        const params = new URLSearchParams(window.location.search);
        const code = params.get("code");

        if (!code) {
          setError("No authorization code provided");
          setLoading(false);
          return;
        }

        const response = await fetch("http://127.0.0.1:8000/auth/callback", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code })
        });

        if (!response.ok) {
          throw new Error("Failed to authenticate");
        }

        const data = await response.json();

        // Clear any previous user data
        localStorage.clear();
        
        // Store new user's token and data
        localStorage.setItem("token", data.access_token);
        localStorage.setItem("user", JSON.stringify(data.user));

        // Force full page reload to reinitialize App with new user
        window.location.href = "/";
      } catch (err) {
        setError(err.message);
        setLoading(false);
      }
    };

    handleCallback();
  }, []);

  if (loading) {
    return (
      <div style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "100vh",
        backgroundColor: "#242424"
      }}>
        <p style={{ color: "white" }}>Authenticating...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "100vh",
        backgroundColor: "#242424"
      }}>
        <p style={{ color: "red" }}>Error: {error}</p>
      </div>
    );
  }
}
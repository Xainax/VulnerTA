import React from "react";

export default function Login() {
  const handleGitHubLogin = () => {
    const clientId = import.meta.env.VITE_GITHUB_CLIENT_ID;
    const redirectUri = import.meta.env.VITE_GITHUB_REDIRECT_URI;
    const scope = "user:email";

    const authUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}`;
    window.location.href = authUrl;
  };

  return (
    <div style={{
      display: "flex",
      flexDirection: "column",
      justifyContent: "center",
      alignItems: "center",
      minHeight: "100vh",
      backgroundColor: "#242424",
      color: "white"
    }}>
      <div style={{
        textAlign: "center",
        padding: "2rem",
        backgroundColor: "#1a1a1a",
        borderRadius: "8px",
        maxWidth: "400px"
      }}>
        <h1 style={{ marginBottom: "1rem" }}>VulnerTA</h1>
        <p style={{ marginBottom: "2rem", color: "#999" }}>
          AI Vulnerability Search & Assessment
        </p>

        <button
          onClick={handleGitHubLogin}
          style={{
            width: "100%",
            padding: "12px 18px",
            fontSize: "16px",
            borderRadius: "6px",
            background: "black",
            color: "white",
            border: "1px solid white",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "8px",
            transition: "all 0.3s"
          }}
          onMouseEnter={(e) => e.target.style.background = "#333"}
          onMouseLeave={(e) => e.target.style.background = "black"}
        >
          <GitHubIcon />
          Login with GitHub
        </button>
      </div>
    </div>
  );
}

function GitHubIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="white">
      <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v 3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
    </svg>
  );
}
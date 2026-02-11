import React, { useState, useEffect } from "react";
import Dashboard from "./components/Dashboard";
import Login from "./components/Login";
import OAuthCallback from "./components/OAuthCallback";

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);

  useEffect(() => {
    // Check if user is already logged in
    const token = localStorage.getItem("token");
    const storedUser = localStorage.getItem("user");

    if (token && storedUser) {
      setIsAuthenticated(true);
      setUser(JSON.parse(storedUser));
    }
    setLoading(false);
  }, []);

  // Handle OAuth callback
  if (window.location.pathname === "/callback") {
    return <OAuthCallback />;
  }

  if (loading) {
    return <div>Loading...</div>;
  }

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setIsAuthenticated(false);
    setUser(null);
  };

  return (
    <div style={{ width: "100%", minHeight: "100vh" }}>
      {isAuthenticated ? (
        <div>
          <div style={{
            padding: "1rem",
            backgroundColor: "#1a1a1a",
            color: "white",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center"
          }}>
            <span>Welcome, {user?.login}!</span>
            <button
              onClick={handleLogout}
              style={{
                padding: "8px 16px",
                background: "red",
                color: "white",
                border: "none",
                borderRadius: "4px",
                cursor: "pointer"
              }}
            >
              Logout
            </button>
          </div>
          <Dashboard />
        </div>
      ) : (
        <div style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          minHeight: "100vh",
          width: "100%"
        }}>
          <Login />
        </div>
      )}
    </div>
  );
}

export default App;
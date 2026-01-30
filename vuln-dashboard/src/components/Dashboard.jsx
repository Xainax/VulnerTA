import React, { useState } from "react";

export default function Dashboard() {
  const [repoLink, setRepoLink] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!repoLink) return;
    setLoading(true);
    setError("");
    try {
      const res = await fetch("http://127.0.0.1:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_link: repoLink }),
      });
      if (!res.ok) throw new Error("Scan failed");
      const data = await res.json();
      setScanResult(data);
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  };

  return (
    <div style={{ padding: "2rem" }}>
      <h1>VulnerTA Dashboard</h1>
      <div style={{ marginTop: "1rem" }}>
        <input
          type="text"
          placeholder="Enter GitHub repo URL"
          value={repoLink}
          onChange={(e) => setRepoLink(e.target.value)}
          style={{ width: "300px", marginRight: "1rem" }}
        />
        <button onClick={handleScan}>Scan Repo</button>
      </div>

      {loading && <p>Scanning...</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}
      {scanResult && (
        <div style={{ marginTop: "2rem" }}>
          <h2>Scan Result for {scanResult.repo}</h2>
          <p>Python files found: {scanResult.python_files}</p>
          <ul>
            {scanResult.files.map((file) => (
              <li key={file.path}>{file.path} ({file.size} bytes)</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

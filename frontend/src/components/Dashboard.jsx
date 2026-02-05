import React, { useState } from "react";

export default function Dashboard() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSearch = async () => {
    if (!query.trim()) return;

    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://127.0.0.1:8000/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query,
          top_k: 10
        })
      });

      if (!res.ok) throw new Error("Search failed");

      const data = await res.json();
      setResults(data.hits || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "2rem", maxWidth: 1100, margin: "auto" }}>
      <h1>VulnerTA — AI Vulnerability Search</h1>

      <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
        <input
          type="text"
          placeholder="Search vulnerabilities, CVEs, CWEs, code patterns..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSearch()}
          style={{
            flex: 1,
            padding: 12,
            fontSize: 16,
            borderRadius: 6,
            border: "1px solid #ccc"
          }}
        />
        <button
          onClick={handleSearch}
          style={{
            padding: "12px 18px",
            fontSize: 16,
            borderRadius: 6,
            background: "black",
            color: "white",
            border: "none"
          }}
        >
          Search
        </button>
      </div>

      {loading && <p style={{ marginTop: 16 }}>Searching...</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}

      <div style={{ marginTop: 24 }}>
        {results.map((hit, i) => (
          <div
            key={i}
            style={{
              border: "1px solid #ddd",
              borderRadius: 8,
              padding: 16,
              marginBottom: 16
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <strong>{hit.meta?.file_path}</strong>
              <span
                style={{
                  color:
                    hit.meta?.severity?.includes("high") ? "red" :
                    hit.meta?.severity?.includes("medium") ? "orange" : "green"
                }}
              >
                {hit.meta?.severity}
              </span>
            </div>

            <div style={{ fontSize: 13, color: "#555", marginTop: 4 }}>
              Tool: {hit.meta?.tool} | Rule: {hit.meta?.rule_id}
            </div>

            <pre
              style={{
                background: "#1e1e1e",
                color: "#f5f5f5",
                padding: 12,
                borderRadius: 6,
                marginTop: 10,
                fontSize: 13,
                overflowX: "auto",
              }}
            >
              {hit.text}
            </pre>

            <div style={{ marginTop: 10 }}>
              {hit.meta?.cwe_ids?.map((cwe) => (
                <span
                  key={cwe}
                  style={{
                    background: "#ffe5e5",
                    color: "#b00020",
                    padding: "4px 8px",
                    borderRadius: 6,
                    marginRight: 6,
                    fontSize: 12
                  }}
                >
                  {cwe}
                </span>
              ))}
            </div>

            <div style={{ marginTop: 8, fontSize: 12, color: "#444" }}>
              Related CVEs: {hit.meta?.cve_ids?.slice(0, 5).join(", ")}
            </div>

            <div style={{ marginTop: 12, display: "flex", gap: 10 }}>
              <button>Explain Risk</button>
              <button>Generate Patch</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

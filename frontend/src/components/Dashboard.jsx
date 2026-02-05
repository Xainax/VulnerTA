import React, { useState } from "react";

export default function Dashboard() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [answerLoading, setAnswerLoading] = useState(false);
  const [answerError, setAnswerError] = useState("");
  const [answer, setAnswer] = useState(null);
  const [showModal, setShowModal] = useState(false);

  const handleSearch = async () => {
    if (!query.trim()) return;

    setLoading(true);
    setError("");
    setResults([]);
    setAnswer(null);
    setShowModal(false);

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

  const handleExplainRisk = async (hit) => {
    setAnswerLoading(true);
    setAnswerError("");
    setAnswer(null);
    setShowModal(true);

    try {
      const question = `Bandit flagged ${hit.meta.rule_id} in ${hit.meta.file_path}:${hit.meta.line_start}-${hit.meta.line_end}. Explain the risk and suggest a minimal patch diff.`;

      const res = await fetch("http://127.0.0.1:8000/answer", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, top_k: 5 })
      });

      if (!res.ok) throw new Error("Failed to get answer");

      const data = await res.json();
      setAnswer(data);
    } catch (e) {
      setAnswerError(e.message);
    } finally {
      setAnswerLoading(false);
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

      {/* Search results */}
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
                    hit.meta?.severity?.toLowerCase().includes("high") ? "red" :
                    hit.meta?.severity?.toLowerCase().includes("medium") ? "orange" : "green"
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
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                fontFamily: "monospace",
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
              <button onClick={() => handleExplainRisk(hit)}>Explain Risk</button>
              <button>Generate Patch</button>
            </div>
          </div>
        ))}
      </div>

      {/* Modal */}
      {showModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100vw",
            height: "100vh",
            background: "rgba(0,0,0,0.6)",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            zIndex: 9999
          }}
          onClick={() => setShowModal(false)}
        >
          <div
            style={{
              background: "#1e1e1e",
              color: "#f5f5f5",
              padding: 24,
              borderRadius: 10,
              width: "80%",
              maxHeight: "80%",
              overflowY: "auto",
              boxShadow: "0 0 20px rgba(0,0,0,0.5)"
            }}
            onClick={(e) => e.stopPropagation()} // Prevent closing when clicking inside
          >
            <button
              onClick={() => setShowModal(false)}
              style={{
                float: "right",
                background: "red",
                color: "white",
                border: "none",
                borderRadius: 6,
                padding: "4px 10px",
                cursor: "pointer",
                marginBottom: 16
              }}
            >
              Close
            </button>

            {answerLoading && <p>Generating explanation...</p>}
            {answerError && <p style={{ color: "red" }}>{answerError}</p>}
            {answer && (
              <>
                <h3>Explanation:</h3>
                <p>{answer.answer}</p>

                <h4>Citations:</h4>
                <ul>
                  {answer.citations.map((c) => (
                    <li key={c.doc_id}>
                      {c.file_path}:{c.line_start}-{c.line_end} | {c.rule_id} | CWEs: {c.cwe_ids.join(", ")} | CVEs: {c.cve_ids.join(", ")}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

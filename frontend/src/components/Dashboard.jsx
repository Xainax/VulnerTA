import React, { useState } from "react";
import RepositorySelector from "./RepositorySelector";
import FileExplorer from "./FileExplorer";

export default function Dashboard() {
  const [selectedRepo, setSelectedRepo] = useState(null);
  const [view, setView] = useState("tabs"); // tabs | selector | explorer | search | vuln-search
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [highlightLines, setHighlightLines] = useState([]);

  // new analysis state
  const [analysis, setAnalysis] = useState(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisError, setAnalysisError] = useState("");

  const [answerLoading, setAnswerLoading] = useState(false);
  const [answerError, setAnswerError] = useState("");
  const [answer, setAnswer] = useState(null);
  const [report, setReport] = useState(null);
  const [reportError, setReportError] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);

  const rawBackendUrl = import.meta.env.VITE_BACKEND_URL;
  const backendUrl = rawBackendUrl && rawBackendUrl !== "/"
    ? rawBackendUrl.replace(/\/$/, "")
    : "http://127.0.0.1:8000";

  const handleSelectRepo = async (repo) => {
    console.log("Selected repo:", repo);
    console.log("Backend URL:", backendUrl);
    setSelectedRepo(repo);
    setAnalysis(null);
    setAnalysisError("");
    setAnalysisLoading(true);
    try {
      console.log("Starting scan request...");
      const token = localStorage.getItem("token");
      const res = await fetch(`${backendUrl}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_link: repo.url, github_token: token })
      });
      console.log("Scan response status:", res.status);
      if (!res.ok) throw new Error(`Scan failed (${res.status})`);
      const data = await res.json();
      console.log("Scan response data:", data);
      setAnalysis(data.analysis);
      console.log("Analysis set successfully");

      const analysisContext = buildAnalysisContext(data.analysis);
      await generateRepoReport(analysisContext);
    } catch (e) {
      console.error("Scan error:", e);
      setAnalysisError(e.message);
    } finally {
      console.log("Setting analysisLoading to false");
      setAnalysisLoading(false);
    }

    setView("explorer");
    setSelectedFile(null);
    setHighlightLines([]);
  };

  const handleBackToSelector = () => {
    setView("tabs");
    setSelectedRepo(null);
    setSelectedFile(null);
  };

  const handleSearch = async () => {
    if (!query.trim()) return;

    setLoading(true);
    setError("");
    setResults([]);
    setAnswer(null);
    setShowModal(false);

    try {
      const res = await fetch(`${backendUrl}/search`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query,
          top_k: 50
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

  const formatFindingSummary = (label, findings) => {
    if (!findings) return `${label}: no findings available.`;
    const taintedFlows = findings.tainted_flows || [];
    const evalExec = findings.eval_exec || [];
    const unsafeWrites = findings.unsafe_writes || [];

    const summarize = (items) => {
      if (!items.length) return "none";
      return items
        .slice(0, 3)
        .map((item) => `line ${item.lineno || "?"}${item.sink ? ` ${item.sink}` : ""}${item.detail ? ` ${item.detail}` : ""}`)
        .join("; ");
    };

    return [
      `${label}: ${taintedFlows.length} tainted flows, ${evalExec.length} eval/exec calls, ${unsafeWrites.length} unsafe writes`,
      `  tainted flows: ${summarize(taintedFlows)}`,
      `  eval/exec: ${summarize(evalExec)}`,
      `  unsafe writes: ${summarize(unsafeWrites)}`,
    ].join("\n");
  };

  const buildAnalysisContext = (analysisData = analysis) => {
    if (!analysisData) return "";

    const formatTopFiles = (label, files) => {
      if (!files?.length) return `${label}: no per-file results available.`;
      const topFiles = files
        .slice()
        .sort((a, b) => (b.risk || 0) - (a.risk || 0))
        .slice(0, 5)
        .map((file) => {
          const counts = file.counts || {};
          return `${file.file}: risk=${file.risk || 0}, tainted_flows=${counts.tainted_flows || 0}, eval_exec=${counts.eval_exec || 0}, unsafe_writes=${counts.unsafe_writes || 0}`;
        });
      return `${label}: ${files.length} files analyzed. Top files:\n${topFiles.join("\n")}`;
    };

    const astSummary = `AST analysis summary:\nFiles analyzed: ${analysisData.ast?.files_analyzed || 0}\nRisk score: ${analysisData.ast?.risk_score || 0}\nCounts: ${JSON.stringify(analysisData.ast?.counts || {})}`;
    const pycfgSummary = `PyCFG analysis summary:\nFiles analyzed: ${analysisData.pycfg?.files_analyzed || 0}\nRisk score: ${analysisData.pycfg?.risk_score || 0}\nCounts: ${JSON.stringify(analysisData.pycfg?.counts || {})}`;

    return [
      astSummary,
      formatTopFiles("AST top files", analysisData.ast?.files),
      formatFindingSummary("AST findings", analysisData.ast?.findings),
      pycfgSummary,
      formatTopFiles("PyCFG top files", analysisData.pycfg?.files),
      formatFindingSummary("PyCFG findings", analysisData.pycfg?.findings),
    ].join("\n\n");
  };

  const generateRepoReport = async (analysis_context) => {
    setAnswerLoading(true);
    setAnswerError("");
    setReportError("");
    setAnswer(null);
    setReport(null);

    try {
      const question = "Create a vulnerability report based on the repository scan findings. Summarize the main issues, likely root causes, risk levels, and recommended fixes.";
      const res = await fetch(`${backendUrl}/answer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, top_k: 50, analysis_context })
      });

      const text = await res.text();
      if (!res.ok) {
        throw new Error(`Report generation failed (${res.status}): ${text}`);
      }

      let data;
      try {
        data = JSON.parse(text);
      } catch (parseError) {
        throw new Error(`Failed to parse report response: ${parseError.message}`);
      }

      setReport(data);
    } catch (e) {
      setReportError(e.message || String(e));
    } finally {
      setAnswerLoading(false);
    }
  };

  const handleExplainRisk = async (hit) => {
    setAnswerLoading(true);
    setAnswerError("");
    setAnswer(null);
    setShowModal(true);

    try {
      const question = `Bandit flagged ${hit.meta.rule_id} in ${hit.meta.file_path}:${hit.meta.line_start}-${hit.meta.line_end}. Explain the risk and suggest a minimal patch diff.`;
      const analysis_context = buildAnalysisContext();

      const res = await fetch(`${backendUrl}/answer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, top_k: 50, analysis_context })
      });

      const text = await res.text();
      if (!res.ok) {
        throw new Error(`Failed to get answer (${res.status}): ${text}`);
      }

      let data;
      try {
        data = JSON.parse(text);
      } catch (parseError) {
        throw new Error(`Failed to parse answer response: ${parseError.message}`);
      }

      console.log("Answer response:", data);
      setAnswer(data);
    } catch (e) {
      setAnswerError(e.message);
    } finally {
      setAnswerLoading(false);
    }
  };

  const handleGeneratePatch = async (hit) => {
    setAnswerLoading(true);
    setAnswerError("");
    setAnswer(null);
    setShowModal(true);

    try {
      const analysis_context = buildAnalysisContext();
      const res = await fetch(`${backendUrl}/patch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: hit.meta?.rule_id ?? "",
          file_path: hit.meta?.file_path ?? "",
          line_start: hit.meta?.line_start ?? null,
          line_end: hit.meta?.line_end ?? null,
          code_snippet: hit.text ?? "",
          vulnerability_description: hit.meta?.message ?? "",
          analysis_context,
          top_k: 50,
          filters: {}
        })
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`Patch failed (${res.status}): ${text}`);
      }

      const data = await res.json();

      setAnswer({
        answer: data.explanation,
        patch: data.patch,
        citations: data.citations || []
      });
    } catch (e) {
      setAnswerError(e.message);
    } finally {
      setAnswerLoading(false);
    }
  };

  const openFileWithHighlight = (hit) => {
    setSelectedFile({
      path: hit.meta.file_path,
      repo: selectedRepo.name,
      owner: selectedRepo.owner
    });
    const lineStart = hit.meta.line_start;
    const lineEnd = hit.meta.line_end;
    const lines = [];
    if (lineStart && lineEnd) {
      for (let i = lineStart; i <= lineEnd; i++) {
        lines.push(i);
      }
    } else if (lineStart) {
      lines.push(lineStart);
    }
    setHighlightLines(lines);
    setView("explorer");
  };

  // Repository Selector View
  if (view === "selector") {
    return <RepositorySelector onSelectRepo={handleSelectRepo} onBack={() => setView("tabs")} analyzing={analysisLoading} />;
  }

  // Standalone Vulnerability Search View
  if (view === "vuln-search") {
    return (
      <div style={{ minHeight: "100vh" }}>
        {/* Top Navigation */}
        <div style={{
          backgroundColor: '#1a1a1a',
          color: 'white',
          padding: '1rem 2rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <h1 style={{ margin: 0, fontSize: '1.3rem' }}>VulnerTA</h1>
          <button
            onClick={() => setView("tabs")}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: '#666',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            ← Back
          </button>
        </div>

        {/* Search Content */}
        <div style={{ padding: '2rem' }}>
          <div style={{ maxWidth: "1100px", margin: "auto" }}>
            <h1>AI Vulnerability Search</h1>
            <p style={{ color: "#666", marginBottom: "2rem" }}>
              Search across vulnerability databases, CVEs, and code patterns
            </p>

            <div style={{ display: "flex", gap: "1rem", marginTop: "1rem", marginBottom: "2rem" }}>
              <input
                type="text"
                placeholder="Search vulnerabilities, CVEs, CWEs, code patterns..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                style={{
                  flex: 1,
                  padding: "0.75rem",
                  fontSize: "1rem",
                  borderRadius: "6px",
                  border: "1px solid #ccc"
                }}
              />
              <button
                onClick={handleSearch}
                disabled={loading}
                style={{
                  padding: "0.75rem 1.5rem",
                  fontSize: "1rem",
                  borderRadius: "6px",
                  backgroundColor: loading ? "#ccc" : "black",
                  color: "white",
                  border: "none",
                  cursor: loading ? "not-allowed" : "pointer"
                }}
              >
                {loading ? "Searching..." : "Search"}
              </button>
            </div>

            {loading && (
              <div style={{ marginTop: "2rem", textAlign: "center" }}>
                <svg
                  width="40"
                  height="40"
                  viewBox="0 0 40 40"
                  style={{
                    animation: "spin 1s linear infinite",
                    display: "inline-block"
                  }}
                >
                  <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
                  <circle
                    cx="20"
                    cy="20"
                    r="18"
                    fill="none"
                    stroke="black"
                    strokeWidth="2"
                    strokeDasharray="28.3 113.1"
                  />
                </svg>
              </div>
            )}

            {error && <p style={{ color: "red", fontSize: "1rem" }}>❌ {error}</p>}

            {/* Search Results */}
            <div style={{ marginTop: "2rem" }}>
              {results.map((hit, i) => (
                <div
                  key={i}
                  style={{
                    border: "1px solid #ddd",
                    borderRadius: "8px",
                    padding: "1rem",
                    marginBottom: "1rem",
                    backgroundColor: "#f9f9f9"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong style={{ fontSize: "1.1rem" }}>{hit.meta?.file_path}</strong>
                    <span
                      style={{
                        backgroundColor:
                          hit.meta?.severity?.toLowerCase().includes("high") ? "#ef5350" :
                          hit.meta?.severity?.toLowerCase().includes("medium") ? "#ffa726" : "#42a5f5",
                        color: "white",
                        padding: "0.25rem 0.75rem",
                        borderRadius: "4px",
                        fontSize: "0.9rem",
                        fontWeight: "bold"
                      }}
                    >
                      {hit.meta?.severity}
                    </span>
                  </div>

                  <div style={{ fontSize: "0.9rem", color: "#555", marginTop: "0.5rem" }}>
                    Tool: {hit.meta?.tool} | Rule: {hit.meta?.rule_id} | Lines: {hit.meta?.line_start}-{hit.meta?.line_end}
                  </div>

                  <pre
                    style={{
                      background: "#1e1e1e",
                      color: "#f5f5f5",
                      padding: "1rem",
                      borderRadius: "6px",
                      marginTop: "1rem",
                      fontSize: "0.85rem",
                      overflowX: "auto",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                      fontFamily: "monospace"
                    }}
                  >
                    {hit.text}
                  </pre>

                  {hit.meta?.cwe_ids?.length > 0 && (
                    <div style={{ marginTop: "0.75rem", display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
                      {hit.meta?.cwe_ids?.map((cwe) => (
                        <span
                          key={cwe}
                          style={{
                            background: "#ffe5e5",
                            color: "#b00020",
                            padding: "0.25rem 0.5rem",
                            borderRadius: "4px",
                            fontSize: "0.8rem"
                          }}
                        >
                          {cwe}
                        </span>
                      ))}
                    </div>
                  )}

                  {hit.meta?.cve_ids?.length > 0 && (
                    <div style={{ marginTop: "0.5rem", fontSize: "0.85rem", color: "#666" }}>
                      Related CVEs: {hit.meta?.cve_ids?.slice(0, 5).join(", ")}
                    </div>
                  )}

                  <div style={{ marginTop: "1rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                    <button
                      onClick={() => handleExplainRisk(hit)}
                      style={{
                        padding: "0.5rem 1rem",
                        fontSize: "0.9rem",
                        borderRadius: "4px",
                        backgroundColor: "#0366d6",
                        color: "white",
                        border: "none",
                        cursor: "pointer"
                      }}
                    >
                       Explain Risk
                    </button>
                    <button
                      onClick={() => handleGeneratePatch(hit)}
                      style={{
                        padding: "0.5rem 1rem",
                        fontSize: "0.9rem",
                        borderRadius: "4px",
                        backgroundColor: "#28a745",
                        color: "white",
                        border: "none",
                        cursor: "pointer"
                      }}
                    >
                       Generate Patch
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Answer Modal */}
            {showModal && (
              <div
                style={{
                  position: "fixed",
                  top: 0,
                  left: 0,
                  width: "100vw",
                  height: "100vh",
                  backgroundColor: "rgba(0, 0, 0, 0.6)",
                  display: "flex",
                  justifyContent: "center",
                  alignItems: "center",
                  zIndex: 9999
                }}
                onClick={() => setShowModal(false)}
              >
                <div
                  style={{
                    backgroundColor: "#1e1e1e",
                    color: "#f5f5f5",
                    padding: "2rem",
                    borderRadius: "10px",
                    width: "80%",
                    maxHeight: "80vh",
                    overflowY: "auto",
                    boxShadow: "0 0 20px rgba(0, 0, 0, 0.5)"
                  }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <button
                    onClick={() => setShowModal(false)}
                    style={{
                      float: "right",
                      background: "red",
                      color: "white",
                      border: "none",
                      borderRadius: "6px",
                      padding: "0.5rem 1rem",
                      cursor: "pointer",
                      marginBottom: "1rem"
                    }}
                  >
                    ✕ Close
                  </button>

                  {answerLoading && <p> Generating explanation...</p>}
                  {answerError && <p style={{ color: "#ff6b6b" }}>❌ {answerError}</p>}
                  {answer && (
                    <>
                      <h3> Explanation:</h3>
                      <p style={{ lineHeight: "1.6" }}>
                        {typeof answer === "string"
                          ? answer
                          : answer.answer || JSON.stringify(answer, null, 2)}
                      </p>
                      {answer.patch && (
                        <>
                          <h3>Suggested Patch:</h3>
                          <pre style={{
                            whiteSpace: "pre-wrap",
                            background: "#111",
                            padding: "1rem",
                            borderRadius: "8px",
                            overflowX: "auto",
                            fontSize: "0.85rem"
                          }}>
                            {answer.patch}
                          </pre>
                        </>
                      )}
                      {answer.citations?.length > 0 && (
                        <>
                          <h4>Citations:</h4>
                          <ul style={{ fontSize: "0.9rem", color: "#aaa" }}>
                            {answer.citations.map((c) => (
                              <li key={c.doc_id}>
                                <strong>{c.file_path}</strong>:{c.line_start}-{c.line_end} | {c.rule_id}
                                {c.cwe_ids?.length > 0 && ` | CWEs: ${c.cwe_ids.join(", ")}`}
                                {c.cve_ids?.length > 0 && ` | CVEs: ${c.cve_ids.join(", ")}`}
                              </li>
                            ))}
                          </ul>
                        </>
                      )}
                    </>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // Top-level tabs view
  if (view === "tabs") {
    return (
      <div style={{ minHeight: "100vh" }}>
        <div style={{
          backgroundColor: '#1a1a1a',
          color: 'white',
          padding: '2rem'
        }}>
          <h1 style={{ margin: '0 0 2rem 0' }}>VulnerTA</h1>
          <div style={{ display: 'flex', gap: '1rem' }}>
            <button
              onClick={() => setView("selector")}
              style={{
                padding: '1rem 2rem',
                fontSize: '1.1rem',
                borderRadius: '6px',
                backgroundColor: '#0366d6',
                color: 'white',
                border: 'none',
                cursor: 'pointer',
                fontWeight: 'bold'
              }}
            >
              📁 Browse Repositories
            </button>
            <button
              onClick={() => {
                setView("vuln-search");
                setQuery("");
                setResults([]);
                setError("");
              }}
              style={{
                padding: '1rem 2rem',
                fontSize: '1.1rem',
                borderRadius: '6px',
                backgroundColor: '#28a745',
                color: 'white',
                border: 'none',
                cursor: 'pointer',
                fontWeight: 'bold'
              }}
            >
              🔍 Search Vulnerabilities
            </button>
          </div>
        </div>
      </div>
    );
  }
  return (
    <div style={{ minHeight: "100vh" }}>
      {/* Header */}
      <div style={{
        backgroundColor: '#1a1a1a',
        color: 'white',
        padding: '1rem 2rem',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.3rem' }}> {selectedRepo?.name}</h1>
          <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.9rem', color: '#999' }}>
            {selectedRepo?.owner}
          </p>
        </div>
        <button
          onClick={handleBackToSelector}
          style={{
            padding: '0.5rem 1rem',
            backgroundColor: '#666',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          ← Back to Repos
        </button>
      </div>

      {/* View Tabs */}
      <div style={{ 
        display: 'flex', 
        gap: '1rem', 
        padding: '1rem 2rem',
        backgroundColor: '#f5f5f5',
        borderBottom: '1px solid #ddd'
      }}>
        <button
          onClick={() => setView("explorer")}
          style={{
            padding: '0.75rem 1.5rem',
            fontSize: '1rem',
            borderRadius: '6px',
            backgroundColor: view === "explorer" ? "#0366d6" : "#e0e0e0",
            color: view === "explorer" ? "white" : "black",
            border: "none",
            cursor: "pointer",
            fontWeight: view === "explorer" ? "bold" : "normal"
          }}
        >
           Code Explorer
        </button>
        <button
          onClick={() => setView("search")}
          style={{
            padding: '0.75rem 1.5rem',
            fontSize: '1rem',
            borderRadius: '6px',
            backgroundColor: view === "search" ? "#0366d6" : "#e0e0e0",
            color: view === "search" ? "white" : "black",
            border: "none",
            cursor: "pointer",
            fontWeight: view === "search" ? "bold" : "normal"
          }}
        >
           Vulnerability Search
        </button>
      </div>

      {/* Content */}
      <div style={{ padding: '2rem' }}>
        {/* Explorer View */}
        {view === "explorer" && selectedRepo && (
          <>
            {analysisLoading && (
              <div style={{
                position: 'fixed',
                top: 0,
                left: 0,
                width: '100vw',
                height: '100vh',
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'center',
                zIndex: 9999,
                color: 'white'
              }}>
                <div style={{ textAlign: 'center' }}>
                  <svg
                    width="60"
                    height="60"
                    viewBox="0 0 40 40"
                    style={{
                      animation: "spin 1s linear infinite",
                      display: "block",
                      margin: "0 auto 1.5rem"
                    }}
                  >
                    <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
                    <circle
                      cx="20"
                      cy="20"
                      r="18"
                      fill="none"
                      stroke="white"
                      strokeWidth="3"
                      strokeDasharray="28.3 113.1"
                    />
                  </svg>
                  <h2 style={{ margin: '0 0 1rem 0', fontSize: '1.5rem' }}>Analyzing Repository</h2>
                  <p style={{ margin: 0, fontSize: '1.1rem', opacity: 0.9 }}>
                    Scanning {selectedRepo.name} for security vulnerabilities...
                  </p>
                  <p style={{ margin: '1rem 0 0 0', fontSize: '0.9rem', opacity: 0.7 }}>
                    This may take a few moments depending on repository size.
                  </p>
                </div>
              </div>
            )}
            {analysisError && <p style={{color:'red'}}>Error during analysis: {analysisError}</p>}
            {analysis && (
              <div style={{ marginBottom: '2rem', maxWidth: '800px' }}>
                <h2>Analysis Summary</h2>
                <div style={{ display: 'flex', gap: '2rem', marginBottom: '1rem' }}>
                  <div>
                    <h3>AST Analysis</h3>
                    <p>Files analyzed: {analysis.ast?.files_analyzed || 0}</p>
                    <p>Risk score: {analysis.ast?.risk_score || 0}</p>
                  </div>
                  <div>
                    <h3>PyCFG Analysis</h3>
                    <p>Files analyzed: {analysis.pycfg?.files_analyzed || 0}</p>
                    <p>Risk score: {analysis.pycfg?.risk_score || 0}</p>
                  </div>
                </div>
                <h3>Vulnerability Counts</h3>
                <div style={{ display: 'flex', gap: '2rem' }}>
                  <div>
                    <h4>AST Findings</h4>
                    {analysis.ast?.counts && Object.entries(analysis.ast.counts).map(([cat, count]) => {
                      const max = Math.max(...Object.values(analysis.ast.counts));
                      const pct = max > 0 ? (count / max) * 100 : 0;
                      return (
                        <div key={cat} style={{ marginBottom: '0.5rem' }}>
                          <strong>{cat.replace(/_/g,' ')}</strong>: {count}
                          <div style={{ background: '#eee', width: '100%', height: '8px', borderRadius:'4px', overflow:'hidden' }}>
                            <div style={{ background: '#4287f5', width: `${pct}%`, height: '100%' }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  <div>
                    <h4>PyCFG Findings</h4>
                    {analysis.pycfg?.counts && Object.entries(analysis.pycfg.counts).map(([cat, count]) => {
                      const max = Math.max(...Object.values(analysis.pycfg.counts));
                      const pct = max > 0 ? (count / max) * 100 : 0;
                      return (
                        <div key={cat} style={{ marginBottom: '0.5rem' }}>
                          <strong>{cat.replace(/_/g,' ')}</strong>: {count}
                          <div style={{ background: '#eee', width: '100%', height: '8px', borderRadius:'4px', overflow:'hidden' }}>
                            <div style={{ background: '#ff9800', width: `${pct}%`, height: '100%' }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}
            {report && (
              <div style={{ marginBottom: '2rem', maxWidth: '800px', padding: '1rem', borderRadius: '10px', backgroundColor: '#f9fafb', border: '1px solid #d8e2ea' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
                  <div>
                    <h2 style={{ margin: 0 }}>Vulnerability Report</h2>
                    <p style={{ margin: '0.5rem 0 0 0', color: '#555' }}>
                      A full vulnerability report is ready for this repository.
                    </p>
                  </div>
                  <button
                    onClick={() => setShowReportModal(true)}
                    style={{
                      padding: '0.75rem 1.2rem',
                      borderRadius: '8px',
                      border: 'none',
                      backgroundColor: '#0366d6',
                      color: 'white',
                      cursor: 'pointer',
                      fontWeight: 'bold'
                    }}
                  >
                    View report
                  </button>
                </div>
              </div>
            )}
            {answerLoading && !report && (
              <div style={{ marginBottom: '2rem', maxWidth: '800px', padding: '1rem', borderRadius: '10px', backgroundColor: '#fff8e1', border: '1px solid #ffecb3', color: '#795548' }}>
                Generating vulnerability report...
              </div>
            )}
            {reportError && (
              <p style={{ color: 'red', marginBottom: '1rem' }}>Report generation failed: {reportError}</p>
            )}
            {showReportModal && report && (
              <div
                style={{
                  position: 'fixed',
                  top: 0,
                  left: 0,
                  width: '100vw',
                  height: '100vh',
                  backgroundColor: 'rgba(0, 0, 0, 0.65)',
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  zIndex: 9999,
                  padding: '1rem'
                }}
                onClick={() => setShowReportModal(false)}
              >
                <div
                  style={{
                    position: 'relative',
                    width: 'min(900px, 100%)',
                    maxHeight: '90vh',
                    backgroundColor: 'white',
                    borderRadius: '16px',
                    padding: '1.5rem',
                    overflowY: 'auto',
                    boxShadow: '0 24px 80px rgba(0,0,0,0.25)'
                  }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <button
                    onClick={() => setShowReportModal(false)}
                    style={{
                      position: 'absolute',
                      top: '1rem',
                      right: '1rem',
                      border: 'none',
                      background: 'transparent',
                      fontSize: '1.4rem',
                      cursor: 'pointer',
                      color: '#333'
                    }}
                  >
                    ×
                  </button>
                  <h2 style={{ marginTop: 0, marginBottom: '0.5rem' }}>Full Vulnerability Report</h2>
                  <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.6, color: '#111' }}>
                    {typeof report === 'string' ? report : report.answer || JSON.stringify(report, null, 2)}
                  </div>
                </div>
              </div>
            )}
            <FileExplorer
              repo={selectedRepo.name}
              owner={selectedRepo.owner}
              branch={selectedRepo.defaultBranch}
              selectedFile={selectedFile}
              setSelectedFile={setSelectedFile}
              highlightLines={highlightLines}
              setHighlightLines={setHighlightLines}
            />
          </>
        )}

        {/* Search View */}
        {view === "search" && (
          <div style={{ maxWidth: "1100px", margin: "auto" }}>
            <h1>VulnerTA — AI Vulnerability Search</h1>

            <div style={{ display: "flex", gap: "1rem", marginTop: "1rem", marginBottom: "2rem" }}>
              <input
                type="text"
                placeholder="Search vulnerabilities, CVEs, CWEs, code patterns..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                style={{
                  flex: 1,
                  padding: "0.75rem",
                  fontSize: "1rem",
                  borderRadius: "6px",
                  border: "1px solid #ccc"
                }}
              />
              <button
                onClick={handleSearch}
                disabled={loading}
                style={{
                  padding: "0.75rem 1.5rem",
                  fontSize: "1rem",
                  borderRadius: "6px",
                  backgroundColor: loading ? "#ccc" : "black",
                  color: "white",
                  border: "none",
                  cursor: loading ? "not-allowed" : "pointer"
                }}
              >
                {loading ? "Searching..." : "Search"}
              </button>
            </div>

            {loading && (
              <div style={{ marginTop: "2rem", textAlign: "center" }}>
                <svg
                  width="40"
                  height="40"
                  viewBox="0 0 40 40"
                  style={{
                    animation: "spin 1s linear infinite",
                    display: "inline-block"
                  }}
                >
                  <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
                  <circle
                    cx="20"
                    cy="20"
                    r="18"
                    fill="none"
                    stroke="black"
                    strokeWidth="2"
                    strokeDasharray="28.3 113.1"
                  />
                </svg>
              </div>
            )}

            {error && <p style={{ color: "red", fontSize: "1rem" }}>❌ {error}</p>}

            {/* Search Results */}
            <div style={{ marginTop: "2rem" }}>
              {results.map((hit, i) => (
                <div
                  key={i}
                  style={{
                    border: "1px solid #ddd",
                    borderRadius: "8px",
                    padding: "1rem",
                    marginBottom: "1rem",
                    backgroundColor: "#f9f9f9"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong style={{ fontSize: "1.1rem" }}>{hit.meta?.file_path}</strong>
                    <span
                      style={{
                        backgroundColor:
                          hit.meta?.severity?.toLowerCase().includes("high") ? "#ef5350" :
                          hit.meta?.severity?.toLowerCase().includes("medium") ? "#ffa726" : "#42a5f5",
                        color: "white",
                        padding: "0.25rem 0.75rem",
                        borderRadius: "4px",
                        fontSize: "0.9rem",
                        fontWeight: "bold"
                      }}
                    >
                      {hit.meta?.severity}
                    </span>
                  </div>

                  <div style={{ fontSize: "0.9rem", color: "#555", marginTop: "0.5rem" }}>
                    Tool: {hit.meta?.tool} | Rule: {hit.meta?.rule_id} | Lines: {hit.meta?.line_start}-{hit.meta?.line_end}
                  </div>

                  <pre
                    style={{
                      background: "#1e1e1e",
                      color: "#f5f5f5",
                      padding: "1rem",
                      borderRadius: "6px",
                      marginTop: "1rem",
                      fontSize: "0.85rem",
                      overflowX: "auto",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                      fontFamily: "monospace"
                    }}
                  >
                    {hit.text}
                  </pre>

                  {hit.meta?.cwe_ids?.length > 0 && (
                    <div style={{ marginTop: "0.75rem", display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
                      {hit.meta?.cwe_ids?.map((cwe) => (
                        <span
                          key={cwe}
                          style={{
                            background: "#ffe5e5",
                            color: "#b00020",
                            padding: "0.25rem 0.5rem",
                            borderRadius: "4px",
                            fontSize: "0.8rem"
                          }}
                        >
                          {cwe}
                        </span>
                      ))}
                    </div>
                  )}

                  {hit.meta?.cve_ids?.length > 0 && (
                    <div style={{ marginTop: "0.5rem", fontSize: "0.85rem", color: "#666" }}>
                      Related CVEs: {hit.meta?.cve_ids?.slice(0, 5).join(", ")}
                    </div>
                  )}

                  <div style={{ marginTop: "1rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                    <button
                      onClick={() => handleExplainRisk(hit)}
                      style={{
                        padding: "0.5rem 1rem",
                        fontSize: "0.9rem",
                        borderRadius: "4px",
                        backgroundColor: "#0366d6",
                        color: "white",
                        border: "none",
                        cursor: "pointer"
                      }}
                    >
                       Explain Risk
                    </button>
                    <button
                      onClick={() => handleGeneratePatch(hit)}
                      style={{
                        padding: "0.5rem 1rem",
                        fontSize: "0.9rem",
                        borderRadius: "4px",
                        backgroundColor: "#28a745",
                        color: "white",
                        border: "none",
                        cursor: "pointer"
                      }}
                    >
                       Generate Patch
                    </button>
                    <button
                      onClick={() => openFileWithHighlight(hit)}
                      style={{
                        padding: "0.5rem 1rem",
                        fontSize: "0.9rem",
                        borderRadius: "4px",
                        backgroundColor: "#6f42c1",
                        color: "white",
                        border: "none",
                        cursor: "pointer"
                      }}
                    >
                       View in Code
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Answer Modal */}
            {showModal && (
              <div
                style={{
                  position: "fixed",
                  top: 0,
                  left: 0,
                  width: "100vw",
                  height: "100vh",
                  backgroundColor: "rgba(0, 0, 0, 0.6)",
                  display: "flex",
                  justifyContent: "center",
                  alignItems: "center",
                  zIndex: 9999
                }}
                onClick={() => setShowModal(false)}
              >
                <div
                  style={{
                    backgroundColor: "#1e1e1e",
                    color: "#f5f5f5",
                    padding: "2rem",
                    borderRadius: "10px",
                    width: "80%",
                    maxHeight: "80vh",
                    overflowY: "auto",
                    boxShadow: "0 0 20px rgba(0, 0, 0, 0.5)"
                  }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <button
                    onClick={() => setShowModal(false)}
                    style={{
                      float: "right",
                      background: "red",
                      color: "white",
                      border: "none",
                      borderRadius: "6px",
                      padding: "0.5rem 1rem",
                      cursor: "pointer",
                      marginBottom: "1rem"
                    }}
                  >
                    ✕ Close
                  </button>

                  {answerLoading && <p> Generating explanation...</p>}
                  {answerError && <p style={{ color: "#ff6b6b" }}>❌ {answerError}</p>}
                  {answer && (
                    <>
                      <h3> Explanation:</h3>
                      <p style={{ lineHeight: "1.6" }}>
                        {typeof answer === "string"
                          ? answer
                          : answer.answer || JSON.stringify(answer, null, 2)}
                      </p>
                      {answer.patch && (
                        <>
                          <h3>Suggested Patch:</h3>
                          <pre style={{
                            whiteSpace: "pre-wrap",
                            background: "#111",
                            padding: "1rem",
                            borderRadius: "8px",
                            overflowX: "auto",
                            fontSize: "0.85rem"
                          }}>
                            {answer.patch}
                          </pre>
                        </>
                      )}
                      {answer.citations?.length > 0 && (
                        <>
                          <h4>Citations:</h4>
                          <ul style={{ fontSize: "0.9rem", color: "#aaa" }}>
                            {answer.citations.map((c) => (
                              <li key={c.doc_id}>
                                <strong>{c.file_path}</strong>:{c.line_start}-{c.line_end} | {c.rule_id}
                                {c.cwe_ids?.length > 0 && ` | CWEs: ${c.cwe_ids.join(", ")}`}
                                {c.cve_ids?.length > 0 && ` | CVEs: ${c.cve_ids.join(", ")}`}
                              </li>
                            ))}
                          </ul>
                        </>
                      )}
                    </>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
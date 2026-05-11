import React, { useEffect, useState } from 'react';

export default function CodeViewer({ filePath, repo, owner, highlightLines = [] }) {
  const [fileContent, setFileContent] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [detailModalOpen, setDetailModalOpen] = useState(false);

  const rawBackendUrl = import.meta.env.VITE_BACKEND_URL;
  const backendUrl = rawBackendUrl && rawBackendUrl !== "/"
    ? rawBackendUrl.replace(/\/$/, "")
    : "http://127.0.0.1:8000";

  const fetchFileContent = async () => {
    setLoading(true);
    try {
      const response = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}`,
        {
          headers: {
            'Authorization': `token ${localStorage.getItem("token")}`,
            'Accept': 'application/vnd.github.v3.raw'
          }
        }
      );
      const content = await response.text();
      setFileContent(content);
      await fetchVulnerabilities(filePath);
    } catch (error) {
      console.error('Error fetching file:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchVulnerabilities = async (path) => {
    try {
      const response = await fetch(`${backendUrl}/search`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: path, top_k: 50 })
      });
      const data = await response.json();
      const vulns = data.hits
        ?.filter(hit => hit.meta?.file_path === path)
        .map(hit => ({
          line: hit.meta?.line_start || 0,
          lineEnd: hit.meta?.line_end || hit.meta?.line_start || 0,
          type: hit.meta?.rule_id || 'Unknown',
          severity: hit.meta?.severity?.toLowerCase() || 'low',
          message: hit.meta?.message || extractMessageFromText(hit.text) || '',
          fullText: hit.text || '',
          cweIds: hit.meta?.cwe_ids || [],
          cveIds: hit.meta?.cve_ids || [],
          tool: hit.meta?.tool || '',
          docId: hit.doc_id,
          symbol: hit.meta?.symbol || '',
        })) || [];
      setVulnerabilities(vulns);
    } catch (error) {
      console.error('Error fetching vulnerabilities:', error);
    }
  };

  const extractMessageFromText = (text) => {
    if (!text) return '';
    const match = text.match(/MESSAGE:\s*(.+)/);
    return match ? match[1].trim() : '';
  };

  const extractCodeSnippet = (text) => {
    if (!text) return '';
    const match = text.match(/CODE_SNIPPET:\n([\s\S]*?)(?:\n(?:RELATED_CVES:|$)|$)/);
    return match ? match[1].trim() : '';
  };

  useEffect(() => {
    fetchFileContent();
  }, [filePath]);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return '#ffebee';
      case 'medium': return '#fff3e0';
      case 'low': return '#e3f2fd';
      default: return '#f5f5f5';
    }
  };

  const getSeverityBorderColor = (severity) => {
    switch (severity) {
      case 'high': return '#ef5350';
      case 'medium': return '#ffa726';
      case 'low': return '#42a5f5';
      default: return '#bdbdbd';
    }
  };

  const getSeverityBadgeColor = (severity) => {
    switch (severity) {
      case 'high': return { bg: '#ef5350', text: 'white' };
      case 'medium': return { bg: '#ffa726', text: 'white' };
      case 'low': return { bg: '#42a5f5', text: 'white' };
      default: return { bg: '#757575', text: 'white' };
    }
  };

  const isLineVulnerable = (lineNumber) =>
    vulnerabilities.some(v => v.line === lineNumber);

  const getLineVulnerabilities = (lineNumber) =>
    vulnerabilities.filter(v => v.line === lineNumber);

  const isLineHighlighted = (lineNumber) =>
    highlightLines.includes(lineNumber);

  const getLineTextColor = (highlighted, vulnerable) =>
    highlighted || vulnerable ? '#1e1e1e' : '#d4d4d4';

  const getVulnerabilitySnippet = (vuln, context = 2) => {
    const currentLine = vuln.line || 1;
    const start = Math.max(1, currentLine - context);
    const end = Math.min(lines.length, currentLine + context);
    return lines
      .slice(start - 1, end)
      .map((line, index) => {
        const lineNumber = start + index;
        const marker = lineNumber === currentLine ? '▶' : ' ';
        return `${marker} ${String(lineNumber).padStart(4, ' ')} | ${line}`;
      })
      .join('\n');
  };

  const lines = fileContent.split('\n');

  if (loading) return <div style={{ padding: '2rem' }}>⏳ Loading file...</div>;

  return (
    <div style={{ display: 'flex', gap: '1rem', height: '100%' }}>
      {/* Code Editor */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{
          backgroundColor: '#1e1e1e',
          color: 'white',
          padding: '1rem',
          fontFamily: 'monospace',
          fontSize: '0.9rem',
          borderBottom: '1px solid #ddd'
        }}>
          <span style={{ color: '#666' }}>📦 {repo}</span> / <span style={{ fontWeight: 'bold' }}>📄 {filePath}</span>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', backgroundColor: '#1e1e1e', color: '#d4d4d4' }}>
          {lines.map((line, index) => {
            const lineNumber = index + 1;
            const vulnerable = isLineVulnerable(lineNumber);
            const lineVulns = getLineVulnerabilities(lineNumber);
            const highlighted = isLineHighlighted(lineNumber);

            let bgColor = '#1e1e1e';
            if (highlighted) bgColor = '#fff3f2';
            else if (vulnerable) bgColor = getSeverityColor(lineVulns[0].severity);

            let borderLeft = 'none';
            if (highlighted) borderLeft = '4px solid #d32f2f';
            else if (vulnerable) borderLeft = `4px solid ${getSeverityBorderColor(lineVulns[0].severity)}`;

            const lineTextColor = getLineTextColor(highlighted, vulnerable);

            return (
              <div
                key={lineNumber}
                style={{ display: 'flex', backgroundColor: bgColor, borderLeft, minHeight: '1.5rem' }}
                onMouseEnter={() => { if (vulnerable) setSelectedVuln(lineVulns[0]); }}
              >
                <div style={{
                  width: '3.5rem', textAlign: 'right', paddingRight: '1rem',
                  color: '#666', backgroundColor: '#252526', userSelect: 'none',
                  fontFamily: 'monospace', fontSize: '0.9rem',
                  borderRight: highlighted ? '2px solid #ef5350' : 'none'
                }}>
                  {lineNumber}
                </div>
                <div style={{
                  flex: 1, paddingLeft: '1rem', fontFamily: 'monospace', fontSize: '0.9rem',
                  overflowX: 'auto', position: 'relative', whiteSpace: 'pre-wrap',
                  wordWrap: 'break-word', paddingRight: '2rem', color: lineTextColor
                }}>
                  <code style={{ color: lineTextColor }}>{line || '\n'}</code>
                  {vulnerable && (
                    <div
                      style={{
                        position: 'absolute', right: '0.5rem', top: '0',
                        display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer'
                      }}
                      onClick={() => { setSelectedVuln(lineVulns[0]); setDetailModalOpen(true); }}
                    >
                      <span style={{ fontSize: '1rem' }}>⚠️</span>
                      {lineVulns.length > 1 && (
                        <span style={{
                          fontSize: '0.7rem', fontWeight: 'bold', backgroundColor: '#ef5350',
                          color: 'white', padding: '0.15rem 0.35rem', borderRadius: '3px'
                        }}>
                          {lineVulns.length}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Panel */}
      <div style={{
        width: '30%', backgroundColor: '#f5f5f5', borderLeft: '1px solid #ddd',
        overflowY: 'auto', padding: '1rem'
      }}>
        {vulnerabilities.length > 0 ? (
          <div>
            {selectedVuln && (
              <div style={{
                marginBottom: '1rem', padding: '1rem', borderRadius: '10px',
                backgroundColor: '#ffffff', border: '1px solid #ddd',
                boxShadow: '0 4px 18px rgba(0,0,0,0.05)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
                  <div>
                    <h4 style={{ margin: 0, color: 'black'}}>Selected vulnerability</h4>
                    <p style={{ margin: '0.4rem 0 0 0', color: '#555', fontSize: '0.9rem' }}>
                      Line {selectedVuln.line} · {selectedVuln.type}
                    </p>
                  </div>
                  <button
                    onClick={() => setDetailModalOpen(true)}
                    style={{
                      padding: '0.5rem 0.85rem', borderRadius: '6px', border: 'none',
                      backgroundColor: '#0366d6', color: 'white', cursor: 'pointer'
                    }}
                  >
                    View details
                  </button>
                </div>
              </div>
            )}

            <h3 style={{ marginTop: 0, color: 'black' }}>⚠️ Vulnerabilities ({vulnerabilities.length})</h3>

            {vulnerabilities.map((vuln, idx) => {
              const badgeColor = getSeverityBadgeColor(vuln.severity);
              const isSelected = selectedVuln === vuln;
              return (
                <div
                  key={idx}
                  style={{
                    marginBottom: '1rem', padding: '0.75rem', borderRadius: '4px',
                    backgroundColor: getSeverityColor(vuln.severity),
                    borderLeft: `4px solid ${getSeverityBorderColor(vuln.severity)}`,
                    cursor: 'pointer', transition: 'all 0.2s',
                    border: isSelected ? '2px solid #0366d6' : 'none',
                    paddingLeft: isSelected ? '0.5rem' : '0.75rem'
                  }}
                  onClick={() => { setSelectedVuln(vuln); setDetailModalOpen(true); }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.transform = 'scale(1.02)';
                    e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.transform = 'scale(1)';
                    e.currentTarget.style.boxShadow = 'none';
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'start', gap: '0.5rem' }}>
                    <span style={{ fontSize: '1rem', flexShrink: 0 }}>⚠️</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                        <span style={{ fontWeight: 'bold', fontSize: '0.9rem', color: 'black' }}>{vuln.type}</span>
                        <span style={{
                          fontSize: '0.7rem', padding: '0.2rem 0.4rem', borderRadius: '3px',
                          fontWeight: 'bold', backgroundColor: badgeColor.bg, color: badgeColor.text
                        }}>
                          {vuln.severity.toUpperCase()}
                        </span>
                      </div>
                      {vuln.message && (
                        <p style={{ fontSize: '0.8rem', color: '#333', margin: '0.5rem 0' }}>
                          {vuln.message.length > 100 ? vuln.message.slice(0, 100) + '…' : vuln.message}
                        </p>
                      )}
                      <p style={{ fontSize: '0.75rem', color: '#666', margin: 0 }}>Line {vuln.line}</p>
                      {vuln.cweIds?.length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginTop: '0.4rem' }}>
                          {vuln.cweIds.map(cwe => (
                            <span key={cwe} style={{
                              fontSize: '0.65rem', background: '#ffe5e5', color: '#b00020',
                              padding: '0.15rem 0.35rem', borderRadius: '3px'
                            }}>{cwe}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{ color: '#999', textAlign: 'center', paddingTop: '2rem' }}>
            ✅ No vulnerabilities detected in this file
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {detailModalOpen && selectedVuln && (
        <div
          style={{
            position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh',
            backgroundColor: 'rgba(0,0,0,0.55)', display: 'flex',
            justifyContent: 'center', alignItems: 'center', zIndex: 9999, padding: '1rem'
          }}
          onClick={() => setDetailModalOpen(false)}
        >
          <div
            style={{
              position: 'relative', width: 'min(820px, 100%)', maxHeight: '90vh',
              backgroundColor: 'white', borderRadius: '16px', padding: '1.75rem',
              overflowY: 'auto', boxShadow: '0 20px 60px rgba(0,0,0,0.25)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Close */}
            <button
              onClick={() => setDetailModalOpen(false)}
              style={{
                position: 'absolute', top: '1rem', right: '1rem', border: 'none',
                background: 'transparent', fontSize: '1.4rem', cursor: 'pointer', color: '#333'
              }}
            >×</button>

            {/* Title row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem', flexWrap: 'wrap' }}>
              <h2 style={{ margin: 0, fontSize: '1.25rem' }}>{selectedVuln.type}</h2>
              <span style={{
                padding: '0.3rem 0.7rem', borderRadius: '6px', fontWeight: 'bold', fontSize: '0.8rem',
                backgroundColor: getSeverityBadgeColor(selectedVuln.severity).bg,
                color: getSeverityBadgeColor(selectedVuln.severity).text
              }}>
                {selectedVuln.severity.toUpperCase()}
              </span>
            </div>
            <p style={{ color: '#666', margin: '0 0 1.25rem 0', fontSize: '0.9rem' }}>
              {filePath} · Lines {selectedVuln.line}–{selectedVuln.lineEnd || selectedVuln.line}
            </p>

            {/* Metadata grid */}
            <div style={{
              display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem',
              marginBottom: '1.25rem', backgroundColor: '#f7f9fc',
              padding: '1rem', borderRadius: '10px', border: '1px solid #e2e8f0'
            }}>
              {selectedVuln.tool && (
                <div>
                  <div style={{ fontSize: '0.75rem', color: '#888', marginBottom: '0.2rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Tool</div>
                  <div style={{ fontWeight: '600', fontSize: '0.9rem', color: 'black' }}>{selectedVuln.tool}</div>
                </div>
              )}
              <div>
                <div style={{ fontSize: '0.75rem', color: '#888', marginBottom: '0.2rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Rule ID</div>
                <div style={{ fontWeight: '600', fontSize: '0.9rem', fontFamily: 'monospace', color: 'black' }}>{selectedVuln.type}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', color: '#888', marginBottom: '0.2rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Line</div>
                <div style={{ fontWeight: '600', fontSize: '0.9rem', color: 'black' }}>
                  {selectedVuln.line}{selectedVuln.lineEnd && selectedVuln.lineEnd !== selectedVuln.line ? `–${selectedVuln.lineEnd}` : ''}
                </div>
              </div>
              {selectedVuln.symbol && (
                <div>
                  <div style={{ fontSize: '0.75rem', color: '#888', marginBottom: '0.2rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Symbol</div>
                  <div style={{ fontWeight: '600', fontSize: '0.9rem', fontFamily: 'monospace', color: 'black'}}>{selectedVuln.symbol}</div>
                </div>
              )}
            </div>

            {/* Description */}
            {selectedVuln.message ? (
              <div style={{ marginBottom: '1.25rem' }}>
                <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1rem', color: 'black'}}>Description</h3>
                <div style={{
                  backgroundColor: '#f7f9fc', padding: '1rem', borderRadius: '10px',
                  border: '1px solid #e2e8f0', color: '#333', lineHeight: '1.6', fontSize: '0.9rem'
                }}>
                  {selectedVuln.message}
                </div>
              </div>
            ) : (
              <div style={{ marginBottom: '1.25rem' }}>
                <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1rem', color: 'black'}}>Description</h3>
                <div style={{
                  backgroundColor: '#f7f9fc', padding: '1rem', borderRadius: '10px',
                  border: '1px solid #e2e8f0', color: '#999', lineHeight: '1.6', fontSize: '0.9rem',
                  fontStyle: 'italic'
                }}>
                  No description available for this finding.
                </div>
              </div>
            )}

            {/* CWE IDs */}
            {selectedVuln.cweIds?.length > 0 && (
              <div style={{ marginBottom: '1.25rem' }}>
                <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1rem', color: 'black' }}>CWE Classifications</h3>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                  {selectedVuln.cweIds.map(cwe => (
                    <a
                      key={cwe}
                      href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        display: 'inline-block', padding: '0.35rem 0.75rem', borderRadius: '6px',
                        backgroundColor: '#fff0f0', color: '#c0392b', fontWeight: '600',
                        fontSize: '0.85rem', textDecoration: 'none', border: '1px solid #fcc'
                      }}
                    >
                      {cwe} ↗
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* CVE IDs */}
            {selectedVuln.cveIds?.length > 0 && (
              <div style={{ marginBottom: '1.25rem' }}>
                <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1rem', color: 'black' }}>Related CVEs</h3>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                  {selectedVuln.cveIds.map(cve => (
                    <a
                      key={cve}
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        display: 'inline-block', padding: '0.35rem 0.75rem', borderRadius: '6px',
                        backgroundColor: '#fff8e1', color: '#b7800a', fontWeight: '600',
                        fontSize: '0.85rem', textDecoration: 'none', border: '1px solid #ffe082'
                      }}
                    >
                      {cve} ↗
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Code snippet from file context */}
            <div style={{ marginBottom: '1.25rem' }}>
              <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1rem', color: 'black' }}>Code Snippet</h3>
              <pre style={{
                whiteSpace: 'pre-wrap', overflowX: 'auto', padding: '1rem', borderRadius: '10px',
                backgroundColor: '#111827', color: '#f8f8f2', fontSize: '0.85rem',
                lineHeight: '1.5', border: '1px solid #333', margin: 0
              }}>
                {/* Try to show the embedded code snippet from the retrieval text, fall back to file context */}
                {extractCodeSnippet(selectedVuln.fullText) || getVulnerabilitySnippet(selectedVuln)}
              </pre>
            </div>

            {/* Full retrieval text (collapsible) */}
            {selectedVuln.fullText && (
              <details style={{ marginBottom: '0.5rem' }}>
                <summary style={{
                  cursor: 'pointer', fontSize: '0.9rem', color: '#555',
                  padding: '0.5rem 0', userSelect: 'none'
                }}>
                  Show full finding context
                </summary>
                <pre style={{
                  whiteSpace: 'pre-wrap', overflowX: 'auto', padding: '1rem',
                  borderRadius: '10px', backgroundColor: '#1e1e1e', color: '#ccc',
                  fontSize: '0.8rem', lineHeight: '1.5', border: '1px solid #444',
                  marginTop: '0.5rem', maxHeight: '300px', overflowY: 'auto'
                }}>
                  {selectedVuln.fullText}
                </pre>
              </details>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
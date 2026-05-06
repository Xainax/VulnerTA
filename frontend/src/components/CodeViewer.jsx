import React, { useEffect, useState } from 'react';

export default function CodeViewer({ filePath, repo, owner, highlightLines = [] }) {
  const [fileContent, setFileContent] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState(null);

  const backendUrl = import.meta.env.VITE_BACKEND_URL || "http://127.0.0.1:8000";

  const fetchFileContent = async () => {
    setLoading(true);
    try {
      const response = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}`,
        {
          headers: {
            'Authorization': `token ${localStorage.getItem("token") || import.meta.env.VITE_GITHUB_TOKEN}`,
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
        body: JSON.stringify({
          query: path,
          top_k: 50
        })
      });
      const data = await response.json();
      const vulns = data.hits
        ?.filter(hit => hit.meta?.file_path === path)
        .map(hit => ({
          line: hit.meta?.line_start || 0,
          type: hit.meta?.rule_id || 'Unknown',
          severity: hit.meta?.severity?.toLowerCase() || 'low',
          message: hit.meta?.message || '',
          cveId: hit.meta?.cve_ids?.[0]
        })) || [];
      setVulnerabilities(vulns);
    } catch (error) {
      console.error('Error fetching vulnerabilities:', error);
    }
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

        <div style={{
          flex: 1,
          overflowY: 'auto',
          backgroundColor: '#1e1e1e',
          color: '#d4d4d4'
        }}>
          {lines.map((line, index) => {
            const lineNumber = index + 1;
            const vulnerable = isLineVulnerable(lineNumber);
            const lineVulns = getLineVulnerabilities(lineNumber);
            const highlighted = isLineHighlighted(lineNumber);

            let bgColor = '#1e1e1e';
            if (highlighted) {
              bgColor = '#ffe5e5';
            } else if (vulnerable) {
              bgColor = getSeverityColor(lineVulns[0].severity);
            }

            let borderLeft = 'none';
            if (highlighted) {
              borderLeft = '4px solid #ef5350';
            } else if (vulnerable) {
              borderLeft = `4px solid ${getSeverityBorderColor(lineVulns[0].severity)}`;
            }

            return (
              <div
                key={lineNumber}
                style={{
                  display: 'flex',
                  backgroundColor: bgColor,
                  borderLeft: borderLeft,
                  minHeight: '1.5rem'
                }}
                onMouseEnter={() => {
                  if (vulnerable) setSelectedVuln(lineVulns[0]);
                }}
              >
                {/* Line Number */}
                <div style={{
                  width: '3.5rem',
                  textAlign: 'right',
                  paddingRight: '1rem',
                  color: '#666',
                  backgroundColor: '#252526',
                  userSelect: 'none',
                  fontFamily: 'monospace',
                  fontSize: '0.9rem',
                  borderRight: highlighted ? '2px solid #ef5350' : 'none'
                }}>
                  {lineNumber}
                </div>

                {/* Code Content */}
                <div style={{
                  flex: 1,
                  paddingLeft: '1rem',
                  fontFamily: 'monospace',
                  fontSize: '0.9rem',
                  overflowX: 'auto',
                  position: 'relative',
                  whiteSpace: 'pre-wrap',
                  wordWrap: 'break-word',
                  paddingRight: '2rem'
                }}>
                  <code>{line || '\n'}</code>

                  {/* Vulnerability Indicator */}
                  {vulnerable && (
                    <div
                      style={{
                        position: 'absolute',
                        right: '0.5rem',
                        top: '0',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem',
                        cursor: 'pointer'
                      }}
                      onClick={() => setSelectedVuln(lineVulns[0])}
                    >
                      <span style={{ fontSize: '1rem' }}>⚠️</span>
                      {lineVulns.length > 1 && (
                        <span style={{
                          fontSize: '0.7rem',
                          fontWeight: 'bold',
                          backgroundColor: '#ef5350',
                          color: 'white',
                          padding: '0.15rem 0.35rem',
                          borderRadius: '3px'
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

      {/* Right Panel: Vulnerability Details */}
      <div style={{
        width: '30%',
        backgroundColor: '#f5f5f5',
        borderLeft: '1px solid #ddd',
        overflowY: 'auto',
        padding: '1rem'
      }}>
        {vulnerabilities.length > 0 ? (
          <div>
            <h3 style={{ marginTop: 0 }}>
              ⚠️ Vulnerabilities ({vulnerabilities.length})
            </h3>

            {vulnerabilities.map((vuln, idx) => {
              const badgeColor = getSeverityBadgeColor(vuln.severity);
              const isSelected = selectedVuln === vuln;

              return (
                <div
                  key={idx}
                  style={{
                    marginBottom: '1rem',
                    padding: '0.75rem',
                    borderRadius: '4px',
                    backgroundColor: getSeverityColor(vuln.severity),
                    borderLeft: `4px solid ${getSeverityBorderColor(vuln.severity)}`,
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    border: isSelected ? '2px solid #0366d6' : 'none',
                    paddingLeft: isSelected ? '0.5rem' : '0.75rem'
                  }}
                  onClick={() => setSelectedVuln(vuln)}
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
                        <span style={{ fontWeight: 'bold', fontSize: '0.9rem' }}>
                          {vuln.type}
                        </span>
                        <span style={{
                          fontSize: '0.7rem',
                          padding: '0.2rem 0.4rem',
                          borderRadius: '3px',
                          fontWeight: 'bold',
                          backgroundColor: badgeColor.bg,
                          color: badgeColor.text
                        }}>
                          {vuln.severity.toUpperCase()}
                        </span>
                      </div>
                      <p style={{ fontSize: '0.8rem', color: '#333', margin: '0.5rem 0' }}>
                        {vuln.message}
                      </p>
                      <p style={{ fontSize: '0.75rem', color: '#666', margin: 0 }}>
                        Line {vuln.line}
                      </p>
                      {vuln.cveId && (
                        <p style={{ fontSize: '0.75rem', color: '#0366d6', marginTop: '0.5rem' }}>
                          CVE: {vuln.cveId}
                        </p>
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
    </div>
  );
}
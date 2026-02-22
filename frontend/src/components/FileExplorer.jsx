import React, { useState } from 'react';
import CodeViewer from './CodeViewer';

export default function FileExplorer({ repo, owner, selectedFile, setSelectedFile, highlightLines, setHighlightLines }) {
  const [expandedDirs, setExpandedDirs] = useState(new Set());
  const [fileTree, setFileTree] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchRepoStructure = useCallback(async () => {
  setLoading(true);
  setError("");
  try {
    console.log(`Fetching repo structure for ${owner}/${repo} on branch ${branch || 'main'}`);
    
    const token = import.meta.env.VITE_GITHUB_TOKEN;
    if (!token) {
      throw new Error("GitHub token not configured. Set VITE_GITHUB_TOKEN in .env.local");
    }

    const branchName = branch || 'main';
    const response = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${branchName}?recursive=1`,
      {
        headers: {
          'Authorization': `token ${token}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      }
    );

    if (!response.ok) {
      const errorData = await response.json();
      console.error("GitHub API error:", errorData);
      throw new Error(`GitHub API error: ${response.status} - ${errorData.message}`);
    }

    const data = await response.json();
    console.log("GitHub API response:", data);

    if (!data.tree) {
      throw new Error("Invalid response from GitHub API - no tree data");
    }

    const tree = buildTree(data.tree);
    console.log("Built file tree:", tree);
    setFileTree(tree);
    setError("");
  } catch (err) {
    console.error('Error fetching repo structure:', err);
    setError(err.message || "Failed to load repository");
    setFileTree([]);
  } finally {
    setLoading(false);
  }
}, [owner, repo, branch]);

  const buildTree = (items) => {
    return items
      .filter(item => !item.path.includes('node_modules') && !item.path.includes('.git'))
      .map(item => ({
        name: item.path.split('/').pop(),
        path: item.path,
        type: item.type === 'tree' ? 'directory' : 'file'
      }));
  };

  const toggleDir = (path) => {
    const newExpanded = new Set(expandedDirs);
    if (newExpanded.has(path)) {
      newExpanded.delete(path);
    } else {
      newExpanded.add(path);
    }
    setExpandedDirs(newExpanded);
  };

  const handleSelectFile = (file) => {
    setSelectedFile(file);
    setHighlightLines([]); // Clear previous highlights
  };

  return (
    <div style={{ display: 'flex', height: 'calc(100vh - 100px)', gap: '1rem' }}>
      {/* Left Panel: File Tree */}
      <div style={{
        width: '25%',
        borderRight: '1px solid #ddd',
        backgroundColor: '#f5f5f5',
        padding: '1rem',
        overflowY: 'auto'
      }}>
        <h2 style={{ marginTop: 0, fontSize: '1.1rem' }}>Repository Files</h2>
        <button
          onClick={fetchRepoStructure}
          style={{
            width: '100%',
            marginBottom: '1rem',
            padding: '0.75rem',
            backgroundColor: '#0366d6',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            fontWeight: 'bold'
          }}
        >
          {loading ? '⏳ Loading...' : '📂 Load Repository'}
        </button>

        {fileTree.length > 0 && (
          <div style={{ fontSize: '0.9rem' }}>
            {fileTree.map((node) => (
              <FileTreeNode
                key={node.path}
                node={node}
                isExpanded={expandedDirs.has(node.path)}
                onToggle={() => toggleDir(node.path)}
                onSelectFile={() => handleSelectFile(node)}
                isSelected={selectedFile?.path === node.path}
              />
            ))}
          </div>
        )}
      </div>

      {/* Right Panel: Code Viewer */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {selectedFile ? (
          <CodeViewer
            filePath={selectedFile.path}
            repo={repo}
            owner={owner}
            highlightLines={highlightLines}
          />
        ) : (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100%',
            color: '#999',
            fontSize: '1.1rem'
          }}>
            👈 Select a file to view
          </div>
        )}
      </div>
    </div>
  );
}

function FileTreeNode({ node, isExpanded, onToggle, onSelectFile, isSelected }) {
  if (node.type === 'file') {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.5rem',
          cursor: 'pointer',
          borderRadius: '4px',
          fontSize: '0.9rem',
          backgroundColor: isSelected ? '#0366d6' : 'transparent',
          color: isSelected ? 'white' : 'inherit',
          transition: 'all 0.2s'
        }}
        onClick={onSelectFile}
        onMouseEnter={(e) => !isSelected && (e.currentTarget.style.backgroundColor = '#e0e0e0')}
        onMouseLeave={(e) => !isSelected && (e.currentTarget.style.backgroundColor = 'transparent')}
      >
        <span>📄</span>
        <span>{node.name}</span>
      </div>
    );
  }

  return (
    <div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.5rem',
          cursor: 'pointer',
          borderRadius: '4px',
          fontWeight: 'bold',
          fontSize: '0.9rem',
          transition: 'all 0.2s'
        }}
        onClick={onToggle}
        onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#e0e0e0'}
        onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
      >
        <span style={{
          display: 'inline-block',
          transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)',
          transition: 'transform 0.2s',
          width: '1rem'
        }}>
          ▶
        </span>
        <span>📁</span>
        <span>{node.name}</span>
      </div>
    </div>
  );
}
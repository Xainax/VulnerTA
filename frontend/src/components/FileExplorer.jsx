import React, { useState, useCallback, useEffect } from 'react';
import CodeViewer from './CodeViewer';

export default function FileExplorer({ repo, owner, branch, selectedFile, setSelectedFile, highlightLines, setHighlightLines }) {
  const [expandedDirs, setExpandedDirs] = useState(new Set());
  const [fileTree, setFileTree] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const fetchRepoStructure = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      console.log(`Fetching repo structure for ${owner}/${repo} on branch ${branch || 'main'}`);
      
      const token = localStorage.getItem("token");
      if (!token) {
        throw new Error("Not authenticated. Please log in with GitHub.");
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

  useEffect(() => {
    fetchRepoStructure();
  }, [fetchRepoStructure]);

  const buildTree = (items) => {
    const filtered = items
      .filter(item => !item.path.includes('node_modules') && !item.path.includes('.git'));
    
    const nodeMap = {};
    
    // Create all nodes first
    filtered.forEach(item => {
      nodeMap[item.path] = {
        name: item.path.split('/').pop(),
        path: item.path,
        type: item.type === 'tree' ? 'directory' : 'file',
        children: []
      };
    });
    
    // Build parent-child relationships
    const roots = [];
    filtered.forEach(item => {
      const node = nodeMap[item.path];
      const pathParts = item.path.split('/');
      
      if (pathParts.length === 1) {
        // Root level
        roots.push(node);
      } else {
        // Find parent
        const parentPath = pathParts.slice(0, -1).join('/');
        if (nodeMap[parentPath]) {
          nodeMap[parentPath].children.push(node);
        } else {
          roots.push(node);
        }
      }
    });
    
    return roots;
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
        
        {error && (
          <div style={{
            backgroundColor: '#ffebee',
            color: '#c62828',
            padding: '0.75rem',
            borderRadius: '4px',
            marginBottom: '1rem',
            fontSize: '0.85rem'
          }}>
            ❌ {error}
          </div>
        )}
        
        <button
          onClick={fetchRepoStructure}
          disabled={loading}
          style={{
            width: '100%',
            marginBottom: '1rem',
            padding: '0.75rem',
            backgroundColor: loading ? '#ccc' : '#0366d6',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: loading ? 'not-allowed' : 'pointer',
            fontWeight: 'bold'
          }}
        >
          {loading ? '⏳ Loading...' : '🔄 Reload Repository'}
        </button>

        {fileTree.length > 0 && (
          <div style={{ fontSize: '0.9rem' }}>
            {fileTree.map((node) => (
              <FileTreeNode
                key={node.path}
                node={node}
                expandedDirs={expandedDirs}
                onToggleDir={toggleDir}
                onSelectFile={handleSelectFile}
                selectedFile={selectedFile}
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

function FileTreeNode({ node, expandedDirs, onToggleDir, onSelectFile, selectedFile }) {
  if (node.type === 'file') {
    const isThisSelected = selectedFile?.path === node.path;
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
          backgroundColor: isThisSelected ? '#0366d6' : 'transparent',
          color: isThisSelected ? 'white' : '#333',
          transition: 'all 0.2s',
          marginLeft: '1rem'
        }}
        onClick={() => onSelectFile(node)}
        onMouseEnter={(e) => !isThisSelected && (e.currentTarget.style.backgroundColor = '#e0e0e0')}
        onMouseLeave={(e) => !isThisSelected && (e.currentTarget.style.backgroundColor = 'transparent')}
      >
        <span>📄</span>
        <span>{node.name}</span>
      </div>
    );
  }

  // Directory node
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
          color: '#333',
          transition: 'all 0.2s'
        }}
        onClick={() => onToggleDir(node.path)}
        onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#e0e0e0'}
        onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
      >
        <span style={{
          display: 'inline-block',
          transform: expandedDirs.has(node.path) ? 'rotate(90deg)' : 'rotate(0deg)',
          transition: 'transform 0.2s',
          width: '1rem'
        }}>
          ▶
        </span>
        <span>📁</span>
        <span>{node.name}</span>
      </div>
      
      {/* Render children only if expanded */}
      {expandedDirs.has(node.path) && node.children && node.children.length > 0 && (
        <div style={{ marginLeft: '0.5rem' }}>
          {node.children.map((child) => (
            <FileTreeNode
              key={child.path}
              node={child}
              expandedDirs={expandedDirs}
              onToggleDir={onToggleDir}
              onSelectFile={onSelectFile}
              selectedFile={selectedFile}
            />
          ))}
        </div>
      )}
    </div>
  );
}
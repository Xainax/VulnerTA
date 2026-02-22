import React, { useState, useEffect } from 'react';

export default function RepositorySelector({ onSelectRepo }) {
  const [repos, setRepos] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    fetchUserRepositories();
  }, []);

  const fetchUserRepositories = async () => {
    setLoading(true);
    setError("");
    try {
      const token = import.meta.env.VITE_GITHUB_TOKEN;
      if (!token) {
        throw new Error("GitHub token not configured. Set VITE_GITHUB_TOKEN in .env.local");
      }

      console.log("Fetching user repositories...");

      // First, get the authenticated user
      const userResponse = await fetch('https://api.github.com/user', {
        headers: {
          'Authorization': `token ${token}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });

      if (!userResponse.ok) {
        throw new Error(`Failed to fetch user info: ${userResponse.status}`);
      }

      const user = await userResponse.json();
      console.log("Current user:", user.login);

      // Get all repositories for the user (both owned and collaborative)
      const repoResponse = await fetch(
        'https://api.github.com/user/repos?per_page=100&sort=updated&direction=desc',
        {
          headers: {
            'Authorization': `token ${token}`,
            'Accept': 'application/vnd.github.v3+json'
          }
        }
      );

      if (!repoResponse.ok) {
        throw new Error(`Failed to fetch repositories: ${repoResponse.status}`);
      }

      const repoData = await repoResponse.json();
      console.log("Repositories found:", repoData.length);

      // Map to a cleaner format
      const repoList = repoData.map(repo => ({
        id: repo.id,
        name: repo.name,
        fullName: repo.full_name,
        owner: repo.owner.login,
        description: repo.description,
        url: repo.html_url,
        language: repo.language,
        stars: repo.stargazers_count,
        isPrivate: repo.private,
        defaultBranch: repo.default_branch
      }));

      setRepos(repoList);
      setError("");
    } catch (err) {
      console.error('Error fetching repositories:', err);
      setError(err.message || "Failed to load repositories");
      setRepos([]);
    } finally {
      setLoading(false);
    }
  };

  const filteredRepos = repos.filter(repo =>
    repo.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    repo.description?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div style={{
      padding: '2rem',
      maxWidth: '1200px',
      margin: '0 auto'
    }}>
      <h1 style={{ marginTop: 0 }}>📚 Select a Repository</h1>
      <p style={{ color: '#666' }}>Choose a repository to analyze for vulnerabilities</p>

      {/* Search Bar */}
      <div style={{ marginBottom: '2rem' }}>
        <input
          type="text"
          placeholder="Search repositories..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{
            width: '100%',
            padding: '0.75rem',
            fontSize: '1rem',
            borderRadius: '6px',
            border: '1px solid #ddd',
            boxSizing: 'border-box'
          }}
        />
      </div>

      {/* Loading State */}
      {loading && (
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>⏳</div>
          <p>Loading your repositories...</p>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div style={{
          padding: '1rem',
          backgroundColor: '#ffebee',
          color: '#c62828',
          borderRadius: '6px',
          marginBottom: '1rem'
        }}>
          <strong>❌ Error:</strong> {error}
          <br />
          <button
            onClick={fetchUserRepositories}
            style={{
              marginTop: '0.5rem',
              padding: '0.5rem 1rem',
              backgroundColor: '#c62828',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Retry
          </button>
        </div>
      )}

      {/* Repository Grid */}
      {!loading && filteredRepos.length > 0 && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
          gap: '1rem'
        }}>
          {filteredRepos.map((repo) => (
            <div
              key={repo.id}
              onClick={() => onSelectRepo(repo)}
              style={{
                padding: '1.5rem',
                border: '1px solid #ddd',
                borderRadius: '8px',
                backgroundColor: '#f9f9f9',
                cursor: 'pointer',
                transition: 'all 0.2s',
                boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.2)';
                e.currentTarget.style.transform = 'translateY(-2px)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';
                e.currentTarget.style.transform = 'translateY(0)';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'start', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '1.5rem' }}>📦</span>
                <div style={{ flex: 1 }}>
                  <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '1rem' }}>
                    <a
                      href={repo.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: '#0366d6', textDecoration: 'none' }}
                    >
                      {repo.name}
                    </a>
                  </h3>
                  <p style={{ margin: 0, fontSize: '0.85rem', color: '#666' }}>
                    {repo.owner}
                  </p>
                </div>
                {repo.isPrivate && (
                  <span style={{
                    fontSize: '0.75rem',
                    backgroundColor: '#eee',
                    padding: '0.25rem 0.5rem',
                    borderRadius: '4px',
                    color: '#666'
                  }}>
                    🔒 Private
                  </span>
                )}
              </div>

              {repo.description && (
                <p style={{
                  margin: '0 0 0.75rem 0',
                  fontSize: '0.9rem',
                  color: '#555',
                  lineHeight: '1.4'
                }}>
                  {repo.description.substring(0, 100)}
                  {repo.description.length > 100 ? '...' : ''}
                </p>
              )}

              <div style={{
                display: 'flex',
                gap: '1rem',
                fontSize: '0.85rem',
                color: '#666',
                marginBottom: '1rem',
                flexWrap: 'wrap'
              }}>
                {repo.language && (
                  <span>
                    💻 {repo.language}
                  </span>
                )}
                <span>
                  ⭐ {repo.stars}
                </span>
                <span>
                  🌳 {repo.defaultBranch}
                </span>
              </div>

              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onSelectRepo(repo);
                }}
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  backgroundColor: '#0366d6',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontWeight: 'bold',
                  fontSize: '0.9rem'
                }}
              >
                Analyze →
              </button>
            </div>
          ))}
        </div>
      )}

      {/* No Results */}
      {!loading && filteredRepos.length === 0 && repos.length > 0 && (
        <div style={{ textAlign: 'center', padding: '2rem', color: '#999' }}>
          <p>No repositories match your search</p>
        </div>
      )}

      {/* No Repos */}
      {!loading && repos.length === 0 && !error && (
        <div style={{ textAlign: 'center', padding: '2rem', color: '#999' }}>
          <p>No repositories found</p>
        </div>
      )}
    </div>
  );
}
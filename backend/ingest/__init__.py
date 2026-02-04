"""
VulnerTA Ingestion Package

This package handles cloning repositories and running static analysis tools
(Bandit, Semgrep, and later AST/CFG extraction).
"""

__version__ = "0.1.0"
__all__ = ["ingest_repo", "nvd_loader"]
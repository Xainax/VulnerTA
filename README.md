# VulnerTA
Open-Source Vulnerability Tracking and Assessment using LLM/RAG

This project includes a lightweight semantic vulnerability prototype centered on AST analysis. The backend exposes an endpoint that accepts a GitHub repository URL, retrieves all `.py` files, and performs structural analysis to detect:

* tainted input flowing into sensitive sinks (e.g. `input()` → `eval`)
* direct `eval`/`exec` usage
* unsafe file writes (`open(..., 'w'|'a')`)

Each repository scan returns structured JSON with counts per category and a computed risk score. The React frontend visualizes the results with a bar graph and total risk score for demo purposes.

## Getting Started

1. Set up a Python environment and install dependencies from `requirements.txt`.
2. Configure a GitHub token in a `.env` file (`GITHUB_TOKEN`) or set `VITE_GITHUB_TOKEN` for the frontend.
3. Run the backend — the API and retriever are now combined, so you can launch everything with:

   ```bash
   # you can run this from the workspace root or inside the backend directory
   uvicorn retriever.app:app --host 127.0.0.1 --port 8000 --reload
   ```

   (the code automatically adjusts `sys.path` so sibling packages like `apps` and
   `backend/index` are importable).

   Start the frontend with `npm install && npm run dev`.
4. In the UI select a repository (your own GitHub or any public repo) and watch the analysis appear.

The prototype is intentionally small, focusing on AST-driven reasoning and a clean visualization, making it suitable for demos or further extension.

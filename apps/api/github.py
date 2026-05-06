from github import Github, GithubException
from urllib.parse import urlparse

def extract_owner_repo(repo_link: str):
    parsed = urlparse(repo_link)
    parts = parsed.path.strip("/").split("/")

    if len(parts) < 2:
        raise ValueError("Invalid GitHub repository URL")

    return parts[0], parts[1].replace(".git", "")


def fetch_python_files(repo_link: str, token: str, fetch_content: bool = False):
    """Return a list of dictionaries representing Python files in the repo.

    If `fetch_content` is True the returned objects will include a ``content`` key
    containing the UTF-8 decoded source. This keeps the existing behaviour for
    callers that only need the path/size.
    """
    try:
        owner, repo_name = extract_owner_repo(repo_link)
        g = Github(token)
        repo = g.get_repo(f"{owner}/{repo_name}")
    except GithubException as e:
        raise Exception(f"GitHub API error: {e.data.get('message')}")

    py_files = []
    stack = [""]

    while stack:
        path = stack.pop()

        try:
            contents = repo.get_contents(path)
        except GithubException:
            continue

        if not isinstance(contents, list):
            contents = [contents]

        for file in contents:
            if file.type == "dir":
                stack.append(file.path)
            elif file.path.endswith(".py"):
                entry = {"path": file.path, "size": file.size}
                if fetch_content:
                    try:
                        entry["content"] = file.decoded_content.decode("utf-8", errors="ignore")
                    except Exception:
                        entry["content"] = ""
                py_files.append(entry)

    return py_files

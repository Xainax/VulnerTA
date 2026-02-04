from github import Github, GithubException
from urllib.parse import urlparse

def extract_owner_repo(repo_link: str):
    parsed = urlparse(repo_link)
    parts = parsed.path.strip("/").split("/")

    if len(parts) < 2:
        raise ValueError("Invalid GitHub repository URL")

    return parts[0], parts[1].replace(".git", "")


def fetch_python_files(repo_link: str, token: str):
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
                py_files.append({
                    "path": file.path,
                    "size": file.size
                })

    return py_files

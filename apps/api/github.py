from github import Github

def fetch_python_files(repo_link: str, token: str):
    g = Github(token)

    # Extract owner and repo name from URL
    parts = repo_link.rstrip("/").split("/")
    if len(parts) < 2:
        raise ValueError("Invalid GitHub repo URL")
    owner, repo_name = parts[-2], parts[-1]

    repo = g.get_repo(f"{owner}/{repo_name}")

    py_files = []
    contents = repo.get_contents("")

    while contents:
        file = contents.pop(0)
        if file.type == "dir":
            contents.extend(repo.get_contents(file.path))
        elif file.path.endswith(".py"):
            py_files.append({
                "path": file.path,
                "size": file.size
            })

    return py_files

#!/usr/bin/env python3
"""
HexStrike AI - GitHub & Git Repository Fetcher / Cloner
======================================================
Provides automated shallow cloning, ZIP archive fetching fallback, and path extraction
for scanning remote GitHub/Git repositories seamlessly within SAST, SCA, and Unified Audits.
"""

import os
import re
import sys
import shutil
import tempfile
import subprocess
import urllib.request
import zipfile
import uuid
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Regular expressions for Git & GitHub repository URLs
GITHUB_URL_PATTERNS = [
    re.compile(r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?(?:/.*)?$", re.IGNORECASE),
    re.compile(r"^git@github\.com:(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?$", re.IGNORECASE),
    re.compile(r"^(?P<owner>[a-zA-Z0-9_-]+)/(?P<repo>[a-zA-Z0-9_.-]+)$")
]

GENERIC_GIT_PATTERNS = [
    re.compile(r"^(?:https?|git|ssh)://.+/(?P<repo>[\w.-]+?)(?:\.git)?$", re.IGNORECASE)
]


def is_git_or_github_url(input_str: str) -> bool:
    """Check if the provided string is a GitHub or Git repository URL / identifier"""
    if not input_str or not isinstance(input_str, str):
        return False
    
    clean_str = input_str.strip()
    if os.path.exists(clean_str) and (os.path.isabs(clean_str) or clean_str in [".", "..", "./", ".\\"]):
        return False
        
    for pat in GITHUB_URL_PATTERNS:
        if pat.match(clean_str):
            return True
            
    for pat in GENERIC_GIT_PATTERNS:
        if pat.match(clean_str):
            return True
            
    return False


def parse_repo_info(input_str: str) -> Dict[str, str]:
    """Extract owner, repo name, and standard clone URL from input"""
    clean_str = input_str.strip()
    for pat in GITHUB_URL_PATTERNS:
        m = pat.match(clean_str)
        if m:
            owner = m.group("owner")
            repo = m.group("repo")
            if repo.endswith(".git"):
                repo = repo[:-4]
            return {
                "owner": owner,
                "repo": repo,
                "full_name": f"{owner}/{repo}",
                "clone_url": f"https://github.com/{owner}/{repo}.git",
                "web_url": f"https://github.com/{owner}/{repo}",
                "is_github": True
            }
            
    for pat in GENERIC_GIT_PATTERNS:
        m = pat.match(clean_str)
        if m:
            repo = m.group("repo")
            if repo.endswith(".git"):
                repo = repo[:-4]
            return {
                "owner": "git",
                "repo": repo,
                "full_name": repo,
                "clone_url": clean_str if clean_str.endswith(".git") else f"{clean_str}.git",
                "web_url": clean_str,
                "is_github": False
            }
            
    return {
        "owner": "unknown",
        "repo": "repository",
        "full_name": clean_str,
        "clone_url": clean_str,
        "web_url": clean_str,
        "is_github": False
    }


def fetch_or_clone_repo(
    repo_input: str,
    branch: Optional[str] = None,
    destination: Optional[str] = None,
    timeout_seconds: int = 60
) -> Dict[str, Any]:
    """
    Clones or downloads a remote GitHub/Git repository into a local directory for scanning.
    Tries git shallow clone first, falling back to GitHub zipball download.
    """
    info = parse_repo_info(repo_input)
    clone_url = info["clone_url"]
    
    if not destination:
        unique_id = uuid.uuid4().hex[:8]
        temp_dir = Path(tempfile.gettempdir()) / f"hexstrike_repo_{info['repo']}_{unique_id}"
        temp_dir.mkdir(parents=True, exist_ok=True)
        dest_path = str(temp_dir)
    else:
        dest_path = destination
        os.makedirs(dest_path, exist_ok=True)

    # Strategy 1: Git Shallow Clone
    git_success = False
    git_error = ""
    try:
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([clone_url, dest_path])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            encoding="utf-8",
            errors="replace"
        )
        if result.returncode == 0 and os.listdir(dest_path):
            git_success = True
            logger.info(f"Successfully cloned repository {info['full_name']} via git to {dest_path}")
        else:
            git_error = result.stderr.strip() or f"Git exit code {result.returncode}"
    except Exception as e:
        git_error = str(e)

    if git_success:
        return {
            "success": True,
            "repo_path": dest_path,
            "repo_info": info,
            "method": "git_clone",
            "branch": branch or "default",
            "error": None
        }

    # Strategy 2: GitHub ZIP Archive Fallback (if it's a GitHub repository)
    if info.get("is_github"):
        branches_to_try = [branch] if branch else ["main", "master", "develop"]
        zip_success = False
        zip_error = ""
        
        for try_branch in branches_to_try:
            zip_url = f"https://codeload.github.com/{info['owner']}/{info['repo']}/zip/refs/heads/{try_branch}"
            zip_file_path = os.path.join(tempfile.gettempdir(), f"{info['repo']}_{try_branch}_{uuid.uuid4().hex[:6]}.zip")
            
            try:
                req = urllib.request.Request(
                    zip_url,
                    headers={"User-Agent": "HexStrike-AI-Security-Auditor/6.0"}
                )
                with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
                    with open(zip_file_path, "wb") as out_file:
                        shutil.copyfileobj(response, out_file)
                
                # Unzip archive into dest_path
                with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
                    # Find root folder in zip
                    root_dirs = {item.split('/')[0] for item in zip_ref.namelist() if '/' in item}
                    zip_ref.extractall(dest_path)
                    
                # If extracted into a subfolder like repo-main, check if we should point to that
                extracted_items = os.listdir(dest_path)
                final_path = dest_path
                if len(extracted_items) == 1 and os.path.isdir(os.path.join(dest_path, extracted_items[0])):
                    final_path = os.path.join(dest_path, extracted_items[0])

                if os.path.exists(zip_file_path):
                    os.remove(zip_file_path)

                zip_success = True
                logger.info(f"Successfully downloaded GitHub archive for {info['full_name']} (branch: {try_branch})")
                return {
                    "success": True,
                    "repo_path": final_path,
                    "base_temp_path": dest_path,
                    "repo_info": info,
                    "method": "zip_archive",
                    "branch": try_branch,
                    "error": None
                }
            except Exception as ze:
                zip_error = str(ze)
                if os.path.exists(zip_file_path):
                    try:
                        os.remove(zip_file_path)
                    except Exception:
                        pass
                continue

    return {
        "success": False,
        "repo_path": None,
        "repo_info": info,
        "method": "failed",
        "error": f"Failed to clone/download repository. Git error: {git_error}. Zip error: {zip_error if 'zip_error' in locals() else 'N/A'}"
    }


def cleanup_repo(target_path: Optional[str], base_temp_path: Optional[str] = None):
    """Safely remove temporary cloned repository directory"""
    paths_to_clean = [p for p in [base_temp_path, target_path] if p and os.path.exists(p)]
    for p in paths_to_clean:
        if "hexstrike_repo_" in p or p.startswith(tempfile.gettempdir()):
            try:
                shutil.rmtree(p, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp repo path {p}: {e}")

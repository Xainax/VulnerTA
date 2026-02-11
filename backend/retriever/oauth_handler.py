import requests
from fastapi import APIRouter, HTTPException
import os
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

@router.post("/auth/callback")
async def github_callback(body: dict):
    try:
        code = body.get("code")
        
        if not code:
            raise HTTPException(status_code=400, detail="No authorization code provided")
        
        print(f"[DEBUG] Received code: {code[:20]}...")
        print(f"[DEBUG] Using Client ID: {GITHUB_CLIENT_ID}")

        # Exchange code for access token
        token_response = requests.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code
            }
        )
        
        token_data = token_response.json()
        print(f"[DEBUG] Token response: {token_data}")
        
        access_token = token_data.get("access_token")
        error = token_data.get("error")

        if error:
            raise HTTPException(status_code=400, detail=f"GitHub OAuth error: {error}")
        
        if not access_token:
            raise HTTPException(status_code=400, detail="Failed to get access token")

        # Get user info
        user_response = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {access_token}"}
        )
        
        user_data = user_response.json()
        print(f"[DEBUG] User data: {user_data}")

        return {
            "access_token": access_token,
            "user": {
                "login": user_data.get("login"),
                "id": user_data.get("id"),
                "avatar_url": user_data.get("avatar_url"),
                "email": user_data.get("email")
            }
        }
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
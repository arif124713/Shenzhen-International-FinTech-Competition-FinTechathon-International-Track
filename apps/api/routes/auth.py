"""Seeded demo auth (US-01/US-05). Simple session cookie with seeded users; no production identity."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

router = APIRouter(tags=["auth"])

USERS = {
    "rafi": {"id": "u_rafi", "name": "Rafi", "role": "student", "lang": "en"},
    "ammu": {"id": "u_ammu", "name": "Ammu", "role": "guardian", "lang": "bn"},
}


class LoginBody(BaseModel):
    username: str


@router.post("/auth/login")
def login(body: LoginBody, response: Response) -> dict[str, str]:
    user = USERS.get(body.username.lower())
    if user is None:
        raise HTTPException(status_code=401, detail={"code": "UNKNOWN_USER"})
    token = secrets.token_urlsafe(24)
    response.set_cookie("session", token, httponly=True, samesite="lax", max_age=3600)
    return {"user_id": user["id"], "name": user["name"], "role": user["role"], "lang": user["lang"]}

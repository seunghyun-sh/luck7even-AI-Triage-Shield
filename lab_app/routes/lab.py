"""Health and controlled reset endpoints used by the team."""

import secrets

from flask import Blueprint, abort, current_app, request

from lab_app.db import init_db

lab_bp = Blueprint("lab", __name__)


@lab_bp.get("/health")
def health():
    return {"status": "ok"}, 200


@lab_bp.post("/internal/lab-1/reset")
def reset():
    expected = current_app.config["LAB_1_RESET_TOKEN"]
    supplied = request.headers.get("X-Lab-1-Reset-Token", "")
    if not expected or not secrets.compare_digest(expected, supplied):
        abort(404)
    init_db()
    return {"status": "reset"}, 200

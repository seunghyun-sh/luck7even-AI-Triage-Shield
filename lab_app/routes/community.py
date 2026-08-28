"""Reviews and customer-support pages."""

from flask import Blueprint, current_app, redirect, render_template, request, url_for

from lab_app.db import get_db

community_bp = Blueprint("community", __name__)


@community_bp.route("/reviews", methods=("GET", "POST"))
def reviews():
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "익명").strip() or "익명"
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "")
        try:
            rating = max(1, min(int(request.form.get("rating", "5")), 5))
        except ValueError:
            rating = 5
        db.execute(
            "INSERT INTO reviews (author, title, content, rating) VALUES (?, ?, ?, ?)",
            (author, title, content, rating),
        )
        db.commit()
        return redirect(url_for("community.reviews"))
    entries = db.execute("SELECT * FROM reviews ORDER BY id DESC").fetchall()
    return render_template(
        "reviews.html",
        reviews=entries,
        vulnerable=current_app.config["LAB_1_SECURITY_MODE"] == "vulnerable",
    )


@community_bp.route("/support", methods=("GET", "POST"))
def support():
    submitted = False
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO inquiries (name, email, subject, message) VALUES (?, ?, ?, ?)",
            (
                request.form.get("name", ""),
                request.form.get("email", ""),
                request.form.get("subject", ""),
                request.form.get("message", ""),
            ),
        )
        db.commit()
        submitted = True
    notices = db.execute("SELECT * FROM notices ORDER BY id DESC").fetchall()
    return render_template("support.html", notices=notices, submitted=submitted)


@community_bp.get("/support/preview")
def support_preview():
    return render_template(
        "support_preview.html",
        security_mode=current_app.config["LAB_1_SECURITY_MODE"],
    )

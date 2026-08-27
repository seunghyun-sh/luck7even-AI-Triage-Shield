"""Public storefront pages."""

import sqlite3

from flask import Blueprint, redirect, render_template, request, session, url_for

from lab_app.db import get_db

storefront_bp = Blueprint("storefront", __name__)


@storefront_bp.get("/")
def home():
    db = get_db()
    featured = db.execute(
        "SELECT * FROM products ORDER BY rating DESC, review_count DESC LIMIT 4"
    ).fetchall()
    recent_reviews = db.execute(
        "SELECT * FROM reviews ORDER BY id DESC LIMIT 3"
    ).fetchall()
    return render_template("home.html", featured=featured, recent_reviews=recent_reviews)


@storefront_bp.get("/products")
def products():
    category = request.args.get("category", "")
    db = get_db()
    categories = [
        row["category"]
        for row in db.execute("SELECT DISTINCT category FROM products ORDER BY category")
    ]
    if category:
        items = db.execute(
            "SELECT * FROM products WHERE category = ? ORDER BY id",
            (category,),
        ).fetchall()
    else:
        items = db.execute("SELECT * FROM products ORDER BY id").fetchall()
    return render_template(
        "products.html",
        products=items,
        categories=categories,
        selected_category=category,
    )


@storefront_bp.get("/products/<int:product_id>")
def product_detail(product_id: int):
    product = get_db().execute(
        "SELECT * FROM products WHERE id = ?",
        (product_id,),
    ).fetchone()
    if product is None:
        return render_template("404.html"), 404
    return render_template("product_detail.html", product=product)


@storefront_bp.get("/search")
def search():
    keyword = request.args.get("q", "")
    results = []
    error = None
    if keyword:
        # Intentionally vulnerable: input is concatenated into SQL for the lab.
        query = (
            "SELECT * FROM products "
            f"WHERE name LIKE '%{keyword}%' OR description LIKE '%{keyword}%' "
            "ORDER BY id"
        )
        try:
            results = get_db().execute(query).fetchall()
        except sqlite3.Error as exc:
            # Intentionally exposed to support error-based SQLi assessment.
            error = str(exc)
    return render_template(
        "search.html",
        keyword=keyword,
        products=results,
        error=error,
    )


@storefront_bp.get("/cart")
def cart():
    cart_items = session.get("cart", {})
    products = []
    total = 0
    db = get_db()
    for product_id, quantity in cart_items.items():
        product = db.execute(
            "SELECT * FROM products WHERE id = ?",
            (int(product_id),),
        ).fetchone()
        if product:
            subtotal = product["price"] * quantity
            products.append({"product": product, "quantity": quantity, "subtotal": subtotal})
            total += subtotal
    return render_template("cart.html", cart_items=products, total=total)


@storefront_bp.post("/cart/add/<int:product_id>")
def add_to_cart(product_id: int):
    product = get_db().execute(
        "SELECT id FROM products WHERE id = ?",
        (product_id,),
    ).fetchone()
    if product is not None:
        cart_items = session.get("cart", {})
        key = str(product_id)
        cart_items[key] = min(cart_items.get(key, 0) + 1, 9)
        session["cart"] = cart_items
        session.modified = True
    return redirect(request.referrer or url_for("storefront.cart"))


@storefront_bp.post("/cart/clear")
def clear_cart():
    session.pop("cart", None)
    return redirect(url_for("storefront.cart"))


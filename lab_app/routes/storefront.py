"""Public storefront pages and the two MySQL blind-SQLi targets."""

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from lab_app.db import DATABASE_ERRORS, get_db

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
    if keyword:
        pattern = f"%{keyword}%"
        results = get_db().execute(
            "SELECT * FROM products "
            "WHERE name LIKE ? OR description LIKE ? ORDER BY id",
            (pattern, pattern),
        ).fetchall()
    return render_template(
        "search.html",
        keyword=keyword,
        products=results,
        vulnerable=current_app.config["LAB_1_SECURITY_MODE"] == "vulnerable",
    )


@storefront_bp.get("/products/stock")
def stock_status():
    """Boolean-based blind SQLi target with a compact storefront JSON response."""
    product_id = request.args.get("product_id", "")
    vulnerable = current_app.config["LAB_1_SECURITY_MODE"] == "vulnerable"

    try:
        if vulnerable:
            # Intentionally vulnerable: the numeric expression is concatenated.
            query = f"SELECT id, stock FROM products WHERE id = {product_id or '0'}"
            product = get_db().execute(query).fetchone()
        else:
            try:
                normalized_id = int(product_id)
            except ValueError:
                return jsonify(status="invalid", available=False), 400
            product = get_db().execute(
                "SELECT id, stock FROM products WHERE id = ?",
                (normalized_id,),
            ).fetchone()
    except DATABASE_ERRORS:
        product = None

    if product is None:
        return jsonify(status="unavailable", available=False)
    return jsonify(
        status="in_stock" if product["stock"] > 0 else "sold_out",
        available=product["stock"] > 0,
    )


@storefront_bp.get("/coupon/check")
def coupon_check():
    """Coupon page containing the controlled MySQL time-based blind target."""
    code = request.args.get("code", "")
    coupon = None
    checked = bool(code)
    if checked:
        try:
            if current_app.config["LAB_1_SECURITY_MODE"] == "vulnerable":
                # Intentionally vulnerable in the isolated training mode.
                query = (
                    "SELECT code, discount_percent FROM coupons "
                    f"WHERE code = '{code}' AND active = 1\nLIMIT 1"
                )
                coupon = get_db().execute(query).fetchone()
            else:
                coupon = get_db().execute(
                    "SELECT code, discount_percent FROM coupons "
                    "WHERE code = ? AND active = 1 LIMIT 1",
                    (code,),
                ).fetchone()
        except DATABASE_ERRORS:
            coupon = None
    return render_template(
        "coupon.html",
        code=code,
        coupon=coupon,
        checked=checked,
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

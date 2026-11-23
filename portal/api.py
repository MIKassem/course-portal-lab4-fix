import re

from flask import Blueprint, jsonify, request
from flask_login import current_user
from sqlalchemy import func

from .models import User, db
from .policy import signed_in

bp = Blueprint("api", __name__, url_prefix="/api")

EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


@bp.get("/me")
@signed_in
def me():
    return jsonify(id=current_user.id, username=current_user.username,
                   role=current_user.role, email=current_user.email)


# Was PUT /api/users/<id>/email: the client chose whose address changed (attack 5).
# Now there is no id in the URL. The server takes the user from the session, so
# a user can only ever change their own address.
@bp.put("/me/email")
@signed_in
def set_my_email():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    if not EMAIL.fullmatch(email) or len(email) > 120:
        return jsonify(error="invalid address"), 400
    # An address that already belongs to someone else is refused: the inbox and
    # password reset mail are found by address, so sharing one would let lina
    # read dr_haddad's reset link again. (A real portal would also mail a
    # confirmation link to the new address and switch only once it is opened.)
    taken = User.query.filter(func.lower(User.email) == email, User.id != current_user.id).first()
    if taken:
        return jsonify(error="address not available"), 409
    current_user.email = email
    db.session.commit()
    return jsonify(status="ok")

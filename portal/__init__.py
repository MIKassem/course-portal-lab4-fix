import os
import secrets

from flask import Flask, Response
from flask_login import LoginManager

from .models import User, db


def _secret_key(app):
    """The key that signs the session cookie. Never a value written in the source:
    anyone who knows it can forge a session for any user. Taken from PORTAL_SECRET,
    or made once at random and kept in instance/secret_key (git-ignored)."""
    if os.environ.get("PORTAL_SECRET"):
        return os.environ["PORTAL_SECRET"]
    path = os.path.join(app.instance_path, "secret_key")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)
    app.config["SECRET_KEY"] = _secret_key(app)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
        app.instance_path, "portal.db")
    if os.environ.get("PORTAL_DB"):  # tooling hook: an explicit SQLite file path
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.environ["PORTAL_DB"]

    # Session cookie attributes.
    # These two work on a plain http:// server like this lab:
    #   HttpOnly      page scripts cannot read the cookie (an XSS cannot steal it)
    #   SameSite=Lax  not sent on cross-site POSTs and cross-site subrequests
    #                 (but still sent on a top-level GET link, and the browser
    #                 does not count 127.0.0.1:8000 -> 127.0.0.1:5002 as cross-site)
    # These need HTTPS:
    #   Secure        the browser only sends the cookie over https://. On http://
    #                 it would be dropped (localhost is a browser exception, not
    #                 something to rely on), so it is False here and must be True
    #                 in production.
    #   a "__Host-" name prefix (e.g. __Host-session) needs Secure, so also HTTPS.
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("PORTAL_HTTPS") == "1",
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(uid):
        return db.session.get(User, int(uid))

    from . import auth
    app.register_blueprint(auth.bp)
    from . import api, courses, staff
    app.register_blueprint(courses.bp)
    app.register_blueprint(staff.bp)
    app.register_blueprint(api.bp)

    from . import policy

    @app.get("/robots.txt")
    @policy.public
    def robots():
        # robots.txt is public. It must not list the pages you want hidden:
        # it is the first file an attacker reads. Access control protects them now.
        return Response("User-agent: *\nDisallow:\n", mimetype="text/plain")

    policy.install(app)

    with app.app_context():
        db.create_all()
        if not app.config.get("TESTING") and User.query.first() is None:
            from .seed import seed
            seed()
    return app

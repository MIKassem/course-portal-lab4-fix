"""Access control policy for the Course Portal.

  ROLE_PERMISSIONS   RBAC: which permissions each role could ever use
  CONDITIONS         ABAC: one function per permission, (user, obj, ctx) -> bool
  can()              step 1 RBAC, step 2 ABAC; anything unknown is denied
  requires()         declare the permission a route needs, next to the route
  install(app)       one before_request hook that checks every request

Every route states its rule with @requires(...), @signed_in or @public. The hook
in install() is the only place that decides; the views contain no access checks.
"""
import ipaddress
from datetime import timedelta

from flask import Response, current_app, g, request, session
from flask_login import current_user

from . import csrf
from .models import utcnow

# --------------------------------------------------------------------------
# Step 1, RBAC: the permissions each role could ever use.
# A role that is not listed, or a permission that is not listed, is denied.
# --------------------------------------------------------------------------
ROLE_PERMISSIONS = {
    "student":    frozenset({"view_material", "submit", "view_grade"}),
    "ta":         frozenset({"view_material", "grade", "view_gradebook"}),
    "instructor": frozenset({"view_material", "create_assignment", "grade", "change_grade",
                             "view_gradebook", "release_grades"}),
    "registrar":  frozenset({"enroll", "manage_roles", "assign_staff"}),
    # N1: the chair may read gradebooks and holds no permission that writes a grade.
    "chair":      frozenset({"view_gradebook"}),
}
ROLES = frozenset(ROLE_PERMISSIONS)

# N2: how long after the deadline an approved extension lets a student submit.
EXTENSION_GRACE = timedelta(days=3)

# N3: the networks that count as campus. 127.0.0.0/8 is the lab machine itself.
CAMPUS_NETWORKS = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.0/8"))


# --------------------------------------------------------------------------
# Step 2, ABAC: one condition per permission, (user, obj, ctx) -> bool.
# obj is the record the request is about, already loaded by the hook.
# ctx is built by the server for each request: {"network": "campus" | "external"}.
# Every condition fails closed: a missing object or a missing fact means False.
# The current time is always the server's clock (utcnow), never a request value.
# --------------------------------------------------------------------------
def _view_material(user, course, ctx):           # R1
    return course is not None and course.id in (user.enrolled_in | user.staff_of)


def _submit(user, assignment, ctx):              # R2, N2
    if assignment is None or assignment.course_id not in user.enrolled_in:
        return False
    now = utcnow()
    if now < assignment.deadline:
        return True
    # N2: after the deadline only with an approved extension, and only for 3 days.
    return (assignment.id in user.approved_extensions
            and now < assignment.deadline + EXTENSION_GRACE)


def _view_grade(user, sub, ctx):                 # R3
    return sub is not None and sub.student_id == user.id and sub.released


def _create_assignment(user, course, ctx):       # R4
    if course is None:                           # the empty form: teaches at least one course
        return bool(user.teaches)
    return course.id in user.teaches


def _grade(user, sub, ctx):                      # R5, N4
    return (sub is not None
            and sub.course_id in user.staff_of
            and not sub.released
            # N4: nobody grades a course they are enrolled in as a student.
            and sub.course_id not in user.enrolled_in)


def _change_grade(user, sub, ctx):               # R5, N3
    if sub is None or sub.course_id not in user.teaches:
        return False
    if utcnow() >= sub.course.grade_deadline:
        return False
    if sub.course_id in user.enrolled_in:        # same conflict of interest as N4
        return False
    # N3: a released grade changes only from the campus network.
    if sub.released and (ctx or {}).get("network") != "campus":
        return False
    return True


def _enroll(user, course, ctx):                  # R6: no condition
    return True


def _view_gradebook(user, course, ctx):          # attack 2, N1
    return course is not None and (course.id in user.staff_of
                                   or course.department in user.chair_of)


def _release_grades(user, course, ctx):          # attack 3
    return course is not None and course.id in user.teaches


def _manage_roles(user, obj, ctx):               # attack 1: registrar only, no condition
    return True


def _assign_staff(user, course, ctx):            # attack 7: registrar only, no condition
    return True


CONDITIONS = {
    "view_material": _view_material,
    "submit": _submit,
    "view_grade": _view_grade,
    "create_assignment": _create_assignment,
    "grade": _grade,
    "change_grade": _change_grade,
    "enroll": _enroll,
    "view_gradebook": _view_gradebook,
    "release_grades": _release_grades,
    "manage_roles": _manage_roles,
    "assign_staff": _assign_staff,
}


def role_holds(user, perm):
    """Step 1 alone: could this kind of user ever use this function?"""
    return perm in ROLE_PERMISSIONS.get(getattr(user, "role", None), ())


def can(user, perm, obj=None, ctx=None):
    """Step 1 (RBAC), then step 2 (ABAC). Anything unknown is denied."""
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if not role_holds(user, perm):                       # step 1
        return False
    condition = CONDITIONS.get(perm)
    if condition is None:                                # a permission nobody defined
        return False
    try:
        return condition(user, obj, ctx or {}) is True   # step 2
    except Exception:                                    # a broken rule denies, it never allows
        current_app.logger.exception("policy condition %s raised", perm)
        return False


# --------------------------------------------------------------------------
# The request context. Built by the server, never taken from the request body
# or from a header the client writes.
# --------------------------------------------------------------------------
def network_of(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except (TypeError, ValueError):
        return "external"
    return "campus" if any(ip in net for net in CAMPUS_NETWORKS) else "external"


def request_context():
    # N3: request.remote_addr is the address of the TCP peer, set by the server
    # from the socket. X-Forwarded-For, X-Real-IP and the like are ignored: any
    # client can write them. (Behind a reverse proxy, use werkzeug's ProxyFix
    # with the exact number of trusted proxies, and nothing else.)
    return {"network": network_of(request.remote_addr)}


# --------------------------------------------------------------------------
# Declaring a rule next to each route.
# --------------------------------------------------------------------------
PUBLIC = "@public"
SIGNED_IN = "@signed_in"


class Rule:
    def __init__(self, perm, load=None, hide=False):
        self.perm = perm      # a permission name, PUBLIC or SIGNED_IN
        self.load = load      # loader(**view_args) -> the object, or None if it does not exist
        self.hide = hide      # True: a failed condition answers 404, as if the record did not exist


def requires(perm, load=None, hide=False):
    """@requires("grade", load=lambda sid: db.session.get(Submission, sid), hide=True)"""
    def deco(f):
        f.access_rule = Rule(perm, load, hide)
        return f
    return deco


public = requires(PUBLIC)        # anyone, signed in or not
signed_in = requires(SIGNED_IN)  # any signed-in user, no permission needed


# --------------------------------------------------------------------------
# One hook for every request.
# --------------------------------------------------------------------------
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_DENIAL_PAGES = {
    401: '<!doctype html><title>Sign in</title><p>Please <a href="/login">sign in</a>.</p>',
    403: "<!doctype html><title>Forbidden</title><p>Forbidden.</p>",
    404: "<!doctype html><title>Not found</title><p>Not found.</p>",
}


def _log_denial(status, reason, perm=None):
    user = current_user.username if current_user.is_authenticated else "-"
    current_app.logger.warning(
        "ACCESS DENIED status=%s user=%s ip=%s %s %r endpoint=%s perm=%s reason=%s",
        status, user, request.remote_addr, request.method, request.path,
        request.endpoint, perm, reason)


def _deny(status, reason, perm=None):
    _log_denial(status, reason, perm)
    return Response(_DENIAL_PAGES[status], status=status, mimetype="text/html")


def _enforce():
    # A URL that matches no route, or a method the route does not accept, gets
    # Flask's own 404 or 405. No view runs, so there is nothing to protect.
    if request.routing_exception is not None or request.endpoint is None:
        if getattr(request.routing_exception, "code", None) == 405:
            # e.g. GET /staff/release/1 (step 17): logged, then Flask answers 405.
            _log_denial(405, "method not allowed on this route")
        return None
    if request.endpoint == "static":
        return None
    view = current_app.view_functions.get(request.endpoint)
    rule = getattr(view, "access_rule", None)

    # 1. CSRF, first of all and for every route, public ones included: a request
    #    that can change data must carry this session's token whenever the
    #    session cookie carries any authority (a signed-in user) or a token.
    #    A signed-in session always has a token: login makes one. Decided on the
    #    session cookie itself, because that cookie is what a forged request borrows.
    if request.method not in SAFE_METHODS:
        if ("_user_id" in session or csrf.FIELD in session) and not csrf.valid():
            return _deny(403, "missing or wrong CSRF token", rule and rule.perm)

    # 2. Public pages: login, forgot, reset, robots.txt.
    if rule is not None and rule.perm == PUBLIC:
        return None

    # 3. Everything else needs a signed-in user.
    if not current_user.is_authenticated:
        return _deny(401, "not signed in", rule and rule.perm)

    # 4. Deny by default: a route that nobody gave a rule is refused, not left open.
    if rule is None:
        return _deny(403, "route has no access rule")
    if rule.perm == SIGNED_IN:
        return None

    # 5. RBAC before anything is loaded. A role that can never use this function
    #    is refused without the server touching the object, so the answer is the
    #    same whether the object exists or not: nothing leaks.
    if not role_holds(current_user, rule.perm):
        return _deny(403, "role does not hold the permission", rule.perm)

    # 6. Load the object the route is about, then check the condition (ABAC).
    obj = rule.load(**(request.view_args or {})) if rule.load else None
    if rule.load and obj is None:
        return _deny(404, "object not found", rule.perm)
    if not can(current_user, rule.perm, obj, request_context()):
        # For a record that belongs to someone else, a refusal looks exactly
        # like a missing record: 404, so ids cannot be probed.
        return _deny(404 if rule.hide else 403, "condition failed", rule.perm)
    g.obj = obj
    return None


def install(app):
    app.before_request(_enforce)
    # Templates call csrf_token() for the hidden field and the meta tag.
    app.jinja_env.globals["csrf_token"] = csrf.token

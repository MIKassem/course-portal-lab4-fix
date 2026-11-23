from markupsafe import escape
from datetime import datetime

from flask import Blueprint, g, render_template, request

from .courses import load_course
from .models import Assignment, Course, CourseTA, Enrollment, Submission, User, db
from .policy import ROLES, requires

bp = Blueprint("staff", __name__)

# The blueprint-level "instructors only for writes" hook is gone: it checked
# POST only, so GET slipped past it (attack 3). The global hook in policy.py
# now decides for every route and every method.


def load_course_from_form():
    try:
        cid = int(request.form.get("course_id", ""))
    except ValueError:
        return None
    return db.session.get(Course, cid)


@bp.post("/staff/release/<int:cid>")      # POST only: a GET must never change data
@requires("release_grades", load=load_course)
def release(cid):
    for sub in Submission.query.join(Assignment).filter(Assignment.course_id == cid):
        sub.released = True
    db.session.commit()
    return f"Grades released for {escape(g.obj.code)}."


@bp.get("/staff/assignments/new")
@requires("create_assignment")
def new_assignment_form():
    return render_template("course_new_assignment.html")


@bp.post("/staff/assignments/new")
@requires("create_assignment", load=load_course_from_form)
def new_assignment():
    try:
        deadline = datetime.fromisoformat(request.form.get("deadline", ""))
    except ValueError:
        return "Invalid deadline.", 400
    title = request.form.get("title", "").strip()
    if not title:
        return "A title is required.", 400
    db.session.add(Assignment(course_id=g.obj.id, title=title, deadline=deadline))
    db.session.commit()
    return f"Assignment added to course {g.obj.id}."


# The registrar console keeps its address, but the address is no longer what
# protects it: the manage_roles and enroll permissions do.
@bp.get("/registrar-x9k2")
@requires("manage_roles")
def registrar_console():
    return render_template("registrar_console.html", users=User.query.all())


@bp.post("/registrar-x9k2/role")
@requires("manage_roles")
def set_role():
    user = User.query.filter_by(username=request.form.get("username", "")).first_or_404()
    role = request.form.get("role", "")
    if role not in ROLES:
        return "Unknown role.", 400
    user.role = role
    db.session.commit()
    return f"Role of {escape(user.username)} set to {escape(user.role)}."


@bp.post("/registrar-x9k2/enroll")
@requires("enroll", load=load_course_from_form)
def enroll():
    user = User.query.filter_by(username=request.form.get("username", "")).first_or_404()
    if g.obj.id not in user.enrolled_in:
        db.session.add(Enrollment(user_id=user.id, course_id=g.obj.id))
        db.session.commit()
    return f"{escape(user.username)} enrolled in course {g.obj.id}."


@bp.get("/registrar")
@requires("assign_staff")
def registrar():
    return render_template("registrar.html", courses=Course.query.all())


@bp.post("/courses/<int:cid>/staff/add")
@requires("assign_staff", load=load_course)
def add_ta(cid):
    # No Referer check: the decision is the registrar's role, from the database.
    user = User.query.filter_by(username=request.form.get("username", "")).first_or_404()
    if cid not in user.assists:
        db.session.add(CourseTA(user_id=user.id, course_id=cid))
        db.session.commit()
    return f"{escape(user.username)} added as TA of {escape(g.obj.code)}."

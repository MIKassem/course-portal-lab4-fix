from markupsafe import escape
from flask import Blueprint, g, render_template, request, session
from flask_login import current_user

from .models import Assignment, Course, Submission, db
from .policy import requires, signed_in

bp = Blueprint("courses", __name__)

GRADES = {"A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "F"}


# Loaders: how the hook finds the object a route is about. None means "no such record".
def load_course(cid):
    return db.session.get(Course, cid)


def load_assignment(aid):
    return db.session.get(Assignment, aid)


def load_submission(sid):
    return db.session.get(Submission, sid)


@bp.get("/")
@signed_in
def dashboard():
    ids = current_user.enrolled_in | current_user.staff_of
    courses = Course.query.filter(Course.id.in_(ids)).all() if ids else []
    return render_template("dashboard.html", courses=courses)


@bp.get("/courses/<int:cid>/materials")
@requires("view_material", load=load_course)
def materials(cid):
    return render_template("materials.html", course=g.obj)


@bp.post("/assignments/<int:aid>/submit")
@requires("submit", load=load_assignment)
def submit(aid):
    sub = Submission.query.filter_by(assignment_id=aid, student_id=current_user.id).first()
    if sub is None:
        sub = Submission(assignment_id=aid, student_id=current_user.id)
        db.session.add(sub)
    sub.body = request.form.get("body", "")
    db.session.commit()
    return render_template("submission.html", sub=sub)


@bp.get("/submissions/<int:sid>")
@requires("view_grade", load=load_submission, hide=True)
def view_submission(sid):
    return render_template("submission.html", sub=g.obj)


@bp.post("/submissions/<int:sid>/grade")
@requires("grade", load=load_submission, hide=True)
def grade(sid):
    value = request.form.get("grade", "")
    if value not in GRADES:
        return "Invalid grade.", 400
    g.obj.grade = value
    db.session.commit()
    return f"Grade for submission {g.obj.id} set to {escape(g.obj.grade)}."


@bp.post("/submissions/<int:sid>/change")
@requires("change_grade", load=load_submission, hide=True)
def change(sid):
    # Step 1. The server remembers what it approved, in the session. Step 2
    # confirms that, and nothing the client sends instead.
    value = request.form.get("grade", "")
    if value not in GRADES:
        return "Invalid grade.", 400
    session["pending_grade_change"] = {"sid": sid, "grade": value}
    return render_template("change_confirm.html", sub=g.obj, grade=value)


@bp.post("/submissions/<int:sid>/change/confirm")
@requires("change_grade", load=load_submission, hide=True)
def change_confirm(sid):
    # Step 2 checks for itself: the same rule as step 1 (change_grade, by the
    # hook), plus "step 1 was done, for this submission, in this session".
    pending = session.pop("pending_grade_change", None)
    if request.form.get("confirmed") != "true" or not pending or pending["sid"] != sid:
        return "Change cancelled."
    g.obj.grade = pending["grade"]
    db.session.commit()
    return f"Grade for submission {g.obj.id} changed to {escape(g.obj.grade)}."


@bp.get("/gradebook/<int:cid>")
@requires("view_gradebook", load=load_course)
def gradebook(cid):
    subs = (Submission.query.join(Assignment)
            .filter(Assignment.course_id == cid).all())
    return render_template("gradebook.html", course=g.obj, subs=subs)

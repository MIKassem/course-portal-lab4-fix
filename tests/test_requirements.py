"""N1 to N4: the four new requirements. Three tests each, at least two denials each.

Each requirement is enforced in the model (portal/policy.py and portal/models.py),
not by an `if` in a view, so most tests ask can() directly; one test per rule also
goes through HTTP to show the hook applies it.
"""
from datetime import timedelta

from conftest import login
from portal.models import Course, Extension, Submission, db, utcnow
from portal.policy import can

CAMPUS = {"network": "campus"}
EXTERNAL = {"network": "external"}


# ---------------------------------------------------------------- N1 ----
# A department chair can view (not change) the grades of every course in
# their department.

def test_n1_chair_views_gradebook_of_own_department(client, world):
    assert can(world["chair"], "view_gradebook", world["cmps215"], CAMPUS) is True
    assert can(world["chair"], "view_gradebook", world["cmps202"], CAMPUS) is True
    login(client, "chair")
    r = client.get("/gradebook/1")
    assert r.status_code == 200
    assert "A1 Threat model" in r.get_data(as_text=True)


def test_n1_chair_cannot_view_another_department(world):
    math = Course(code="MATH 201", title="Calculus", department="MATH", instructor_id=3,
                  grade_deadline=utcnow() + timedelta(days=30))
    db.session.add(math)
    db.session.commit()
    assert can(world["chair"], "view_gradebook", math, CAMPUS) is False


def test_n1_chair_cannot_change_any_grade(client, world):
    assert can(world["chair"], "grade", world["sub_open_215"], CAMPUS) is False
    assert can(world["chair"], "change_grade", world["sub_rel_215"], CAMPUS) is False
    assert can(world["chair"], "release_grades", world["cmps215"], CAMPUS) is False
    login(client, "chair")
    r = client.post("/submissions/2/grade", data={"grade": "A+"})
    assert r.status_code == 403
    db.session.expire_all()
    assert db.session.get(Submission, 2).grade is None


# ---------------------------------------------------------------- N2 ----
# A student with an approved extension can submit up to 3 days after the deadline.

def test_n2_approved_extension_allows_a_late_submission(client, world):
    # A3 closed an hour ago.
    db.session.add(Extension(user_id=world["lina"].id, assignment_id=world["a3_late"].id,
                             approved=True, approved_by=world["dr_haddad"].id))
    db.session.commit()
    assert can(world["lina"], "submit", world["a3_late"], CAMPUS) is True
    login(client, "lina")
    r = client.post(f"/assignments/{world['a3_late'].id}/submit", data={"body": "late lab"})
    assert r.status_code == 200


def test_n2_extension_not_yet_approved_is_refused(world):
    db.session.add(Extension(user_id=world["lina"].id, assignment_id=world["a3_late"].id,
                             approved=False))
    db.session.commit()
    assert can(world["lina"], "submit", world["a3_late"], CAMPUS) is False


def test_n2_extension_ends_three_days_after_the_deadline(world):
    # A1 closed 10 days ago: an approved extension does not reach that far.
    a1 = world["sub_released"].assignment
    db.session.add(Extension(user_id=world["lina"].id, assignment_id=a1.id, approved=True,
                             approved_by=world["dr_haddad"].id))
    db.session.commit()
    assert can(world["lina"], "submit", a1, CAMPUS) is False


# ---------------------------------------------------------------- N3 ----
# Instructors can change a released grade only from the campus network.

def test_n3_instructor_changes_released_grade_from_campus(client, world):
    assert can(world["dr_haddad"], "change_grade", world["sub_rel_215"], CAMPUS) is True
    login(client, "dr_haddad")
    r = client.post("/submissions/1/change", data={"grade": "A"},
                    environ_base={"REMOTE_ADDR": "10.20.30.40"})
    assert r.status_code == 200


def test_n3_external_network_is_refused(world):
    assert can(world["dr_haddad"], "change_grade", world["sub_rel_215"], EXTERNAL) is False
    assert can(world["dr_haddad"], "change_grade", world["sub_rel_215"], {}) is False


def test_n3_forged_forwarded_header_from_outside_is_refused(client):
    login(client, "dr_haddad")
    # The request comes from 203.0.113.7 and claims, in headers it wrote itself,
    # to come from campus. The server reads the TCP peer address, not the headers.
    outside = {"REMOTE_ADDR": "203.0.113.7"}
    forged = {"X-Forwarded-For": "10.0.0.5", "X-Real-IP": "10.0.0.5"}
    r = client.post("/submissions/1/change", data={"grade": "A+"},
                    environ_base=outside, headers=forged)
    assert r.status_code in (403, 404)
    r = client.post("/submissions/1/change/confirm", data={"confirmed": "true"},
                    environ_base=outside, headers=forged)
    assert r.status_code in (403, 404)
    db.session.expire_all()
    assert db.session.get(Submission, 1).grade == "B"


# ---------------------------------------------------------------- N4 ----
# A TA who is also enrolled in a course must never grade that course.

def test_n4_enrolled_ta_cannot_grade_a_classmate(client, world):
    # rana: TA of CMPS 202 and enrolled in CMPS 202. Make sami's submission gradable.
    world["sub_sami"].released = False
    db.session.commit()
    assert can(world["rana_ta"], "grade", world["sub_sami"], CAMPUS) is False
    login(client, "rana")
    r = client.post(f"/submissions/{world['sub_sami'].id}/grade", data={"grade": "F"})
    assert r.status_code in (403, 404)
    db.session.expire_all()
    assert db.session.get(Submission, world["sub_sami"].id).grade == "A-"


def test_n4_enrolled_ta_cannot_grade_her_own_submission(world):
    # Submission 4 is rana's own B1, not released.
    assert world["sub_open_202"].student_id == world["rana_ta"].id
    assert can(world["rana_ta"], "grade", world["sub_open_202"], CAMPUS) is False


def test_n4_ta_not_enrolled_still_grades(world):
    # omar is TA of CMPS 215 and not enrolled in it: N4 must not stop him.
    assert can(world["omar_ta"], "grade", world["sub_open_215"], CAMPUS) is True

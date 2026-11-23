"""CSRF token: proves that a request came from one of the portal's own pages.

The session cookie says who the user is, and the browser attaches it to any
request for the portal, whoever's page started it. The token is a secret that
only the portal's own pages know: it lives in the (signed) session and is
written into every form and into a <meta> tag. Another site's page cannot read
it (same-origin policy), so it cannot put it in a forged request.

  Create  new_token() at login: 32 random bytes, a fresh one for every login.
  Embed   token() in every form (hidden field csrf_token) and in
          <meta name="csrf-token" content="...">.
  Check   valid() in the before_request hook, for every request that can
          change data: the field csrf_token or the header X-CSRF-Token must
          equal this session's token, compared in constant time.
"""
import hmac
import secrets

from flask import request, session

FIELD = "csrf_token"
HEADER = "X-CSRF-Token"


def new_token():
    """A new random token for this session: 256 bits, URL-safe text."""
    session[FIELD] = secrets.token_urlsafe(32)
    return session[FIELD]


def token():
    """The current session's token, made on first use (also for the sign-in form)."""
    return session.get(FIELD) or new_token()


def valid():
    expected = session.get(FIELD)
    sent = request.headers.get(HEADER) or request.form.get(FIELD)
    if not expected or not sent:
        return False
    # Constant time: the comparison takes as long whatever the first wrong byte is.
    return hmac.compare_digest(expected.encode(), sent.encode())

"""Set up DVWA's database: its "Setup DVWA -> Create / Reset Database" step.

DVWA's database lives in memory, so it is empty whenever dvwa-db starts, and DVWA can't be used
until its tables exist. `make lab` runs this inside the worker container, the only VulnScope
service on the lab network. By default it only sets up a database that is still empty, so running
`make lab` again never wipes changes made in DVWA; `--reset` (`make lab-reset-dvwa`) always does.
It uses only the standard library because the lab has no internet.
"""

import http.cookiejar
import re
import secrets
import sys
import time
import urllib.parse
import urllib.request

BASE_URL = "http://dvwa"
DEADLINE_SECONDS = 120  # DVWA and its database can take a while to start
_TOKEN = re.compile(r"name='user_token' value='([0-9a-f]+)'")


def _session() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) ignores any http_proxy in the environment: "dvwa" only resolves inside
    # the lab network, so a proxy could never reach it.
    cookies = urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), cookies)


def _post_form(
    opener: urllib.request.OpenerDirector, path: str, form: dict[str, str]
) -> tuple[str, str]:
    """GET the page for its CSRF token, POST the form. Returns (final URL, page text)."""
    page = opener.open(f"{BASE_URL}{path}", timeout=10).read().decode("utf-8", "replace")
    token = _TOKEN.search(page)
    if token is None:
        raise OSError(f"{path} has no CSRF token yet")
    body = urllib.parse.urlencode({**form, "user_token": token.group(1)}).encode()
    response = opener.open(f"{BASE_URL}{path}", data=body, timeout=60)
    text = response.read().decode("utf-8", "replace")
    return response.geturl(), " ".join(re.sub(r"<[^>]+>", " ", text).split())


def needs_setup() -> bool:
    """Log in as a random, non-existent user. Without tables DVWA redirects to setup.php; with
    them it answers "Login failed". Real accounts and passwords are never touched."""
    form = {"username": f"setup-probe-{secrets.token_hex(4)}", "password": "x", "Login": "Login"}
    url, _ = _post_form(_session(), "/login.php", form)
    return url.endswith("/setup.php")


def create_database() -> bool:
    _, text = _post_form(_session(), "/setup.php", {"create_db": "Create / Reset Database"})
    return "Setup successful" in text


def main(reset: bool) -> int:
    deadline = time.monotonic() + DEADLINE_SECONDS
    last_problem = "no answer"
    # Probe only until this run starts setting up: a failed attempt can leave DVWA's users table
    # behind, and a later probe would then mistake the half-built database for a finished one.
    setup_started = False
    while time.monotonic() < deadline:
        try:
            if not reset and not setup_started and not needs_setup():
                print("DVWA is already set up; leaving its data alone.")
                return 0
            setup_started = True
            if create_database():
                print("DVWA database created (log in at http://dvwa as admin / password).")
                return 0
            last_problem = "DVWA answered, but setup did not succeed (database not ready?)"
        except OSError as exc:
            last_problem = str(exc)
        time.sleep(3)
    print(f"Could not set up DVWA within {DEADLINE_SECONDS}s: {last_problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(reset="--reset" in sys.argv[1:]))

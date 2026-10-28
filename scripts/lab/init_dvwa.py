"""Create DVWA's database tables: its "Setup DVWA -> Create / Reset Database" step.

DVWA's database lives in memory, so it starts empty every time the lab starts, and DVWA can't be
used until this has run. `make lab` runs it inside the worker container, the only VulnScope
service on the lab network. It uses only the standard library because the lab has no internet.
"""

import http.cookiejar
import re
import sys
import time
import urllib.parse
import urllib.request

SETUP_URL = "http://dvwa/setup.php"
DEADLINE_SECONDS = 120  # DVWA and its database can take a while to start


def create_database() -> str:
    """One attempt. Returns DVWA's response text, or raises OSError if it isn't up yet."""
    cookies = urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    opener = urllib.request.build_opener(cookies)
    page = opener.open(SETUP_URL, timeout=10).read().decode("utf-8", "replace")
    token = re.search(r"name='user_token' value='([0-9a-f]+)'", page)
    if token is None:
        raise OSError("setup page has no CSRF token yet")
    form = {"create_db": "Create / Reset Database", "user_token": token.group(1)}
    body = urllib.parse.urlencode(form).encode()
    result = opener.open(SETUP_URL, data=body, timeout=60).read().decode("utf-8", "replace")
    return " ".join(re.sub(r"<[^>]+>", " ", result).split())


def main() -> int:
    deadline = time.monotonic() + DEADLINE_SECONDS
    last_problem = "no answer"
    while time.monotonic() < deadline:
        try:
            text = create_database()
        except OSError as exc:
            last_problem = str(exc)
        else:
            if "Setup successful" in text:
                print("DVWA database created (log in at http://dvwa as admin / password).")
                return 0
            last_problem = "DVWA answered, but setup did not succeed (database not ready?)"
        time.sleep(3)
    print(f"Could not set up DVWA within {DEADLINE_SECONDS}s: {last_problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

"""System facts derived from the signals the analysers collected.

A fact is emitted only when the code shows it. Where the scan has seen the code a fact is about (the places a
password is set, the login route) and found nothing that establishes it, the fact is emitted as false (or 0 /
100000 for lengths) at those places; where it has not, the fact is left out.

A repository may hold several deployable applications (a back end and a front end, or a set of labs). Evidence is
grouped by *app root*, the nearest directory holding a manifest (package.json, pyproject.toml, setup.py,
requirements.txt, Pipfile, manage.py, Dockerfile); each application contributes its own observations, so the
system's fact is the set of values its applications show.
"""

from __future__ import annotations

from typing import Callable

from .common import SOURCE, Collector

MAX_LOCATORS = 8
NO_MAX = 100000


def _sort_key(at: str):
    path, _, line = at.rpartition(":")
    return (path, int(line) if line.isdigit() else 0)


def _ats(sigs, n=MAX_LOCATORS) -> list[str]:
    return sorted({s[1] for s in sigs}, key=_sort_key)[:n]


def _obs(value, ats) -> list[dict]:
    return [{"value": value, "source": SOURCE, "at": a} for a in ats]


def _absent(value, ats) -> list[dict]:
    """Observations of what the code is taken to do because no rule was found (no length check: minimum 0). They
    cite where the rule was looked for, and any source that read the rule itself outranks them."""
    return [{**o, "basis": "absence"} for o in _obs(value, ats)]


def _path(at: str) -> str:
    return at.rpartition(":")[0]


def _merge(obs: list[dict]) -> list[dict]:
    """One observation per (value, locator), ordered by value then place."""
    seen, out = set(), []
    for o in sorted(obs, key=lambda o: (str(type(o["value"])), o["value"], _sort_key(o["at"]))):
        k = (o["value"], o["at"])
        if k not in seen:
            seen.add(k)
            out.append(o)
    return out


POLICY_SIGNALS = ("pw_set_site", "pw_validation", "pw_min", "pw_max", "pw_composition", "pw_blocklist", "pw_expiry",
                  "django_pw_min", "django_pw_validation", "django_pw_composition", "django_pw_blocklist", "django_validators_used")


def derive(out: Collector, app_root: Callable[[str], str] = lambda rel: "", is_client: Callable[[str], bool] = lambda rel: False) -> dict:
    """`is_client(rel)`: the file runs in the browser. A password policy is what the server enforces, so browser-side
    checks count only when the scan saw no server-side policy code at all (an API whose server is elsewhere)."""
    root_of = lambda s: app_root(_path(s[1]))  # noqa: E731
    client_sig = lambda s: s[2].get("side") == "client" or is_client(_path(s[1]))  # noqa: E731
    server_policy = any(not client_sig(s) for name in POLICY_SIGNALS for s in out.signals.get(name, []))

    def sig(name):
        got = out.signals.get(name, [])
        return [s for s in got if not client_sig(s)] if server_policy and name in POLICY_SIGNALS else got
    facts: dict[str, list[dict]] = {}

    stores = [(None, at, {}) for (t, at) in out.elements if t == "PasswordStore"]
    auth = sig("pw_auth") + stores
    if auth:
        facts["password_auth"] = _obs(True, _ats(auth))

    # ---- password policy, per application
    roots = sorted({root_of(s) for name in ("pw_set_site", "pw_validation", "pw_min", "pw_max", "django_pw_min")
                    for s in sig(name)})
    mins, maxs, comps, blocks, periodic = [], [], [], [], []
    for r in roots:
        mine = lambda name: [s for s in sig(name) if root_of(s) == r]  # noqa: E731
        wired = bool(mine("django_validators_used"))
        set_sites = mine("pw_set_site")
        server_min = [s for s in mine("pw_min") if s[2].get("side") == "server"] + (mine("django_pw_min") if wired else [])
        server_max = [s for s in mine("pw_max") if s[2].get("side") == "server"]
        client_min = [s for s in mine("pw_min") if s[2].get("side") == "client"]
        client_max = [s for s in mine("pw_max") if s[2].get("side") == "client"]
        for group, target in ((server_min, mins), (client_min, mins), (server_max, maxs), (client_max, maxs)):
            for v in sorted({s[0] for s in group}):
                target += _obs(v, _ats([s for s in group if s[0] == v], 4))
        if set_sites and not server_min:
            mins += _absent(0, _ats(set_sites, 4))
        if set_sites and not server_max:
            maxs += _absent(NO_MAX, _ats(set_sites, 4))
        seen_policy = mine("pw_validation") + (mine("django_pw_validation") if wired else []) + set_sites
        comp = mine("pw_composition") + (mine("django_pw_composition") if wired else [])
        if comp:
            comps += _obs(True, _ats(comp, 4))
        elif seen_policy:
            comps += _absent(False, _ats(seen_policy, 4))
        block = mine("pw_blocklist") + (mine("django_pw_blocklist") if wired else [])
        if block:
            blocks += _obs(True, _ats(block, 4))
        elif seen_policy:
            blocks += _absent(False, _ats(seen_policy, 4))
        if mine("pw_expiry"):
            periodic += _obs(True, _ats(mine("pw_expiry"), 4))
        elif set_sites:
            periodic += _absent(False, _ats(set_sites, 4))
    for name, obs in (("password_min_length", mins), ("password_max_length", maxs), ("password_composition_rules", comps),
                      ("password_blocklist_check", blocks), ("password_periodic_change", periodic)):
        if obs:
            facts[name] = _merge(obs)

    # ---- login rate limiting, per login route
    limited, unlimited = [], []
    for route in sig("login_route"):
        r = root_of(route)
        fw = route[2].get("fw")
        covering = [s for s in sig("rate_limit") + sig("lockout") if root_of(s) == r and (
            s[2].get("scope") == "global" or "scope" not in s[2]  # app-wide limiter or an account lockout
            or s[2].get("route_at") == route[1]
            or (fw is not None and s[2].get("covers") == fw))]
        if covering:
            limited += [(True, a, {}) for a in _ats(covering, 2)]
        else:
            unlimited.append(route)
    obs = _obs(True, _ats(limited, 2 * MAX_LOCATORS)) + _absent(False, _ats(unlimited, 2 * MAX_LOCATORS))
    if not sig("login_route"):
        obs = _obs(True, _ats([s for s in sig("rate_limit") if s[2].get("scope") in {"login", "global"}] + sig("lockout")))
    if obs:
        facts["login_rate_limited"] = _merge(obs)

    # ---- personal data and erasure
    personal = sig("personal_field")
    if personal:
        stored = [s for s in personal if s[2].get("model")]  # fields of a stored model first, then other places
        ats = _ats(stored) + [a for a in _ats(personal, 10 ** 6) if a not in _ats(stored)]
        facts["processes_personal_data"] = _obs(True, ats[:MAX_LOCATORS])
    if sig("user_delete"):
        facts["account_erasure"] = _obs(True, _ats(sig("user_delete")))
    elif personal and (sig("user_model") or auth):
        # nothing deletes a user: cite a recorded erasure request if there is one (the path to check), else the user model
        facts["account_erasure"] = _absent(False, _ats(sig("erasure_request") or sig("user_model") or personal, 4))
    return facts

"""OWASP ASVS 5.0.0 and NIST SP 800-63B-4 packs.

Expected values are read from the standards: ASVS 5.0.0 V1.2.1/4/5, V1.5.2,
V3.3.1/2/4, V3.4.1/3, V3.5.1, V6.2.1/4/5/9/10/12, V6.3.1, V9.1.1/2, V11.4.2 with
Appendix C, V12.2.1, V13.3.1, V13.4.2, V15.2.1, V15.3.3, V16.2.5; SP 800-63B-4
Sec. 3.1.1.2.
"""

from pathlib import Path

import pytest
import yaml

from normir import Evaluator, Residual, load, validate
from normir.evaluate import facts_in
from normir.evidence import load_evidence, run

ROOT = Path(__file__).resolve().parents[1]
ASVS = ROOT / "packs" / "owasp-asvs-5"
NIST = ROOT / "packs" / "nist-800-63b-4"


def check(pack, norm, system=None, element=None):
    return Evaluator(load(pack), system).norm(norm, element)


@pytest.mark.parametrize("pack", [ASVS, NIST])
def test_pack_validates_and_uses_the_vocabulary(pack):
    rs = load(pack)
    errors, warnings = validate(rs)
    assert errors == [] and warnings == []
    assert rs.subject == "system"
    vocab = yaml.safe_load((ROOT / "vocab" / "code.yaml").read_text())["types"]
    for (kind, name), el in rs.elements.items():
        if kind == "predicate":
            typ, attr = name.split(".", 1)
            spec = vocab.get(typ, {}).get("attrs", {}).get(attr)
            if spec is None:
                assert el.data["label"].startswith("(pack-specific)"), name
            else:
                assert (el.data["type"], el.data["kind"], el.data.get("values")) == (spec["type"], spec["kind"], spec.get("values")), name
            continue
        assert el.data["status"] == "draft"
        if pack == ASVS:
            assert el.data["level"] in (1, 2)
            assert el.data["cite"]["section"].startswith("ASVS 5.0 V")
            assert el.data["cite"]["url"].startswith("https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/")
            assert "#v" in el.data["cite"]["url"]
        else:
            assert el.data["cite"]["url"].startswith("https://pages.nist.gov/800-63-4/sp800-63b.html#")
            assert el.data.get("quote")


def test_asvs_is_link_only():
    assert load(ASVS).top.meta["text_policy"] == "link-only"
    assert load(NIST).top.meta["text_policy"] == "public"


# ------------------------------------------------------- minimum length (C7)

PW = {"password_auth": True}


@pytest.mark.parametrize(
    "facts, expected",
    [
        ({"password_min_length": 7, "password_is_sole_factor": False}, False),  # below 8 even with MFA
        ({"password_min_length": 8, "password_is_sole_factor": False}, True),   # MFA: 8 suffices
        ({"password_min_length": 8, "password_is_sole_factor": True}, False),   # single factor needs 15
        ({"password_min_length": 14, "password_is_sole_factor": True}, False),
        ({"password_min_length": 15, "password_is_sole_factor": True}, True),
        ({"password_min_length": 15}, True),                                   # 15 meets both clauses
        ({"password_auth": False, "password_min_length": 0}, True),            # no passwords: out of scope
    ],
)
def test_nist_minimum_length(facts, expected):
    assert check(NIST, "3.1.1.2 minimum length", {**PW, **facts}) is expected


def test_nist_minimum_length_8_without_knowing_the_factors_is_open():
    v = check(NIST, "3.1.1.2 minimum length", {**PW, "password_min_length": 8})
    assert isinstance(v, Residual)
    assert facts_in(v.expr) == ["system.password_is_sole_factor"]


@pytest.mark.parametrize("length, expected", [(7, False), (8, True), (15, True)])
def test_asvs_minimum_length_is_8_whatever_the_factors(length, expected):
    # V6.2.1: at least 8; 15 is only "strongly recommended".
    facts = {**PW, "password_min_length": length, "password_is_sole_factor": True}
    assert check(ASVS, "V6.2.1", facts) is expected


@pytest.mark.parametrize("length, expected", [(63, False), (64, True), (100000, True)])
def test_asvs_maximum_length_at_least_64(length, expected):
    assert check(ASVS, "V6.2.9", {**PW, "password_max_length": length}) is expected


# --------------------------------------- composition, blocklist, rotation, rate (C8-C10)


@pytest.mark.parametrize(
    "pack, norm, fact, good",
    [
        (NIST, "3.1.1.2 no composition rules", "password_composition_rules", False),
        (ASVS, "V6.2.5", "password_composition_rules", False),
        (NIST, "3.1.1.2 blocklist", "password_blocklist_check", True),
        (ASVS, "V6.2.4", "password_blocklist_check", True),
        (NIST, "3.1.1.2 no periodic change", "password_periodic_change", False),
        (ASVS, "V6.2.10", "password_periodic_change", False),
        (NIST, "3.1.1.2 rate limiting", "login_rate_limited", True),
        (ASVS, "V6.3.1", "login_rate_limited", True),
    ],
)
def test_password_policy_flags(pack, norm, fact, good):
    assert check(pack, norm, {**PW, fact: good}) is True
    assert check(pack, norm, {**PW, fact: not good}) is False
    assert check(pack, norm, {"password_auth": False, fact: not good}) is True


def test_asvs_breached_password_check_needs_a_breach_list():
    assert check(ASVS, "V6.2.12", {**PW, "password_blocklist_check": False}) is False
    v = check(ASVS, "V6.2.12", {**PW, "password_blocklist_check": True})
    assert isinstance(v, Residual) and facts_in(v.expr) == ["system.password_blocklist_includes_breached"]
    assert check(ASVS, "V6.2.12", {**PW, "password_blocklist_check": True, "password_blocklist_includes_breached": True}) is True


# ------------------------------------------------------ password hashing (C1)


@pytest.mark.parametrize(
    "store, asvs, nist",
    [
        ({"algorithm": "md5", "salted": False}, False, False),
        ({"algorithm": "md5", "salted": True}, False, False),      # salt does not make md5 a password hash
        ({"algorithm": "sha256", "salted": True}, False, False),
        ({"algorithm": "plaintext", "salted": False}, False, False),
        ({"algorithm": "bcrypt", "salted": True}, True, True),
        ({"algorithm": "argon2", "salted": True}, True, True),
        ({"algorithm": "pbkdf2", "salted": False}, True, False),   # ASVS names no salt; NIST requires one
    ],
)
def test_password_hashing(store, asvs, nist):
    assert check(ASVS, "V11.4.2", element=store) is asvs
    assert check(NIST, "3.1.1.2 salted hashing", element=store) is nist


def test_nist_salt_length():
    assert check(NIST, "3.1.1.2 salt length", element={"algorithm": "bcrypt", "salted": True}) is True
    assert check(NIST, "3.1.1.2 salt length", element={"algorithm": "pbkdf2", "salted": True, "salt_length_bits": 31}) is False
    assert check(NIST, "3.1.1.2 salt length", element={"algorithm": "pbkdf2", "salted": True, "salt_length_bits": 32}) is True
    v = check(NIST, "3.1.1.2 salt length", element={"algorithm": "scrypt", "salted": True})
    assert facts_in(v.expr) == ["PasswordStore.salt_length_bits"]


# ------------------------------------------------------------- injection (C2)


@pytest.mark.parametrize(
    "query, expected",
    [
        ({"construction": "concatenated", "untrusted_input": True}, False),
        ({"construction": "interpolated", "untrusted_input": True}, False),
        ({"construction": "operator_object", "untrusted_input": True}, False),  # NoSQL operator injection
        ({"construction": "parameterized", "untrusted_input": True}, True),
        ({"construction": "orm", "untrusted_input": True}, True),
        ({"construction": "concatenated", "untrusted_input": False}, True),     # constant text only
    ],
)
def test_query_injection(query, expected):
    assert check(ASVS, "V1.2.4", element=query) is expected


# --------------------------------------------------------------- cookies (C3)


def test_cookie_attributes_apply_to_session_cookies_only():
    bare = {"secure": False, "http_only": False, "same_site": "unset"}
    for norm in ("V3.3.1", "V3.3.2", "V3.3.4"):
        assert check(ASVS, norm, element={**bare, "is_session": False}) is True
        assert check(ASVS, norm, element={**bare, "is_session": True}) is False
    good = {"is_session": True, "secure": True, "http_only": True, "same_site": "lax"}
    for norm in ("V3.3.1", "V3.3.2", "V3.3.4"):
        assert check(ASVS, norm, element=good) is True


def test_session_cookie_samesite_none_depends_on_purpose():
    c = {"is_session": True, "same_site": "none"}
    v = check(ASVS, "V3.3.2", element=c)
    assert facts_in(v.expr) == ["Cookie.cross_site_by_design"]
    assert check(ASVS, "V3.3.2", element={**c, "cross_site_by_design": False}) is False
    assert check(ASVS, "V3.3.2", element={**c, "same_site": "strict"}) is True


def test_cookie_with_unknown_session_role_is_open():
    v = check(ASVS, "V3.3.4", element={"http_only": False})
    assert facts_in(v.expr) == ["Cookie.is_session"]


# -------------------------------------------- tokens, secrets, logging (C4-C6)


def test_token_verification():
    assert check(ASVS, "V9.1.1", element={"verifies_signature": True}) is True
    assert check(ASVS, "V9.1.1", element={"verifies_signature": False}) is False   # jwt.decode without verify
    assert check(ASVS, "V9.1.2", element={"allows_none_alg": False}) is True
    assert check(ASVS, "V9.1.2", element={"allows_none_alg": True}) is False


def test_secrets_and_logs():
    assert check(ASVS, "V13.3.1", element={"kind": "signing_key", "test_or_example": False}) is False
    assert check(ASVS, "V13.3.1", element={"kind": "password", "test_or_example": True}) is True
    assert isinstance(check(ASVS, "V13.3.1", element={"kind": "api_key"}), Residual)
    assert check(ASVS, "V16.2.5", element={"logs_credentials": True, "logs_personal_data": False}) is False
    assert check(ASVS, "V16.2.5", element={"logs_credentials": False, "logs_personal_data": True}) is True


# ----------------------------------------------------- adapter evidence feeds the pack


def test_adapter_evidence_runs_on_asvs_pack():
    doc = {
        "subject": {"kind": "system", "id": "shop"},
        "sources": [{"id": "static", "kind": "analysis", "describes": "shop@abc123"}],
        "facts": {
            "password_auth": [{"value": True, "at": "routes/login.ts:12"}],
            "password_min_length": [{"value": 6, "at": "models/user.ts:40"}],
            "password_max_length": [{"value": 100000}],
            "password_composition_rules": [{"value": False}],
            "password_blocklist_check": [{"value": False}],
            "password_periodic_change": [{"value": False}],
            "login_rate_limited": [{"value": False}],
        },
        "elements": [
            {"type": "PasswordStore", "id": "ps1", "at": "lib/insecurity.ts:43",
             "facts": {"algorithm": [{"value": "md5"}], "salted": [{"value": False}]}},
            {"type": "Query", "id": "q1", "at": "routes/search.ts:23",
             "facts": {"construction": [{"value": "concatenated"}], "untrusted_input": [{"value": True}]}},
            {"type": "Cookie", "id": "c1", "at": "routes/login.ts:50",
             "facts": {"is_session": [{"value": True}], "secure": [{"value": False}], "http_only": [{"value": True}], "same_site": [{"value": "strict"}]}},
            {"type": "Cookie", "id": "c2", "at": "server.ts:200",
             "facts": {"is_session": [{"value": False}], "secure": [{"value": False}], "http_only": [{"value": False}], "same_site": [{"value": "unset"}]}},
            {"type": "TokenVerification", "id": "t1", "at": "lib/insecurity.ts:60",
             "facts": {"verifies_signature": [{"value": True}], "allows_none_alg": [{"value": False}]}},
            {"type": "Secret", "id": "s1", "at": "lib/insecurity.ts:23",
             "facts": {"kind": [{"value": "private_key"}], "test_or_example": [{"value": False}]}},
            {"type": "LogStatement", "id": "l1", "at": "routes/login.ts:30",
             "facts": {"logs_credentials": [{"value": True}], "logs_personal_data": [{"value": True}]}},
        ],
    }
    rows = run(load(ASVS), load_evidence(doc))
    verdict = {(r["norm"], r["element"]): r["verdict"] for r in rows}
    assert verdict[("V11.4.2", "ps1")] == "fail"
    assert verdict[("V1.2.4", "q1")] == "fail"
    assert verdict[("V3.3.1", "c1")] == "fail" and verdict[("V3.3.4", "c1")] == "pass"
    assert verdict[("V3.3.1", "c2")] == "pass" and verdict[("V3.3.4", "c2")] == "pass"
    assert verdict[("V9.1.1", "t1")] == "pass" and verdict[("V9.1.2", "t1")] == "pass"
    assert verdict[("V13.3.1", "s1")] == "fail"
    assert verdict[("V16.2.5", "l1")] == "fail"
    assert verdict[("V6.2.1", "shop")] == "fail"           # 6 < 8
    assert verdict[("V6.2.5", "shop")] == "pass"
    assert verdict[("V6.2.9", "shop")] == "pass"
    assert verdict[("V6.2.4", "shop")] == "fail"
    assert verdict[("V6.2.12", "shop")] == "fail"
    assert verdict[("V6.3.1", "shop")] == "fail"
    # Locators and the source travel with each row.
    row = next(r for r in rows if r["norm"] == "V1.2.4")
    assert row["at"] == ["routes/search.ts:23"] and row["seen_by"] == ["static"]
    assert row["section"] == "ASVS 5.0 V1.2.4"


def test_every_norm_has_guidance():
    for pack in (ASVS, NIST):
        for (kind, name), el in load(pack).elements.items():
            if kind == "norm":
                assert isinstance(el.data.get("guidance"), str) and len(el.data["guidance"]) > 40, name


# ------------------------------------- V1, V3.4, V3.5, V12, V13, V15, V16.2.5 (web)

# Levels as printed in the "L" column of the 5.0.0 chapter files.
WEB_LEVELS = {"V1.2.1": 1, "V1.2.5": 1, "V1.5.2": 2, "V3.4.1": 1, "V3.4.3": 2, "V3.5.1": 1, "V12.2.1": 1,
              "V13.4.2": 2, "V15.2.1": 1, "V15.3.3": 2, "V16.2.5 request parameter filtering": 2}


def test_web_norm_levels_and_citations():
    rs = load(ASVS)
    for name, level in WEB_LEVELS.items():
        el = rs.get("norm", name)
        assert el.data["level"] == level, name
        req = name.split()[0][1:]
        assert el.data["cite"]["ref"] == f"v5.0.0-{req}"
        assert el.data["cite"]["section"] == f"ASVS 5.0 V{req}"
        assert el.data["interpretation"]["note"]
    assert rs.get("norm", "V16.2.5").data.get("for") == {"l": "LogStatement"}       # the element norm is kept
    assert "for" not in rs.get("norm", "V16.2.5 request parameter filtering").data


@pytest.mark.parametrize(
    "out, expected",
    [
        ({"untrusted_input": True, "sanitized": False}, False),   # raw user data in HTML
        ({"untrusted_input": True, "sanitized": True}, True),     # V1.3.1: sanitizer
        ({"untrusted_input": False, "sanitized": False}, True),   # constant markup
        ({"sanitized": True}, True),
    ],
)
def test_html_output_encoding(out, expected):
    assert check(ASVS, "V1.2.1", element=out) is expected


def test_html_output_with_unknown_taint_is_open():
    v = check(ASVS, "V1.2.1", element={"sanitized": False})
    assert facts_in(v.expr) == ["HtmlOutput.untrusted_input"]


@pytest.mark.parametrize(
    "cmd, expected",
    [
        ({"construction": "concatenated", "untrusted_input": True}, False),
        ({"construction": "interpolated", "untrusted_input": True}, False),
        ({"construction": "argv", "untrusted_input": True}, True),          # "parameterized OS queries"
        ({"construction": "constant", "untrusted_input": False}, True),
        ({"construction": "interpolated", "untrusted_input": False}, True),  # nothing from a request reaches it
    ],
)
def test_os_command_injection(cmd, expected):
    assert check(ASVS, "V1.2.5", element=cmd) is expected


@pytest.mark.parametrize(
    "call, expected",
    [
        ({"safe_mode": False, "untrusted_input": True}, False),   # pickle.loads(request.body)
        ({"safe_mode": True, "untrusted_input": True}, True),     # yaml.safe_load / allowlist
        ({"safe_mode": False, "untrusted_input": False}, True),   # own files only
    ],
)
def test_deserialization(call, expected):
    assert check(ASVS, "V1.5.2", element=call) is expected


@pytest.mark.parametrize(
    "facts, expected",
    [
        ({"hsts": True, "hsts_max_age": 31535999}, False),   # one second short of 365 days
        ({"hsts": True, "hsts_max_age": 31536000}, True),    # "at least 1 year"
        ({"hsts": True, "hsts_max_age": 63072000}, True),
        ({"hsts": True, "hsts_max_age": 0}, False),
        ({"hsts": False}, False),
    ],
)
def test_hsts_max_age_at_least_one_year(facts, expected):
    assert check(ASVS, "V3.4.1", facts) is expected


def test_hsts_present_without_max_age_is_open():
    v = check(ASVS, "V3.4.1", {"hsts": True})
    assert facts_in(v.expr) == ["system.hsts_max_age"]


@pytest.mark.parametrize(
    "norm, fact, good",
    [
        ("V3.4.3", "content_security_policy", True),
        ("V3.5.1", "csrf_protection", True),
        ("V12.2.1", "tls_enforced", True),
        ("V13.4.2", "debug_in_production", False),
        ("V16.2.5 request parameter filtering", "log_redacts_credentials", True),
    ],
)
def test_system_web_flags(norm, fact, good):
    assert check(ASVS, norm, {fact: good}) is True
    assert check(ASVS, norm, {fact: not good}) is False
    v = check(ASVS, norm, {})
    assert facts_in(v.expr) == [f"system.{fact}"]


def test_hsts_and_csp_defer_what_the_vocabulary_lacks():
    rs = load(ASVS)
    assert any("includeSubDomains" in d for d in rs.get("norm", "V3.4.1").data["defers_to"])
    assert any("object-src" in d for d in rs.get("norm", "V3.4.3").data["defers_to"])


@pytest.mark.parametrize(
    "dep, expected",
    [
        ({"vulnerable": False}, True),                                                       # nothing to remediate
        ({"vulnerable": True, "fix_available": True, "max_severity": "high"}, False),
        ({"vulnerable": True, "fix_available": True, "max_severity": "critical"}, False),
        ({"vulnerable": True, "fix_available": True, "max_severity": "moderate", "within_remediation_time_frame": True}, True),
        ({"vulnerable": True, "fix_available": True, "max_severity": "moderate", "within_remediation_time_frame": False}, False),
        ({"vulnerable": True, "fix_available": False, "max_severity": "critical", "within_remediation_time_frame": True}, True),
    ],
)
def test_vulnerable_dependency(dep, expected):
    assert check(ASVS, "V15.2.1", element=dep) is expected


@pytest.mark.parametrize(
    "dep",
    [
        {"vulnerable": True, "fix_available": True, "max_severity": "moderate"},   # below the high threshold
        {"vulnerable": True, "fix_available": True, "max_severity": "low"},
        {"vulnerable": True, "fix_available": True, "max_severity": "unknown"},
        {"vulnerable": True, "fix_available": False, "max_severity": "critical"},  # no fix for some advisory
    ],
)
def test_vulnerable_dependency_otherwise_depends_on_the_documented_time_frames(dep):
    # V15.2.1 measures against "the documented update and remediation time frames" (V15.1.1).
    v = check(ASVS, "V15.2.1", element=dep)
    assert facts_in(v.expr) == ["Dependency.within_remediation_time_frame"]


def test_offline_inventory_leaves_dependencies_open():
    v = check(ASVS, "V15.2.1", element={"ecosystem": "npm", "name": "lodash", "version": "4.17.4"})
    assert "Dependency.vulnerable" in facts_in(v.expr)


@pytest.mark.parametrize(
    "ma, expected",
    [
        ({"allowlist": False, "privileged_assignable": True}, False),   # User.update(params) with an admin flag
        ({"allowlist": False, "privileged_assignable": False}, False),  # still no per-action field limit
        ({"allowlist": True, "privileged_assignable": False}, True),
        ({"allowlist": True, "privileged_assignable": True}, True),     # listed on purpose: V8.2.3, not V15.3.3
    ],
)
def test_mass_assignment(ma, expected):
    assert check(ASVS, "V15.3.3", element=ma) is expected


def test_web_evidence_rows_and_absent_types():
    doc = {
        "subject": {"kind": "system", "id": "shop"},
        "sources": [{"id": "static", "kind": "analysis"}],
        "facts": {"hsts": [{"value": True}], "hsts_max_age": [{"value": 15552000}], "content_security_policy": [{"value": False}],
                  "csrf_protection": [{"value": True}], "tls_enforced": [{"value": True}], "debug_in_production": [{"value": False}],
                  "log_redacts_credentials": [{"value": True}]},
        "elements": [
            {"type": "HtmlOutput", "id": "h1", "at": "views/search.ejs:12",
             "facts": {"sanitized": [{"value": False}], "untrusted_input": [{"value": True}]}},
            {"type": "Dependency", "id": "Dependency@npm/lodash@4.17.4", "at": "package-lock.json#L40",
             "facts": {"vulnerable": [{"value": True}], "fix_available": [{"value": True}], "max_severity": [{"value": "critical"}]}},
            {"type": "Dependency", "id": "Dependency@npm/ms@2.1.3", "at": "package-lock.json#L44",
             "facts": {"vulnerable": [{"value": False}]}},
        ],
    }
    rows = run(load(ASVS), load_evidence(doc))
    verdict = {(r["norm"], r["element"]): r["verdict"] for r in rows}
    assert verdict[("V1.2.1", "h1")] == "fail"
    assert verdict[("V3.4.1", "shop")] == "fail"            # 180 days < 1 year
    assert verdict[("V3.4.3", "shop")] == "fail"
    assert verdict[("V3.5.1", "shop")] == verdict[("V12.2.1", "shop")] == verdict[("V13.4.2", "shop")] == "pass"
    assert verdict[("V16.2.5 request parameter filtering", "shop")] == "pass"
    assert verdict[("V15.2.1", "Dependency@npm/lodash@4.17.4")] == "fail"
    assert verdict[("V15.2.1", "Dependency@npm/ms@2.1.3")] == "pass"
    # No CommandExecution, Deserialization or MassAssignment in the repository: no rows, so no fail.
    norms = {r["norm"] for r in rows}
    assert not norms & {"V1.2.5", "V1.5.2", "V15.3.3"}

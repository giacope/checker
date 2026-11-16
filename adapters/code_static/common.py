"""Shared vocabulary of the static adapter: name patterns, literal classifiers, and the collector."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

SOURCE = "static"


# ---------------------------------------------------------------- identifier names

def words(name: str) -> list[str]:
    """`clearTextPassword` / `CLEAR_TEXT_PASSWORD` / `clear-text.password` -> ['clear', 'text', 'password']."""
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", name.lower()) if w]


PW_WORDS = {"password", "passwd", "pwd", "pass", "passphrase", "pw", "passwort", "pword", "clearpassword"}
PW_EXCLUDE = {"hash", "hashed", "digest", "salt", "reset", "forgot", "policy", "length", "len", "validator", "field",
              "label", "placeholder", "regex", "re", "pattern", "hint", "error", "errors", "msg", "message", "strength",
              "expire", "expires", "expiry", "token", "url", "path", "visible", "type", "input", "control", "show",
              "change", "changed", "required", "min", "max", "form", "valid", "match", "matches", "mismatch", "rule",
              "rules", "repeat", "confirm", "confirmation", "again", "verify", "check", "compare", "is", "has", "auth",
              "enc", "encrypted", "md5", "sha1", "sha256", "bcrypt", "stored", "db", "old", "previous"}


def is_password_name(name: str) -> bool:
    """A variable or property that holds a cleartext password."""
    ws = words(name)
    if not ws:
        return False
    if not any(w in PW_WORDS or w.endswith("password") for w in ws):
        return False
    return not any(w in PW_EXCLUDE for w in ws)


def is_stored_password_name(name: str) -> bool:
    """The stored form a cleartext password is compared with: `user.password`, `row['password']`."""
    ws = words(name)
    return bool(ws) and ws[-1] in {"password", "passwd", "pwd"}


CRED_WORDS = {"password", "passwd", "pwd", "secret", "token", "jwt", "sessionid", "sid", "cookie", "cookies",
              "authorization", "apikey", "credential", "credentials", "otp", "totp", "passphrase", "bearer"}


def is_credential_name(name: str) -> bool:
    ws = words(name)
    if is_password_name(name):
        return True
    j = "_".join(ws)
    if re.search(r"(^|_)(session_id|api_key|access_key|private_key|secret_key|auth_header|refresh_token|access_token)(_|$)", j):
        return True
    return any(w in CRED_WORDS for w in ws) and not any(w in {"url", "type", "expire", "expires", "length", "name", "count", "label", "status"} for w in ws)


PERSONAL_WORDS = {"email", "mail", "emails", "firstname", "lastname", "fullname", "surname", "username", "address",
                  "phone", "mobile", "telephone", "ssn", "dob", "birthday", "birthdate", "iban", "passport", "zip",
                  "zipcode", "postcode", "street", "city", "gender"}
PERSONAL_JOINED = re.compile(r"(^|_)(first_name|last_name|full_name|user_name|date_of_birth|birth_date|credit_card|card_number|"
                             r"phone_number|ip_address|postal_code|zip_code|social_security)(_|$)")
USER_OBJECTS = {"user", "users", "customer", "customers", "profile", "account", "member", "person", "patient", "employee"}


def is_personal_name(name: str, owner: str | None = None) -> bool:
    ws = words(name)
    j = "_".join(ws)
    if PERSONAL_JOINED.search(j):
        return True
    if any(w in PERSONAL_WORDS for w in ws) and not any(w in {"template", "templates", "url", "host", "port", "server",
                                                               "smtp", "type", "enabled", "from", "subject", "sender", "field",
                                                               "label", "placeholder", "regex", "re", "valid", "error"} for w in ws):
        return True
    if ws and ws[-1] == "name" and owner is not None and any(w in USER_OBJECTS for w in words(owner)):
        return True
    return False


def is_user_object_name(name: str) -> bool:
    ws = words(name)
    return bool(ws) and (ws[-1] in USER_OBJECTS or "_".join(ws) in {"current_user", "db_user", "user_obj", "user_model", "user_doc"})


SESSION_COOKIE_WORDS = {"session", "sess", "sid", "sessionid", "sessid", "token", "auth", "jwt", "login", "remember", "connect",
                        "jsessionid", "phpsessid", "access", "refresh", "bearer", "identity"}


def session_cookie_name(name: str) -> bool:
    """The cookie name says it carries a session or authentication token."""
    name = name.split("=")[0]
    return any(w in SESSION_COOKIE_WORDS or w.startswith("sess") for w in words(name))


PW_EXPIRY = re.compile(r"password_(expir\w*|max_age|age|valid_until|last_changed|changed_at|change_date|changed_on|updated_at|set_at)(_|$)|"
                       r"(must|force|require[sd]?)_(change|reset)_password|password_(change|reset)_required|days_until_password")
ERASURE_REQUEST = re.compile(r"(^|_)(data_erasure|erasure_request|deletion_requested|deletion_request|account_deletion|delete_account|"
                             r"privacy_requests?|right_to_be_forgotten|gdpr_delete)(_|$)")
LOCKOUT = re.compile(r"(^|_)(fail(ed)?_(login_)?attempts?|login_attempts?|failed_logins?|lockout|locked_until|is_locked|lock_until)(_|$)")


# ---------------------------------------------------------------- secrets

PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
CONN_STRING = re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle|"
                         r"couchdb|neo4j|jdbc:[a-z]+)(?:\+[a-z0-9]+)?://(?P<user>[^:/\s@'\"]*):(?P<pw>[^@\s/'\"]+)@", re.I)
VENDOR_KEYS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"),
]
SIGNING_NAMES = re.compile(r"(^|_)(secret_key|secret|signing_key|sign_key|jwt_key|jwt_secret|hmac_key|session_secret|"
                           r"cookie_secret|token_secret|private_key|app_key|master_key|secret_key_base)(_|$)")
CRYPTO_NAMES = re.compile(r"(^|_)(encryption_key|crypto_key|cipher_key|aes_key|enc_key|encrypt_key|decryption_key|data_key)(_|$)")
APIKEY_NAMES = re.compile(r"(^|_)(api_key|apikey|access_key|access_key_id|secret_access_key|client_secret|auth_token|"
                          r"access_token|api_token|bearer_token|refresh_token|app_secret|consumer_secret|webhook_secret|token|license_key)(_|$)")
NOT_SECRET_TAIL = {"url", "uri", "path", "endpoint", "route", "file", "dir", "field", "label", "placeholder", "message", "msg",
                   "hint", "text", "title", "name", "type", "length", "len", "min", "max", "expire", "expires", "expiry",
                   "timeout", "ttl", "algorithm", "alg", "algorithms", "header", "pattern", "regex", "re", "prefix", "suffix",
                   "selector", "id", "ids", "required", "enabled", "policy", "hours", "minutes", "seconds", "days", "count",
                   "location", "lifetime", "mode", "format", "version", "salt", "rounds", "iterations", "char", "chars",
                   "error", "errors", "status", "strength", "mask", "class", "icon", "key", "keys", "help", "description",
                   "input", "button", "link", "view", "template", "page", "form", "regexp", "env", "var", "variable",
                   "scheme", "schemes", "hasher", "hashers", "validators", "validator", "question", "answer", "size",
                   "address", "contract", "symbol", "decimals", "supply", "balance", "amount", "price"}
FIELDNAME_VALUES = {"password", "passwd", "pwd", "secret", "token", "key", "apikey", "api_key", "username", "true", "false",
                    "null", "none", "required", "string", "str", "text", "hidden", "bearer", "basic", "jwt", "session",
                    "undefined", "nan", "changeme_placeholder", "object", "number", "boolean"}


def secret_kind_for_name(name: str) -> str | None:
    ws = words(name)
    if not ws or ws[-1] in NOT_SECRET_TAIL and "_".join(ws[-2:]) not in {"secret_key", "api_key", "private_key", "signing_key",
                                                                          "access_key", "app_key", "master_key", "jwt_key",
                                                                          "hmac_key", "encryption_key", "license_key", "sign_key",
                                                                          "crypto_key", "cipher_key", "aes_key", "enc_key"}:
        return None
    j = "_".join(ws)
    if "private_key" in j:
        return "private_key"
    if CRYPTO_NAMES.search(j):
        return "other"  # a symmetric encryption key
    if SIGNING_NAMES.search(j):
        return "signing_key"
    if APIKEY_NAMES.search(j):
        return "api_key"
    if any(w in PW_WORDS or w.endswith("password") for w in ws):
        if any(w in {"reset", "forgot", "policy", "change", "confirm", "repeat", "hash", "hashed", "hasher", "hashers"} for w in ws):
            return None
        return "password"
    if any(w in {"credential", "credentials", "passphrase"} for w in ws):
        return "other"
    return None


def literal_secret_kind(value: str) -> str | None:
    """Kinds recognisable from the literal alone, whatever it is assigned to."""
    if PRIVATE_KEY.search(value):
        return "private_key"
    m = CONN_STRING.search(value)
    if m and not re.match(r"^[\$\{<%\[*]|^x+$", m["pw"]) and m["pw"].lower() not in {"password", "pass", "pwd", "secret"}:
        return "connection_string"
    if any(p.search(value) for p in VENDOR_KEYS):
        return "api_key"
    return None


def plausible_secret_value(value: str, kind: str) -> bool:
    v = value.strip()
    if len(v) < 3 or v.lower() in FIELDNAME_VALUES:
        return False
    if re.match(r"^(\$\{|\$[A-Z_]|\{\{|<%|%\(|#\{|<[a-z_\- ]+>$)", v, re.I) or re.search(r"\$\{[^}]+\}$", v):
        return False  # a reference to an environment variable or a template slot
    if re.fullmatch(r"[A-Z_][A-Z0-9_]*_[A-Z0-9_]+", v) or re.fullmatch(r"[a-z]+(\.[a-z_]+){1,}", v):
        return False  # an identifier or a translation key, not a value
    if v.startswith(("/", "./", "../", "http://", "https://", "file:")) or re.search(r"\.(pem|key|crt|pub|json|ya?ml|txt|env)$", v):
        return False
    if kind != "private_key" and len(v.split()) > 2:
        return False  # prose: a message about a password, not a password
    if re.fullmatch(r"[*•x.\-_ ]+", v, re.I):
        return False
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", v):
        return False  # a public blockchain address
    if re.fullmatch(r"(true|false|yes|no|on|off|\d+(\.\d+)?)", v, re.I) and kind not in {"password"}:
        return False
    return True


# ---------------------------------------------------------------- password regexes

def analyse_password_regex(pattern: str) -> dict:
    """Length bounds and character-class requirements a password regex imposes."""
    out: dict = {}
    body = pattern
    comp = re.findall(r"\(\?=[^)]*?(\\d|\[0-9\]|\[a-z\]|\[A-Z\]|\\W|\[\^a-zA-Z0-9\]|\[!@#[^\]]*\]|\\p\{|\[[^\]]*[!@#$%^&*][^\]]*\])", body)
    if comp:
        out["composition"] = True
    m = re.search(r"(?:\.|\\S|\[[^\]]+\])\{(\d+),(\d*)\}\$?\)?\$?$", body) or re.search(r"(?:\.|\\S|\[[^\]]+\])\{(\d+),(\d*)\}", body)
    if m:
        out["min"] = int(m.group(1))
        if m.group(2):
            out["max"] = int(m.group(2))
    return out


# ---------------------------------------------------------------- URLs

LOCAL_HOSTS = re.compile(r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|::1|host\.docker\.internal|[a-z0-9_\-]+)$", re.I)


def external_host(url: str) -> str | None:
    if not re.match(r"^https?://", url):
        return None
    try:
        host = urlparse(url.split("${")[0].split("{")[0]).hostname
    except ValueError:
        return None
    if not host or LOCAL_HOSTS.match(host) or host.endswith((".local", ".internal", ".localhost", "example.com", "example.org")):
        return None
    return host


TRACKER_HOSTS = {
    "google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager", "hotjar.com": "Hotjar",
    "segment.com": "Segment", "segment.io": "Segment", "mixpanel.com": "Mixpanel", "connect.facebook.net": "Meta Pixel",
    "clarity.ms": "Microsoft Clarity", "plausible.io": "Plausible", "amplitude.com": "Amplitude", "heap.io": "Heap",
    "fullstory.com": "FullStory", "intercom.io": "Intercom", "sentry-cdn.com": "Sentry", "browser.sentry-cdn.com": "Sentry",
}

SAAS_SDKS = {  # module name -> recipient
    "stripe": "Stripe", "@sendgrid/mail": "SendGrid", "sendgrid": "SendGrid", "nodemailer": "email (SMTP relay via nodemailer)",
    "openai": "OpenAI", "@anthropic-ai/sdk": "Anthropic", "anthropic": "Anthropic", "twilio": "Twilio", "mailgun.js": "Mailgun",
    "mailgun-js": "Mailgun", "@mailchimp/mailchimp_transactional": "Mailchimp", "analytics-node": "Segment",
    "@segment/analytics-node": "Segment", "mixpanel": "Mixpanel", "posthog-node": "PostHog", "posthog": "PostHog",
    "@sentry/node": "Sentry", "sentry_sdk": "Sentry", "boto3": "AWS", "@aws-sdk/client-ses": "AWS SES",
    "@aws-sdk/client-s3": "AWS S3", "emails": "email (SMTP relay)", "smtplib": "email (SMTP relay)", "braintree": "Braintree",
    "paypalrestsdk": "PayPal", "@paypal/checkout-server-sdk": "PayPal", "google.generativeai": "Google Gemini",
}


# ---------------------------------------------------------------- collector

REJECT_WORDS = {"abort", "error", "errors", "fail", "fails", "failure", "reject", "invalid", "deny", "denied", "flash", "throw",
                "raise", "bad", "badrequest", "unprocessable", "forbidden", "validationerror", "exception", "warn", "alert"}


def rejects_words(names: list[str]) -> bool:
    """Whether calls or names in a branch say it rejects the input (abort, errors.add, ValidationError, flash...)."""
    ws = [w for n in names for w in re.split(r"[^a-z]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", str(n)).lower()) if w]
    return any(w in REJECT_WORDS or w.endswith(("error", "exception")) for w in ws)


def length_bound(op: str, n: int, invalid_when: bool | None) -> tuple[str, int] | None:
    """The password length rule a comparison `len(password) <op> n` states: ("min", k) or ("max", k).

    `invalid_when` is what the comparison holding means where it is: True when the code rejects the password then
    (`if len(p) < 8: raise`), False when it accepts it then (`assert len(p) >= 8`, `return len(p) <= 64`, or under
    one `not`), None when the context does not say, and then there is no rule to read."""
    if invalid_when is None:
        return None
    valid = {  # the lengths that pass, as a bound
        ("<", True): ("min", n), ("<=", True): ("min", n + 1), (">", True): ("max", n), (">=", True): ("max", n - 1),
        (">=", False): ("min", n), (">", False): ("min", n + 1), ("<=", False): ("max", n), ("<", False): ("max", n - 1)}
    return valid.get((op, invalid_when))


@dataclass
class Collector:
    """Elements and subject signals found so far; one element per (type, place)."""

    elements: dict = field(default_factory=dict)   # (type, at) -> {fact: value}
    signals: dict = field(default_factory=dict)    # signal -> [(value, at, extra)]
    via: dict = field(default_factory=dict)        # at -> customer framework model whose rule produced it

    def mark(self, at: str, rule) -> None:
        if rule is not None and not rule.builtin:
            self.via.setdefault(at, rule.model)

    def element(self, type_: str, at: str, **facts):
        cur = self.elements.setdefault((type_, at), {})
        for k, v in facts.items():
            if v is None:
                continue
            if k not in cur:
                cur[k] = v
            elif type_ == "PasswordStore" and k == "algorithm" and cur[k] == "plaintext" and v != "plaintext":
                cur[k] = v  # a hash applied on the same line wins over a raw-looking argument
            elif isinstance(v, bool) and v and k in {"untrusted_input", "logs_credentials", "logs_personal_data", "allows_none_alg"}:
                cur[k] = True
            elif k == "construction" and RISK.get(v, 0) > RISK.get(cur[k], 0):
                cur[k] = v

    def signal(self, name: str, at: str, value=True, **extra):
        self.signals.setdefault(name, []).append((value, at, extra))

    def has(self, name: str) -> bool:
        return bool(self.signals.get(name))


RISK = {"orm": 0, "parameterized": 1, "operator_object": 2, "interpolated": 3, "concatenated": 3}


def model_policy(rule, at: str, side: str, out: Collector) -> None:
    """Signals for a call a framework model says validates a new password."""
    s = rule.spec
    if "min_length" in s:
        out.signal("pw_min", at, s["min_length"], side=side)
    if "max_length" in s:
        out.signal("pw_max", at, s["max_length"], side=side)
    if s.get("composition_rules"):
        out.signal("pw_composition", at)
    if s.get("blocklist"):
        out.signal("pw_blocklist", at)
    out.signal("pw_validation", at, side=side)
    out.mark(at, rule)

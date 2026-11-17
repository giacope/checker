"""The Elixir static adapter on small synthetic repositories: one pattern and its safe counterpart per test."""

import textwrap

import yaml

from adapters.code_elixir import analyse
from adapters.code_elixir.__main__ import main
from normir.evidence import load_evidence

MIX = """\
defmodule App.MixProject do
  use Mix.Project
  def project, do: [app: :app, deps: deps()]
  defp deps do
    [{:phoenix, "~> 1.7"}, {:bcrypt_elixir, "~> 3.0"}]
  end
end
"""
LOCK = """\
%{
  "bcrypt_elixir": {:hex, :bcrypt_elixir, "3.1.0", "abc", [:make, :mix], [], "hexpm", "def"},
  "phoenix": {:hex, :phoenix, "%s", "abc", [:mix], [], "hexpm", "def"},
  "plug": {:hex, :plug, "1.16.1", "abc", [:mix], [], "hexpm", "def"},
}
"""
CONTROLLER = """\
defmodule AppWeb.ItemController do
  use AppWeb, :controller
%s
end
"""


def repo(tmp_path, files: dict, phoenix: str = "1.7.14"):
    (tmp_path / "mix.exs").write_text(MIX)
    (tmp_path / "mix.lock").write_text(LOCK.replace("%s", phoenix))
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return analyse(tmp_path)


def ctrl(body: str) -> str:
    return CONTROLLER % textwrap.indent(textwrap.dedent(body), "  ")


def elements(doc, type_):
    return {e["at"]: {k: v[0]["value"] for k, v in e["facts"].items()} for e in doc["elements"] if e["type"] == type_}


def fact(doc, name):
    return sorted({(o["value"], o["at"]) for o in doc["facts"].get(name, [])}, key=str)


def values(doc, name):
    return {o["value"] for o in doc["facts"].get(name, [])}


# ---------------------------------------------------------------- PasswordStore

def test_bcrypt_vs_md5_and_plaintext(tmp_path):
    doc = repo(tmp_path, {"lib/app/accounts.ex": """\
        defmodule App.Accounts do
          def hash(password), do: Bcrypt.hash_pwd_salt(password)
          def check(user, password), do: Bcrypt.verify_pass(password, user.hashed_password)
          def weak(password), do: :crypto.hash(:md5, password)
          def salted(password, salt), do: :crypto.hash(:sha256, salt <> password)
          def plain(user, password), do: user.password == password
          def dummy, do: Bcrypt.hash_pwd_salt("not a user's password")
        end
        """})
    ps = elements(doc, "PasswordStore")
    assert ps["lib/app/accounts.ex:2"] == {"algorithm": "bcrypt", "salted": True}
    assert ps["lib/app/accounts.ex:3"] == {"algorithm": "bcrypt", "salted": True}
    assert ps["lib/app/accounts.ex:4"] == {"algorithm": "md5", "salted": False}
    assert ps["lib/app/accounts.ex:5"] == {"algorithm": "sha256", "salted": True}
    assert ps["lib/app/accounts.ex:6"] == {"algorithm": "plaintext", "salted": False}
    assert "lib/app/accounts.ex:7" not in ps
    assert values(doc, "password_auth") == {True}


def test_plaintext_password_cast_into_stored_field(tmp_path):
    schema = """\
        defmodule App.User do
          use Ecto.Schema
          import Ecto.Changeset
          schema "users" do
            field :email, :string
            field :password, :string
          end
          def changeset(user, attrs), do: cast(user, attrs, [:email, :password])
        end
        """
    action = ctrl("""\
        def create(conn, %{"user" => user_params}) do
          %App.User{} |> App.User.changeset(user_params) |> App.Repo.insert()
        end
        """)
    doc = repo(tmp_path, {"lib/app/user.ex": schema, "lib/app_web/item_controller.ex": action})
    assert elements(doc, "PasswordStore")["lib/app/user.ex:8"] == {"algorithm": "plaintext", "salted": False}
    hashed = schema.replace("cast(user, attrs, [:email, :password])",
                            "cast(user, attrs, [:email, :password]) |> put_change(:password, Bcrypt.hash_pwd_salt(\"x\"))")
    doc = repo(tmp_path, {"lib/app/user.ex": hashed, "lib/app_web/item_controller.ex": action})
    assert "lib/app/user.ex:8" not in elements(doc, "PasswordStore")


# ---------------------------------------------------------------- Query

def test_interpolated_sql_vs_parameterized(tmp_path):
    doc = repo(tmp_path, {"lib/app/search.ex": """\
        defmodule App.Search do
          def bad(name), do: Ecto.Adapters.SQL.query(App.Repo, "SELECT * FROM p WHERE name = '#{name}'")
          def concat(name), do: App.Repo.query!("SELECT * FROM p WHERE name = '" <> name <> "'")
          def good(name), do: App.Repo.query!("SELECT * FROM p WHERE name = $1", [name])
        end
        """, "lib/app/repo.ex": """\
        defmodule App.Repo do
          use Ecto.Repo, otp_app: :app
        end
        """, "lib/app_web/item_controller.ex": ctrl("""\
        def index(conn, %{"q" => q}) do
          App.Search.bad(q)
          App.Search.concat(q)
          App.Search.good(q)
          json(conn, %{})
        end
        """)})
    q = elements(doc, "Query")
    assert q["lib/app/search.ex:2"] == {"construction": "interpolated", "untrusted_input": True}
    assert q["lib/app/search.ex:3"] == {"construction": "concatenated", "untrusted_input": True}
    assert q["lib/app/search.ex:4"] == {"construction": "parameterized", "untrusted_input": True}


def test_ecto_query_reported_only_when_request_data_reaches_it(tmp_path):
    doc = repo(tmp_path, {"lib/app/items.ex": """\
        defmodule App.Items do
          import Ecto.Query
          def by_name(name), do: from(i in App.Item, where: i.name == ^name) |> App.Repo.all()
          def recent, do: from(i in App.Item, order_by: i.id) |> App.Repo.all()
        end
        """, "lib/app_web/item_controller.ex": ctrl("""\
        def index(conn, params) do
          App.Items.by_name(params["name"])
          App.Items.recent()
          json(conn, %{})
        end
        """)})
    q = elements(doc, "Query")
    assert q == {"lib/app/items.ex:3": {"construction": "orm", "untrusted_input": True}}


# ---------------------------------------------------------------- Cookie

def test_cookie_flags_and_plug_defaults(tmp_path):
    doc = repo(tmp_path, {"lib/app_web/item_controller.ex": ctrl("""\
        def a(conn, _params), do: put_resp_cookie(conn, "remember_token", "v")
        def b(conn, _params), do: put_resp_cookie(conn, "theme", "dark", secure: true, http_only: false, same_site: "Strict")
        """)})
    c = elements(doc, "Cookie")
    # Plug: http_only defaults to true, secure only on https (no force_ssl here), SameSite omitted
    assert c["lib/app_web/item_controller.ex:3"] == {"is_session": True, "secure": False, "http_only": True, "same_site": "unset"}
    assert c["lib/app_web/item_controller.ex:4"] == {"is_session": False, "secure": True, "http_only": False, "same_site": "strict"}


def test_session_cookie_from_endpoint_and_force_ssl(tmp_path):
    endpoint = """\
        defmodule AppWeb.Endpoint do
          use Phoenix.Endpoint, otp_app: :app
          @session_options [store: :cookie, key: "_app_key", signing_salt: "abcdefgh", same_site: "Lax"]
          plug Plug.Session, @session_options
        end
        """
    doc = repo(tmp_path, {"lib/app_web/endpoint.ex": endpoint})
    assert elements(doc, "Cookie")["lib/app_web/endpoint.ex:3"] == {"is_session": True, "secure": False, "http_only": True, "same_site": "lax"}
    assert values(doc, "tls_enforced") == {False}
    assert elements(doc, "Secret") == {}   # signing_salt is not a secret by Phoenix's design
    doc = repo(tmp_path, {"lib/app_web/endpoint.ex": endpoint, "config/prod.exs": """\
        import Config
        config :app, AppWeb.Endpoint, force_ssl: [hsts: true, expires: 63_072_000]
        """})
    assert elements(doc, "Cookie")["lib/app_web/endpoint.ex:3"]["secure"] is True
    assert fact(doc, "tls_enforced") == [(True, "config/prod.exs:2")]
    assert fact(doc, "hsts") == [(True, "config/prod.exs:2")]
    assert fact(doc, "hsts_max_age") == [(63072000, "config/prod.exs:2")]


def test_hsts_default_max_age(tmp_path):
    doc = repo(tmp_path, {"lib/app_web/endpoint.ex": """\
        defmodule AppWeb.Endpoint do
          use Phoenix.Endpoint, otp_app: :app
        end
        """, "config/prod.exs": """\
        import Config
        config :app, AppWeb.Endpoint, force_ssl: [rewrite_on: [:x_forwarded_proto]]
        """})
    assert fact(doc, "hsts_max_age") == [(31536000, "config/prod.exs:2")]


# ---------------------------------------------------------------- TokenVerification

def test_token_verification(tmp_path):
    doc = repo(tmp_path, {"lib/app/peek.ex": """\
        defmodule App.Peek do
          def a(t), do: Joken.peek_claims(t)
        end
        """, "lib/app/tokens.ex": """\
        defmodule App.Tokens do
          # peeking where the module also verifies reads the header first (kid, iss), so it is not reported
          def a(t), do: Joken.peek_claims(t)
          def b(t, signer), do: Joken.verify_and_validate(%{}, t, signer)
          def c(jwk, t), do: JOSE.JWT.verify(jwk, t)
          def d(jwk, t), do: JOSE.JWT.verify_strict(jwk, ["RS256"], t)
          def e(t), do: Phoenix.Token.verify(AppWeb.Endpoint, "salt", t, max_age: 60)
        end
        """})
    t = elements(doc, "TokenVerification")
    assert t["lib/app/peek.ex:2"] == {"verifies_signature": False}
    assert "lib/app/tokens.ex:3" not in t
    assert t["lib/app/tokens.ex:4"] == {"verifies_signature": True, "allows_none_alg": False}
    assert t["lib/app/tokens.ex:5"] == {"verifies_signature": True, "allows_none_alg": True}
    assert t["lib/app/tokens.ex:6"] == {"verifies_signature": True, "allows_none_alg": False}
    assert t["lib/app/tokens.ex:7"] == {"verifies_signature": True, "allows_none_alg": False}


# ---------------------------------------------------------------- Secret

def test_secrets_in_config(tmp_path):
    doc = repo(tmp_path, {"config/prod.exs": """\
        import Config
        config :app, AppWeb.Endpoint,
          secret_key_base: "Qm9ndXNTZWNyZXRLZXlCYXNlVGhhdElzTG9uZ0Vub3VnaDEyMzQ1Njc4",
          live_view: [signing_salt: "Zx81kLpQ"]
        config :app, :stripe, api_key: System.get_env("STRIPE_KEY", "sk_live_51HxQz8KkY2mN3pR4tV6wX9a")
        config :app, :mailer, api_key: System.get_env("MAILER_KEY")
        """, "config/dev.exs": """\
        import Config
        config :app, AppWeb.Endpoint, secret_key_base: "ZGV2ZWxvcG1lbnRPbmx5U2VjcmV0S2V5QmFzZTEyMzQ1Njc4OTA="
        """, "priv/cert/selfsigned_key.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIx\n-----END RSA PRIVATE KEY-----\n"})
    s = elements(doc, "Secret")
    assert s["config/prod.exs:3"] == {"kind": "signing_key"}
    assert s["config/prod.exs:5"]["kind"] == "api_key"
    assert s["config/dev.exs:2"] == {"kind": "signing_key", "test_or_example": True}
    assert s["priv/cert/selfsigned_key.pem:1"] == {"kind": "private_key", "test_or_example": True}
    assert not any(at.startswith(("config/prod.exs:4", "config/prod.exs:6")) for at in s)
    text = yaml.safe_dump(doc)
    assert "Qm9ndXNTZWNy" not in text and "sk_live_51Hx" not in text   # values are never written


# ---------------------------------------------------------------- LogStatement

def test_log_statements(tmp_path):
    doc = repo(tmp_path, {"lib/app_web/item_controller.ex": ctrl("""\
        require Logger
        def create(conn, params) do
          Logger.info("login #{params["email"]} #{params["password"]}")
          Logger.debug(inspect(params))
          Logger.info("created item #{params["id"]}")
          json(conn, %{})
        end
        """)})
    logs = elements(doc, "LogStatement")
    assert logs["lib/app_web/item_controller.ex:5"] == {"logs_credentials": True, "logs_personal_data": True}
    assert "lib/app_web/item_controller.ex:6" in logs   # the whole params of an action that reads a password
    assert "lib/app_web/item_controller.ex:7" not in logs


# ---------------------------------------------------------------- Transfer

def test_transfers(tmp_path):
    doc = repo(tmp_path, {"lib/app/notify.ex": """\
        defmodule App.Notify do
          def hook(user), do: HTTPoison.post("https://hooks.example-crm.io/v1", Jason.encode!(%{email: user.email}))
          def local(x), do: HTTPoison.post("http://localhost:4000/x", x)
          def charge(customer), do: Stripe.Customer.create(%{email: customer.email})
          def send(email), do: App.Mailer.deliver(email)
        end
        """, "lib/app/mailer.ex": """\
        defmodule App.Mailer do
          use Swoosh.Mailer, otp_app: :app
        end
        """, "config/prod.exs": """\
        import Config
        config :app, App.Mailer, adapter: Swoosh.Adapters.Postmark, api_key: System.get_env("POSTMARK")
        """})
    t = elements(doc, "Transfer")
    assert t["lib/app/notify.ex:2"] == {"recipient": "hooks.example-crm.io", "personal_data": True}
    assert "lib/app/notify.ex:3" not in t
    assert t["lib/app/notify.ex:4"] == {"recipient": "Stripe", "personal_data": True}
    assert t["lib/app/notify.ex:5"] == {"recipient": "Postmark", "personal_data": True}


# ---------------------------------------------------------------- CommandExecution

def test_command_execution(tmp_path):
    doc = repo(tmp_path, {"lib/app_web/item_controller.ex": ctrl("""\
        def convert(conn, %{"file" => file}) do
          System.cmd("convert", [file, "out.png"])
          :os.cmd(String.to_charlist("convert #{file} out.png"))
          :os.cmd('uptime')
          Port.open({:spawn, "convert " <> file}, [])
          Port.open({:spawn_executable, "/usr/bin/convert"}, args: [file])
          json(conn, %{})
        end
        """)})
    c = elements(doc, "CommandExecution")
    base = "lib/app_web/item_controller.ex:"
    assert c[base + "4"] == {"construction": "argv", "untrusted_input": True}
    assert c[base + "5"] == {"construction": "interpolated", "untrusted_input": True}
    assert c[base + "6"] == {"construction": "constant", "untrusted_input": False}
    assert c[base + "7"] == {"construction": "concatenated", "untrusted_input": True}
    assert c[base + "8"] == {"construction": "argv", "untrusted_input": True}


# ---------------------------------------------------------------- HtmlOutput

def test_raw_html_in_templates_and_code(tmp_path):
    doc = repo(tmp_path, {"lib/app/review.ex": """\
        defmodule App.Review do
          use Ecto.Schema
          import Ecto.Changeset
          schema "reviews" do
            field :body, :string
          end
          def changeset(r, attrs), do: cast(r, attrs, [:body])
        end
        """, "lib/app_web/item_controller.ex": ctrl("""\
        def create(conn, %{"review" => p}) do
          %App.Review{} |> App.Review.changeset(p) |> App.Repo.insert()
          json(conn, %{})
        end
        """), "lib/app_web/templates/show.html.heex": """\
        <div><%= raw review.body %></div>
        <div>{raw(HtmlSanitizeEx.basic_html(review.body))}</div>
        <div>{raw(@icon_svg)}</div>
        """, "lib/app_web/views/helpers.ex": """\
        defmodule AppWeb.Helpers do
          use Phoenix.Component
          def badge(text), do: {:safe, "<b>#{text}</b>"}
          def note, do: Phoenix.HTML.raw("<i>static</i>")
        end
        """})
    h = elements(doc, "HtmlOutput")
    assert h["lib/app_web/templates/show.html.heex:1"] == {"untrusted_input": True, "sanitized": False}
    assert h["lib/app_web/templates/show.html.heex:2"] == {"sanitized": True}
    assert h["lib/app_web/templates/show.html.heex:3"] == {"sanitized": False}   # cannot tell where it comes from
    assert h["lib/app_web/views/helpers.ex:3"] == {"sanitized": False}
    assert h["lib/app_web/views/helpers.ex:4"] == {"untrusted_input": False, "sanitized": False}


# ---------------------------------------------------------------- MassAssignment

def test_mass_assignment_privileged_fields(tmp_path):
    doc = repo(tmp_path, {"lib/app/user.ex": """\
        defmodule App.User do
          use Ecto.Schema
          import Ecto.Changeset
          schema "users" do
            field :name, :string
            field :role, :string
          end
          def profile_changeset(u, attrs), do: cast(u, attrs, [:name, :role])
          def name_changeset(u, attrs), do: cast(u, attrs, [:name])
          def admin_changeset(u, attrs), do: cast(u, attrs, [:name, :role])
          def fixed(u, name), do: cast(u, %{name: name, role: "member"}, [:name, :role])
        end
        """, "lib/app_web/item_controller.ex": ctrl("""\
        def update(conn, %{"user" => p}) do
          u = conn.assigns.current_user
          App.User.profile_changeset(u, p)
          App.User.name_changeset(u, p)
          App.User.admin_changeset(u, p)
          App.User.fixed(u, p["name"])
          json(conn, %{})
        end
        """)})
    m = elements(doc, "MassAssignment")
    assert m["lib/app/user.ex:8"] == {"allowlist": True, "privileged_assignable": True}
    assert m["lib/app/user.ex:9"] == {"allowlist": True, "privileged_assignable": False}
    assert m["lib/app/user.ex:10"] == {"allowlist": True, "privileged_assignable": False}
    assert "lib/app/user.ex:11" not in m   # a map with fixed keys: the client cannot name the field


# ---------------------------------------------------------------- Deserialization

def test_binary_to_term(tmp_path):
    doc = repo(tmp_path, {"lib/app_web/item_controller.ex": ctrl("""\
        def show(conn, _params) do
          data = Base.decode64!(conn.req_cookies["state"])
          :erlang.binary_to_term(data)
          :erlang.binary_to_term(data, [:safe])
          Plug.Crypto.non_executable_binary_to_term(data, [:safe])
          json(conn, %{})
        end
        """)})
    d = elements(doc, "Deserialization")
    base = "lib/app_web/item_controller.ex:"
    assert d[base + "5"] == {"safe_mode": False, "untrusted_input": True}
    assert d[base + "6"] == {"safe_mode": True, "untrusted_input": True}
    assert d[base + "7"] == {"safe_mode": True, "untrusted_input": True}


# ---------------------------------------------------------------- system facts

ROUTER = """\
defmodule AppWeb.Router do
  use Phoenix.Router
  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    %s
    plug :put_secure_browser_headers%s
  end
  pipeline :api do
    plug :accepts, ["json"]
  end
  scope "/", AppWeb do
    pipe_through :browser
    post "/users/log_in", UserSessionController, :create
  end
  scope "/api", AppWeb do
    pipe_through :api
    post "/items", ItemController, :create
  end
end
"""
SESSION = """\
defmodule AppWeb.UserSessionController do
  use AppWeb, :controller
  def create(conn, %{"user" => %{"email" => email, "password" => password}}) do
    App.Accounts.get_user_by_email_and_password(email, password)
    conn
  end
end
"""


def test_csrf_csp_and_login_rate_limit(tmp_path):
    files = {"lib/app_web/router.ex": ROUTER % ("plug :protect_from_forgery", ""),
             "lib/app_web/user_session_controller.ex": SESSION}
    doc = repo(tmp_path, files)
    assert fact(doc, "csrf_protection") == [(True, "lib/app_web/router.ex:6")]
    assert fact(doc, "content_security_policy") == [(False, "lib/app_web/router.ex:7")]   # Phoenix < 1.8: no CSP
    assert fact(doc, "login_rate_limited") == [(False, "lib/app_web/router.ex:14")]
    doc = repo(tmp_path, files, phoenix="1.8.1")
    assert fact(doc, "content_security_policy") == [(True, "lib/app_web/router.ex:7")]   # 1.8 sends a minimal CSP
    files["lib/app_web/router.ex"] = ROUTER % ("", ', %{"content-security-policy" => "default-src \'self\'"}')
    files["lib/app_web/user_session_controller.ex"] = SESSION.replace(
        "    App.Accounts", '    {:allow, _} = Hammer.check_rate("login", 60_000, 5)\n    App.Accounts')
    doc = repo(tmp_path, files)
    assert fact(doc, "csrf_protection") == [(False, "lib/app_web/router.ex:14")]
    assert fact(doc, "content_security_policy") == [(True, "lib/app_web/router.ex:7")]
    assert values(doc, "login_rate_limited") == {True}


def test_phx_gen_auth_password_policy(tmp_path):
    doc = repo(tmp_path, {"lib/app/accounts/user.ex": """\
        defmodule App.Accounts.User do
          use Ecto.Schema
          import Ecto.Changeset
          schema "users" do
            field :email, :string
            field :password, :string, virtual: true
            field :hashed_password, :string
          end
          defp validate_password(changeset) do
            changeset
            |> validate_length(:password, min: 12, max: 72)
            # |> validate_format(:password, ~r/[a-z]/, message: "at least one lower case character")
            |> put_change(:hashed_password, Bcrypt.hash_pwd_salt(get_change(changeset, :password)))
          end
        end
        """})
    assert fact(doc, "password_min_length") == [(12, "lib/app/accounts/user.ex:11")]
    assert values(doc, "password_max_length") == {72}
    assert values(doc, "password_composition_rules") == {False}   # the commented-out rule does not count
    assert values(doc, "processes_personal_data") == {True}
    assert values(doc, "account_erasure") == {False}


def test_debug_in_production_and_log_filter(tmp_path):
    files = {"config/dev.exs": """\
        import Config
        config :app, AppWeb.Endpoint, debug_errors: true, code_reloader: true
        """, "config/prod.exs": """\
        import Config
        config :app, AppWeb.Endpoint, url: [host: "example.com"]
        """}
    doc = repo(tmp_path, files)
    assert values(doc, "debug_in_production") == {False}
    assert fact(doc, "log_redacts_credentials") == [(False, "mix.lock:3")]   # Phoenix < 1.8.7 filters only "password"
    files["config/prod.exs"] += 'config :app, AppWeb.Endpoint, debug_errors: true\n'
    files["config/config.exs"] = 'import Config\nconfig :phoenix, :filter_parameters, ["password", "token", "secret"]\n'
    doc = repo(tmp_path, files)
    assert fact(doc, "debug_in_production") == [(True, "config/prod.exs:3")]
    assert fact(doc, "log_redacts_credentials") == [(True, "config/config.exs:2")]
    del files["config/config.exs"]
    doc = repo(tmp_path, files, phoenix="1.8.7")
    assert values(doc, "log_redacts_credentials") == {True}


def test_account_erasure_reachable_from_a_request(tmp_path):
    doc = repo(tmp_path, {"lib/app/accounts.ex": """\
        defmodule App.Accounts do
          use Ecto.Schema
          schema "users" do
            field :email, :string
          end
          def delete_user(user), do: App.Repo.delete(user)
        end
        """, "lib/app_web/item_controller.ex": ctrl("""\
        def delete(conn, _params) do
          App.Accounts.delete_user(conn.assigns.current_user)
          json(conn, %{})
        end
        """)})
    assert fact(doc, "account_erasure") == [(True, "lib/app/accounts.ex:6")]


# ---------------------------------------------------------------- document

def test_document_shape_cli_and_determinism(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / ".git").mkdir()
    (src / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (src / ".git" / "refs" / "heads").mkdir(parents=True)
    (src / ".git" / "refs" / "heads" / "main").write_text("a" * 40 + "\n")
    doc = repo(src, {"lib/app/accounts.ex": "defmodule App.Accounts do\n  def h(password), do: Bcrypt.hash_pwd_salt(password)\nend\n",
                     "lib/broken.ex": "defmodule Broken do\n  def x( do\nend\n"})
    s = doc["sources"][0]
    assert doc["subject"] == {"kind": "system", "id": "src"}
    assert s["adapter"] == "adapters.code_elixir" and s["kind"] == "static_analysis" and s["commit"] == "a" * 40
    assert s["unparsed"] == ["lib/broken.ex"]
    e = doc["elements"][0]
    assert e["id"] == f"{e['type']}@{e['at']}" and e["facts"]["algorithm"][0] == {"value": "bcrypt", "source": "static", "at": e["at"]}
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    assert main([str(src), "-o", str(a), "--name", "app"]) == 0
    assert main([str(src), "-o", str(b), "--name", "app"]) == 0
    assert a.read_bytes() == b.read_bytes()
    ev = load_evidence(str(a))
    assert ev.subject["id"] == "app" and any(x.type == "PasswordStore" for x in ev.elements)


def test_customer_model(tmp_path):
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "acme.yaml").write_text(textwrap.dedent("""\
        model: acme-crypto
        language: elixir
        rules:
          - call: Acme.Crypto.hash_secret
            password_hash: {algorithm: argon2, salted: true, password: 0}
        """))
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib").mkdir()
    (src / "lib" / "a.ex").write_text("defmodule A do\n  def h(password), do: Acme.Crypto.hash_secret(password)\nend\n")
    doc = analyse(src, models=[tmp_path / "models"])
    e = elements(doc, "PasswordStore")["lib/a.ex:2"]
    assert e == {"algorithm": "argon2", "salted": True}
    assert doc["sources"][0]["models"][0]["model"] == "acme-crypto"


def test_any_field_of_a_person_schema_is_personal_data_whatever_it_is_named(tmp_path):
    module = """\
        defmodule App.Shop.%s do
          use Ecto.Schema
          schema "%s" do
            field :prenom, :string
            timestamps()
          end
        end
        """
    (tmp_path / "a").mkdir(), (tmp_path / "b").mkdir()
    doc = repo(tmp_path / "a", {"lib/app/shop/customer.ex": module % ("Customer", "customers")})
    assert fact(doc, "processes_personal_data") == [(True, "lib/app/shop/customer.ex:4")]
    doc = repo(tmp_path / "b", {"lib/app/shop/product.ex": module % ("Product", "products")})
    assert fact(doc, "processes_personal_data") == []

"""The Ruby/Rails static adapter on small synthetic repositories: each pattern next to its safe counterpart, and both
sides of each Rails default that depends on the version or on `config.load_defaults`."""

import textwrap
from pathlib import Path

import yaml

from adapters.code_ruby import analyse
from adapters.code_ruby.__main__ import main
from normir.evidence import load_evidence

LOCK = """\
GEM
  remote: https://rubygems.org/
  specs:
    rails ({rails})
    psych ({psych})

PLATFORMS
  ruby

RUBY VERSION
   ruby {ruby}p0
"""


def repo(tmp_path, files: dict, rails="7.1.3", psych="5.1.2", ruby="3.2.2", load_defaults="7.1", app=True):
    base = {}
    if app:
        base["config/application.rb"] = f"""\
            require_relative "boot"
            module App
              class Application < Rails::Application
                {"config.load_defaults " + load_defaults if load_defaults else ""}
              end
            end
            """
        base["Gemfile.lock"] = LOCK.format(rails=rails, psych=psych, ruby=ruby)
    base.update(files)
    for rel, text in base.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return analyse(tmp_path)


def elements(doc, type_):
    return {e["at"]: {k: v[0]["value"] for k, v in e["facts"].items()} for e in doc["elements"] if e["type"] == type_}


def fact(doc, name):
    return sorted({o["value"] for o in doc["facts"].get(name, [])}, key=str)


# ---------------------------------------------------------------- PasswordStore

def test_password_hashing(tmp_path):
    doc = repo(tmp_path, {
        "app/models/user.rb": """\
            class User < ApplicationRecord
              has_secure_password
            end
            """,
        "app/models/legacy.rb": """\
            class Legacy < ApplicationRecord
              def self.digest(password)
                Digest::MD5.hexdigest(password)
              end
              def self.sha(password, salt)
                Digest::SHA256.hexdigest(salt + password)
              end
              def self.bc(password)
                BCrypt::Password.create(password)
              end
              def self.enc(password)
                Base64.encode64(password)
              end
              def self.token(email)
                Digest::MD5.hexdigest(email)
              end
            end
            """})
    ps = elements(doc, "PasswordStore")
    assert ps["app/models/user.rb:2"] == {"algorithm": "bcrypt", "salted": True}
    assert ps["app/models/legacy.rb:3"] == {"algorithm": "md5", "salted": False}
    assert ps["app/models/legacy.rb:6"] == {"algorithm": "sha256", "salted": True}
    assert ps["app/models/legacy.rb:9"] == {"algorithm": "bcrypt", "salted": True}
    assert ps["app/models/legacy.rb:12"] == {"algorithm": "reversible", "salted": False}
    assert "app/models/legacy.rb:15" not in ps  # hashing an email is not storing a password
    assert fact(doc, "password_auth") == [True]
    assert fact(doc, "password_max_length") == [72]  # has_secure_password validates at most 72


def test_devise_password_store_and_policy(tmp_path):
    doc = repo(tmp_path, {
        "app/models/user.rb": """\
            class User < ApplicationRecord
              devise :database_authenticatable, :registerable, :validatable, :lockable
            end
            """,
        "config/initializers/devise.rb": """\
            Devise.setup do |config|
              config.password_length = 12..128
            end
            """,
        "config/routes.rb": """\
            Rails.application.routes.draw do
              devise_for :users
            end
            """})
    assert elements(doc, "PasswordStore")["app/models/user.rb:2"] == {"algorithm": "bcrypt", "salted": True}
    assert fact(doc, "password_min_length") == [12]
    assert fact(doc, "password_max_length") == [128]
    assert fact(doc, "login_rate_limited") == [True]  # :lockable
    assert fact(doc, "account_erasure") == [True]     # registrations#destroy with :registerable


def test_plaintext_password_compared_and_queried(tmp_path):
    doc = repo(tmp_path, {
        "app/controllers/sessions_controller.rb": """\
            class SessionsController < ApplicationController
              def create
                user = User.find_by(email: params[:email])
                if user.password == params[:password]
                  session[:user_id] = user.id
                end
                other = User.where(password: params[:password]).first
              end
            end
            """,
        "app/models/user.rb": "class User < ApplicationRecord\nend\n",
        "db/schema.rb": """\
            ActiveRecord::Schema[7.1].define(version: 1) do
              create_table "users" do |t|
                t.string "email"
                t.string "password"
              end
            end
            """})
    ps = elements(doc, "PasswordStore")
    assert ps["app/controllers/sessions_controller.rb:4"]["algorithm"] == "plaintext"
    assert ps["app/controllers/sessions_controller.rb:7"]["algorithm"] == "plaintext"


def test_secure_password_attribute_is_not_plaintext(tmp_path):
    doc = repo(tmp_path, {
        "app/models/user.rb": "class User < ApplicationRecord\n  has_secure_password\nend\n",
        "app/controllers/users_controller.rb": """\
            class UsersController < ApplicationController
              def create
                User.create!(email: params[:email], password: params[:password])
              end
            end
            """,
        "db/schema.rb": """\
            ActiveRecord::Schema[7.1].define(version: 1) do
              create_table "users" do |t|
                t.string "email"
                t.string "password_digest"
              end
            end
            """})
    assert set(elements(doc, "PasswordStore")) == {"app/models/user.rb:2"}


# ---------------------------------------------------------------- Query

def test_queries(tmp_path):
    doc = repo(tmp_path, {
        "app/models/user.rb": "class User < ApplicationRecord\nend\n",
        "app/controllers/users_controller.rb": """\
            class UsersController < ApplicationController
              def index
                a = User.where("name = '#{params[:name]}'")
                b = User.where("name = '" + params[:name] + "'")
                c = User.where("name = ?", params[:name])
                d = User.where(name: params[:name])
                e = User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
                f = User.where("active = true")
                g = User.where(active: true)
                h = ActiveRecord::Base.connection.execute("DELETE FROM sessions WHERE id = #{params[:id]}")
                i = User.order(params[:sort])
              end
            end
            """})
    q = elements(doc, "Query")
    at = lambda n: f"app/controllers/users_controller.rb:{n}"  # noqa: E731
    assert q[at(3)] == {"construction": "interpolated", "untrusted_input": True}
    assert q[at(4)] == {"construction": "concatenated", "untrusted_input": True}
    assert q[at(5)] == {"construction": "parameterized", "untrusted_input": True}
    assert q[at(6)] == {"construction": "orm", "untrusted_input": True}
    assert q[at(7)] == {"construction": "interpolated", "untrusted_input": True}
    assert at(8) not in q and at(9) not in q  # no request data: nothing to report
    assert q[at(10)] == {"construction": "interpolated", "untrusted_input": True}
    assert q[at(11)] == {"construction": "orm", "untrusted_input": True}  # Rails >= 6.0 refuses raw SQL in order()


def test_query_taint_through_helper_and_callee(tmp_path):
    doc = repo(tmp_path, {
        "app/models/report.rb": """\
            class Report < ApplicationRecord
              def self.by_col(col)
                select("#{col}")
              end
              def self.fixed(col)
                select("#{col}")
              end
            end
            """,
        "app/controllers/reports_controller.rb": """\
            class ReportsController < ApplicationController
              def index
                Report.by_col(column)
                Report.fixed("id")
              end

              private

              def column
                params[:col]
              end
            end
            """})
    q = elements(doc, "Query")
    assert q["app/models/report.rb:3"] == {"construction": "interpolated", "untrusted_input": True}
    assert q["app/models/report.rb:6"] == {"construction": "interpolated", "untrusted_input": False}


# ---------------------------------------------------------------- Cookie

def _session_store(**opts):
    args = "".join(f", {k}: {v}" for k, v in opts.items())
    return {"config/initializers/session_store.rb": f'Rails.application.config.session_store :cookie_store, key: "_app_session"{args}\n'}


def test_session_cookie_defaults_by_version(tmp_path):
    new = repo(tmp_path / "new", _session_store(), load_defaults="7.1")
    old = repo(tmp_path / "old", _session_store(), load_defaults="6.0", rails="6.0.6")
    at = "config/initializers/session_store.rb:1"
    assert elements(new, "Cookie")[at] == {"is_session": True, "secure": False, "http_only": True, "same_site": "lax"}
    assert elements(old, "Cookie")[at] == {"is_session": True, "secure": False, "http_only": True, "same_site": "unset"}


def test_session_cookie_explicit_and_force_ssl(tmp_path):
    files = {**_session_store(httponly="false", same_site=":strict"),
             "config/environments/production.rb": "Rails.application.configure do\n  config.force_ssl = true\nend\n"}
    doc = repo(tmp_path, files)
    assert elements(doc, "Cookie")["config/initializers/session_store.rb:1"] == {
        "is_session": True, "secure": True, "http_only": False, "same_site": "strict"}


def test_cookie_jar(tmp_path):
    doc = repo(tmp_path, {"app/controllers/a_controller.rb": """\
        class AController < ApplicationController
          def show
            cookies[:theme] = params[:theme]
            cookies[:auth_token] = { value: "x", httponly: true, secure: true, same_site: :strict }
          end
        end
        """})
    c = elements(doc, "Cookie")
    assert c["app/controllers/a_controller.rb:3"] == {"secure": False, "http_only": False, "same_site": "lax"}
    assert c["app/controllers/a_controller.rb:4"] == {"is_session": True, "secure": True, "http_only": True, "same_site": "strict"}


# ---------------------------------------------------------------- TokenVerification

def test_jwt_decode(tmp_path):
    doc = repo(tmp_path, {"app/lib/auth.rb": """\
        class Auth
          def a(t, k) = JWT.decode(t, k, false)
          def b(t, k) = JWT.decode(t, k, true, algorithm: "HS256")
          def c(t, k) = JWT.decode(t, k, true, algorithms: ["HS256", "none"])
        end
        """})
    tv = elements(doc, "TokenVerification")
    assert tv["app/lib/auth.rb:2"] == {"verifies_signature": False, "allows_none_alg": True}
    assert tv["app/lib/auth.rb:3"] == {"verifies_signature": True, "allows_none_alg": False}
    assert tv["app/lib/auth.rb:4"] == {"verifies_signature": True, "allows_none_alg": True}


# ---------------------------------------------------------------- Secret

def test_secrets(tmp_path):
    doc = repo(tmp_path, {
        "config/initializers/secret_token.rb": 'App::Application.config.secret_key_base = "3f9a1c0b7e2d4a6f8b1c3e5d7f9a2b4c"\n',
        "config/initializers/stripe.rb": 'Stripe.api_key = ENV.fetch("STRIPE_API_KEY", "sk_live_abcdefghijklmnop1234")\n',
        "config/initializers/env.rb": 'Stripe.api_key = ENV.fetch("STRIPE_API_KEY")\n',
        "config/environments/development.rb": 'Rails.application.configure do\n  config.secret_key_base = "devdevdevdevdevdevdev123"\nend\n',
        "config/secrets.yml": """\
            development:
              secret_key_base: abcdef0123456789abcdef0123456789
            production:
              secret_key_base: fedcba9876543210fedcba9876543210
            staging:
              secret_key_base: <%= ENV["SECRET_KEY_BASE"] %>
            """,
        "config/master.key": "0123456789abcdef0123456789abcdef\n"})
    s = elements(doc, "Secret")
    assert s["config/initializers/secret_token.rb:1"] == {"kind": "signing_key"}
    assert s["config/initializers/stripe.rb:1"] == {"kind": "api_key"}
    assert not any(k.startswith("config/initializers/env.rb") for k in s)
    assert s["config/environments/development.rb:2"] == {"kind": "signing_key", "test_or_example": True}
    assert s["config/secrets.yml:2"] == {"kind": "signing_key", "test_or_example": True}
    assert s["config/secrets.yml:4"] == {"kind": "signing_key"}
    assert "config/secrets.yml:6" not in s
    assert s["config/master.key:1"] == {"kind": "private_key"}
    text = yaml.safe_dump(doc)
    for value in ("3f9a1c0b7e2d", "sk_live_abc", "fedcba98765", "0123456789abcdef0123"):
        assert value not in text  # only the kind is written, never the value


# ---------------------------------------------------------------- LogStatement

def test_log_statements(tmp_path):
    doc = repo(tmp_path, {"app/controllers/s_controller.rb": """\
        class SController < ApplicationController
          def create
            Rails.logger.info "login #{params[:email]} with #{params[:password]}"
            logger.debug params.inspect
            Rails.logger.info "request #{request.request_id} took #{1}"
            puts "user #{current_user.email}"
          end
        end
        """})
    lg = elements(doc, "LogStatement")
    assert lg["app/controllers/s_controller.rb:3"] == {"logs_credentials": True, "logs_personal_data": True}
    assert lg["app/controllers/s_controller.rb:4"]["logs_credentials"] is True  # whole params of a password action
    assert "app/controllers/s_controller.rb:5" not in lg
    assert lg["app/controllers/s_controller.rb:6"] == {"logs_credentials": False, "logs_personal_data": True}


# ---------------------------------------------------------------- Transfer

def test_transfers(tmp_path):
    doc = repo(tmp_path, {
        "app/mailers/user_mailer.rb": """\
            class UserMailer < ApplicationMailer
              def welcome(user)
                mail(to: user.email, subject: "hi")
              end
            end
            """,
        "app/services/hook.rb": """\
            class Hook
              def send_it(user)
                Net::HTTP.post(URI("https://hooks.example.net/in"), { email: user.email }.to_json)
                Net::HTTP.post(URI("http://localhost:3000/in"), "{}")
                HTTParty.post("https://api.partner.io/v1/users", body: { name: user.name })
              end
            end
            """,
        "config/initializers/sentry.rb": 'Sentry.init do |config|\n  config.dsn = ENV["DSN"]\nend\n'})
    t = elements(doc, "Transfer")
    assert t["app/mailers/user_mailer.rb:3"] == {"recipient": "email (SMTP relay)", "personal_data": True}
    assert t["app/services/hook.rb:3"] == {"recipient": "hooks.example.net", "personal_data": True}
    assert "app/services/hook.rb:4" not in t
    assert t["app/services/hook.rb:5"]["recipient"] == "api.partner.io"
    assert t["config/initializers/sentry.rb:1"] == {"recipient": "Sentry"}


# ---------------------------------------------------------------- CommandExecution

def test_commands(tmp_path):
    doc = repo(tmp_path, {"app/controllers/c_controller.rb": """\
        class CController < ApplicationController
          def run
            system("convert #{params[:file]} out.png")
            system("convert", params[:file], "out.png")
            `ls -la`
            x = %x(du -sh #{params[:dir]})
            Open3.capture2("git", "log")
            system("tar " + params[:name])
          end
        end
        """})
    c = elements(doc, "CommandExecution")
    at = lambda n: f"app/controllers/c_controller.rb:{n}"  # noqa: E731
    assert c[at(3)] == {"construction": "interpolated", "untrusted_input": True}
    assert c[at(4)] == {"construction": "argv", "untrusted_input": True}
    assert c[at(5)] == {"construction": "constant", "untrusted_input": False}
    assert c[at(6)] == {"construction": "interpolated", "untrusted_input": True}
    assert c[at(7)] == {"construction": "argv", "untrusted_input": False}
    assert c[at(8)] == {"construction": "concatenated", "untrusted_input": True}


# ---------------------------------------------------------------- HtmlOutput

def test_html_output(tmp_path):
    doc = repo(tmp_path, {
        "app/controllers/posts_controller.rb": """\
            class PostsController < ApplicationController
              def show
                @q = params[:q]
              end
              def create
                Post.create(params.require(:post).permit(:body))
              end
            end
            """,
        "app/models/post.rb": "class Post < ApplicationRecord\nend\n",
        "app/views/posts/show.html.erb": """\
            <h1><%= raw @q %></h1>
            <p><%== @post.body %></p>
            <p><%= sanitize @post.body %></p>
            <p><%= "<b>fixed</b>".html_safe %></p>
            <p><%= @post.body %></p>
            <p><%= raw @post.rendered_widget %></p>
            """})
    h = elements(doc, "HtmlOutput")
    at = lambda n: f"app/views/posts/show.html.erb:{n}"  # noqa: E731
    assert h[at(1)] == {"untrusted_input": True, "sanitized": False}
    assert h[at(2)] == {"untrusted_input": True, "sanitized": False}  # body is permitted from a request
    assert h[at(3)] == {"untrusted_input": True, "sanitized": True}
    assert h[at(4)] == {"untrusted_input": False, "sanitized": False}
    assert at(5) not in h  # escaped by ERB
    assert h[at(6)] == {"sanitized": False}  # cannot tell: untrusted_input left out


# ---------------------------------------------------------------- MassAssignment

def test_mass_assignment(tmp_path):
    files = {
        "app/models/user.rb": "class User < ApplicationRecord\nend\n",
        "app/controllers/users_controller.rb": """\
            class UsersController < ApplicationController
              def create
                User.new(params.require(:user).permit!)
                User.create(user_params)
                User.create(profile_params)
                User.new(params[:user])
              end

              private

              def user_params
                params.require(:user).permit(:name, :email, :admin)
              end

              def profile_params
                params.require(:user).permit(:name, :email)
              end
            end
            """}
    doc = repo(tmp_path / "r7", files)
    m = elements(doc, "MassAssignment")
    at = lambda n: f"app/controllers/users_controller.rb:{n}"  # noqa: E731
    assert m[at(3)]["allowlist"] is False
    assert m[at(4)] == {"allowlist": True, "privileged_assignable": True}
    assert m[at(5)] == {"allowlist": True, "privileged_assignable": False}
    assert at(6) not in m  # Rails 4+: raw params raise ForbiddenAttributesError
    old = elements(repo(tmp_path / "r3", files, rails="3.2.22", load_defaults=None), "MassAssignment")
    assert old[at(6)]["allowlist"] is False  # Rails 3 without attr_accessible: every column


# ---------------------------------------------------------------- Deserialization

def test_deserialization_by_psych_version(tmp_path):
    files = {"app/controllers/d_controller.rb": """\
        class DController < ApplicationController
          def load
            Marshal.load(Base64.decode64(params[:data]))
            YAML.load(params[:yaml])
            YAML.safe_load(params[:yaml])
            YAML.unsafe_load(File.read("config/x.yml"))
            Oj.load(params[:json])
          end
        end
        """}
    at = lambda n: f"app/controllers/d_controller.rb:{n}"  # noqa: E731
    new = elements(repo(tmp_path / "new", files, psych="5.1.2", ruby="3.2.2"), "Deserialization")
    old = elements(repo(tmp_path / "old", files, psych="3.3.4", ruby="3.0.6"), "Deserialization")
    assert new[at(3)] == {"safe_mode": False, "untrusted_input": True}
    assert new[at(4)] == {"safe_mode": True, "untrusted_input": True}
    assert old[at(4)] == {"safe_mode": False, "untrusted_input": True}
    assert new[at(5)]["safe_mode"] is True
    assert new[at(6)] == {"safe_mode": False, "untrusted_input": False}
    assert new[at(7)] == {"safe_mode": False, "untrusted_input": True}  # Oj default :object mode


# ---------------------------------------------------------------- system facts

def test_csrf_defaults(tmp_path):
    ctrl = {"app/controllers/application_controller.rb": "class ApplicationController < ActionController::Base\nend\n"}
    assert fact(repo(tmp_path / "a", ctrl, load_defaults="7.1"), "csrf_protection") == [True]
    assert fact(repo(tmp_path / "b", ctrl, load_defaults=None), "csrf_protection") == [False]
    explicit = {"app/controllers/application_controller.rb":
                "class ApplicationController < ActionController::Base\n  protect_from_forgery with: :exception\nend\n"}
    assert fact(repo(tmp_path / "c", explicit, load_defaults=None), "csrf_protection") == [True]
    skip = {**ctrl, "app/controllers/forms_controller.rb":
            "class FormsController < ApplicationController\n  skip_forgery_protection\nend\n"}
    assert fact(repo(tmp_path / "d", skip), "csrf_protection") == [False, True]
    api = {"app/controllers/application_controller.rb": "class ApplicationController < ActionController::API\nend\n"}
    assert fact(repo(tmp_path / "e", api, load_defaults=None), "csrf_protection") == [True]


def test_tls_hsts_debug_csp(tmp_path):
    prod_on = {"config/environments/production.rb": """\
        Rails.application.configure do
          config.force_ssl = true
          config.consider_all_requests_local = false
        end
        """,
        "config/initializers/content_security_policy.rb": """\
        Rails.application.configure do
          config.content_security_policy do |policy|
            policy.default_src :self
          end
        end
        """}
    doc = repo(tmp_path / "on", prod_on)
    assert fact(doc, "tls_enforced") == [True] and fact(doc, "hsts") == [True]
    assert fact(doc, "hsts_max_age") == [63072000]  # Rails >= 6.1
    assert fact(doc, "debug_in_production") == [False]
    assert fact(doc, "content_security_policy") == [True]
    old = repo(tmp_path / "old", prod_on, rails="6.0.6", load_defaults="6.0")
    assert fact(old, "hsts_max_age") == [31536000]
    prod_off = {"config/environments/production.rb": """\
        Rails.application.configure do
          config.consider_all_requests_local = true
        end
        """,
        "config/initializers/content_security_policy.rb": """\
        # Rails.application.configure do
        #   config.content_security_policy do |policy|
        #     policy.default_src :self
        #   end
        # end
        """}
    doc = repo(tmp_path / "off", prod_off)
    assert fact(doc, "tls_enforced") == [False] and fact(doc, "hsts") == [False]
    assert "hsts_max_age" not in doc["facts"]
    assert fact(doc, "debug_in_production") == [True]
    assert fact(doc, "content_security_policy") == [False]


def test_log_filtering(tmp_path):
    ok = {"config/initializers/filter_parameter_logging.rb":
          "Rails.application.config.filter_parameters += [:passw, :secret, :token, :_key, :crypt, :salt, :certificate, :otp, :ssn]\n",
          "app/controllers/t_controller.rb": "class TController < ApplicationController\n  def a = params[:api_token]\nend\n"}
    assert fact(repo(tmp_path / "ok", ok), "log_redacts_credentials") == [True]
    weak = {**ok, "config/initializers/filter_parameter_logging.rb": "Rails.application.config.filter_parameters += [:password]\n"}
    assert fact(repo(tmp_path / "weak", weak), "log_redacts_credentials") == [False]  # tokens are logged


def test_rack_attack_and_erasure_and_export(tmp_path):
    doc = repo(tmp_path, {
        "app/models/user.rb": "class User < ApplicationRecord\n  has_secure_password\nend\n",
        "db/schema.rb": """\
            ActiveRecord::Schema[7.1].define(version: 1) do
              create_table "users" do |t|
                t.string "email"
              end
            end
            """,
        "app/controllers/sessions_controller.rb": """\
            class SessionsController < ApplicationController
              def create
                user = User.find_by(email: params[:email])&.authenticate(params[:password])
              end
            end
            """,
        "app/controllers/accounts_controller.rb": """\
            class AccountsController < ApplicationController
              def destroy
                current_user.destroy
              end
              def export
                send_data current_user.to_json, filename: "me.json"
              end
            end
            """,
        "config/initializers/rack_attack.rb": """\
            Rack::Attack.throttle("logins/ip", limit: 5, period: 20) do |req|
              req.ip if req.path == "/login" && req.post?
            end
            """})
    assert fact(doc, "processes_personal_data") == [True]
    assert fact(doc, "login_rate_limited") == [True]
    assert fact(doc, "account_erasure") == [True]
    assert fact(doc, "account_data_export") == [True]


def test_no_rate_limit_no_erasure(tmp_path):
    doc = repo(tmp_path, {
        "app/models/user.rb": "class User < ApplicationRecord\n  has_secure_password\nend\n",
        "db/schema.rb": 'ActiveRecord::Schema[7.1].define(version: 1) do\n  create_table "users" do |t|\n    t.string "email"\n  end\nend\n',
        "app/controllers/sessions_controller.rb": """\
            class SessionsController < ApplicationController
              def create
                user = User.find_by(email: params[:email])&.authenticate(params[:password])
              end
            end
            """})
    assert fact(doc, "login_rate_limited") == [False]
    assert fact(doc, "account_erasure") == [False]
    assert fact(doc, "account_data_export") == [False]


# ---------------------------------------------------------------- document shape, CLI, determinism

def test_shape_cli_and_determinism(tmp_path):
    src = tmp_path / "src"
    repo(src, {"app/models/user.rb": "class User < ApplicationRecord\n  has_secure_password\nend\n",
               "app/views/x.html.erb": "<%= raw params[:x] %>\n"})
    (src / ".git").mkdir()
    (src / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (src / ".git" / "refs" / "heads").mkdir(parents=True)
    (src / ".git" / "refs" / "heads" / "main").write_text("a" * 40 + "\n")
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    assert main([str(src), "-o", str(a), "--name", "demo"]) == 0
    assert main([str(src), "-o", str(b), "--name", "demo"]) == 0
    assert a.read_bytes() == b.read_bytes()
    doc = yaml.safe_load(a.read_text())
    assert doc["subject"] == {"kind": "system", "id": "demo"}
    s = doc["sources"][0]
    assert s["adapter"] == "adapters.code_ruby" and s["commit"] == "a" * 40 and s["kind"] == "static_analysis"
    assert s["files_analysed"] == 3 and s["unparsed"] == []
    for e in doc["elements"]:
        assert e["id"] == f"{e['type']}@{e['at']}"
        for obs in e["facts"].values():
            assert obs[0]["source"] == "static" and obs[0]["at"] == e["at"]
    load_evidence(doc)


def test_customer_model(tmp_path):
    model = tmp_path / "acme.yaml"
    model.write_text(textwrap.dedent("""\
        model: acme
        version: "1"
        language: ruby
        rules:
          - call: AcmeCrypto.hash_secret
            password_hash: {algorithm: argon2, salted: true, password: 0}
        """))
    src = tmp_path / "src"
    (src / "app/models").mkdir(parents=True)
    (src / "app/models/user.rb").write_text("class User\n  def set(password)\n    AcmeCrypto.hash_secret(password)\n  end\nend\n")
    doc = analyse(src, models=[model])
    e = next(e for e in doc["elements"] if e["type"] == "PasswordStore")
    assert e["facts"]["algorithm"][0] == {"value": "argon2", "source": "static", "at": "app/models/user.rb:3", "model": "acme@1"}
    assert doc["sources"][0]["models"][0]["places"] >= 1


def test_bench_evidence_is_valid():
    """The evidence written for the two public Rails repositories comes from this adapter and loads."""
    root = Path(__file__).resolve().parents[1]
    for name in ("railsgoat", "lobsters"):
        p = root / "bench" / "evidence" / f"{name}.static.yaml"
        doc = yaml.safe_load(p.read_text())
        assert doc["sources"][0]["adapter"] == "adapters.code_ruby"
        assert doc["elements"] and doc["facts"]
        load_evidence(doc)

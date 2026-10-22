"""
Moduł 1 - identyfikacja, uwierzytelnianie i autoryzacja (wariant 4)

Instalacja:   python -m pip install flask
Uruchomienie: python app.py  ->  http://127.0.0.1:5000

Pierwsze uruchomienie tworzy app.db (ADMIN + 6 kont testowych).
Przy każdym starcie terminal wypisuje hasła jednorazowe kont bez własnego hasła.
Reset bazy: usuń app.db.
"""
import functools
import secrets
import sqlite3
import string
import time
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

# ===================== Wariant 4: parametry, role, uprawnienia =====================

DB_PATH = Path(__file__).with_name("app.db")
ADMIN_LOGIN = "ADMIN"                     # stałe konto administratora

OTP_LENGTH = 10                           # hasło jednorazowe: 10 znaków
OTP_ALPHABET = "".join(c for c in string.ascii_letters + string.digits
                       if c not in "0O1lI")   # bez 0/O, 1/l/I
OTP_VALIDITY = 8 * 60 * 60                # ważność: 8 h (w sekundach)
MIN_DISTINCT_CHARS = 8                    # reguła włączana przez administratora

# Wartości początkowe ustawień z panelu administratora
DEFAULT_SETTINGS = {
    "min_password_length": 16,
    "require_distinct_chars": 0,          # 1 = reguła 8 różnych znaków włączona
    "password_max_age_days": 0,           # 0 = bez limitu
    "session_timeout_minutes": 15,
}

# RBAC wg zasady najmniejszych uprawnień
ROLE_PERMISSIONS = {
    "Administrator": {"users.read", "users.manage", "settings.manage"},
    "Audytor":       {"users.read"},                          # tylko odczyt
    "Redaktor":      {"document.read", "document.edit"},
    "Czytelnik":     {"document.read"},
}
USER_ROLES = ["Audytor", "Redaktor", "Czytelnik"]   # Administrator tylko dla konta ADMIN

TEST_USERS = [("audytor1", "Audytor"), ("audytor2", "Audytor"),
              ("redaktor1", "Redaktor"), ("redaktor2", "Redaktor"),
              ("czytelnik1", "Czytelnik"), ("czytelnik2", "Czytelnik")]

# ===================== Hasła =====================
# Hash z solą: generate_password_hash / check_password_hash (Werkzeug, scrypt).


def check_password_policy(password, settings):
    """Zwraca listę naruszeń polityki haseł (pusta = hasło poprawne)."""
    errors = []
    if len(password) < settings["min_password_length"]:
        errors.append(f"Hasło jest za krótkie (minimalna długość: {settings['min_password_length']}).")
    if settings["require_distinct_chars"] and len(set(password)) < MIN_DISTINCT_CHARS:
        errors.append(f"Hasło musi zawierać co najmniej {MIN_DISTINCT_CHARS} różnych znaków.")
    return errors

# ===================== Baza danych (SQLite) =====================
# Czas: sekundy od 1970 r. (time.time()).

SCHEMA = """
CREATE TABLE users (
    id                   INTEGER PRIMARY KEY,
    login                TEXT NOT NULL UNIQUE,
    role                 TEXT NOT NULL,
    password_hash        TEXT NOT NULL DEFAULT '',    -- algorytm$sól$hash
    must_change_password INTEGER NOT NULL DEFAULT 1,  -- 1 = hasło jednorazowe
    otp_expires_at       REAL,               -- ważność hasła jednorazowego
    password_changed_at  REAL,               -- data ustawienia własnego hasła
    is_blocked           INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE password_history (              -- poprzednie hasła
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL
);
CREATE TABLE settings (                      -- ustawienia z panelu administratora
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
CREATE TABLE document (                      -- dokument Redaktora i Czytelnika
    content TEXT NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, params=(), one=False):
    rows = get_db().execute(sql, params).fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, params=()):
    get_db().execute(sql, params)
    get_db().commit()


def get_settings():
    return {row["key"]: row["value"] for row in query("SELECT key, value FROM settings")}


def set_one_time_password(login):
    """Nadaje hasło jednorazowe: zapisuje hash, wypisuje hasło w terminalu, zwraca komunikat."""
    otp = "".join(secrets.choice(OTP_ALPHABET) for _ in range(OTP_LENGTH))
    expires = time.time() + OTP_VALIDITY
    execute("UPDATE users SET password_hash = ?, must_change_password = 1, otp_expires_at = ? "
            "WHERE login = ?", (generate_password_hash(otp), expires, login))
    valid_until = time.strftime("%Y-%m-%d %H:%M", time.localtime(expires))
    message = f"Hasło jednorazowe dla {login}: {otp} (ważne do {valid_until})"
    print(message, flush=True)
    return message


def init_db():
    """Tworzy tabele, ustawienia, dokument i konta (hasła nadaje blok startowy)."""
    db = get_db()
    db.executescript(SCHEMA)
    db.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", DEFAULT_SETTINGS.items())
    db.execute("INSERT INTO document (content) VALUES ('Przykładowy dokument.')")
    db.executemany("INSERT INTO users (login, role) VALUES (?, ?)", [(ADMIN_LOGIN, "Administrator")] + TEST_USERS)
    db.commit()

# ===================== Sesja i uprawnienia =====================

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # klucz podpisu sesji, nowy przy każdym starcie
app.teardown_appcontext(close_db)


def password_change_reason(user):
    """Powód wymuszonej zmiany hasła: 'otp', 'expired' albo None."""
    if user["must_change_password"]:
        return "otp"
    days = get_settings()["password_max_age_days"]
    if days and time.time() - user["password_changed_at"] > days * 24 * 60 * 60:
        return "expired"
    return None


@app.before_request
def load_user():
    """Przed każdym żądaniem: sesja, bezczynność, blokada, wymuszona zmiana hasła."""
    g.user = None
    if "user_id" not in session:
        return None
    timeout = get_settings()["session_timeout_minutes"]
    if time.time() - session.get("last_activity", 0) > timeout * 60:   # limit bezczynności
        session.clear()
        flash(f"Wylogowano automatycznie po {timeout} min bezczynności.")
        return redirect(url_for("login"))
    user = query("SELECT * FROM users WHERE id = ?", (session["user_id"],), one=True)
    if user is None or user["is_blocked"]:                              # konto usunięte lub zablokowane
        session.clear()
        return redirect(url_for("login"))
    session["last_activity"] = time.time()
    g.user = user
    if password_change_reason(user) and request.endpoint not in ("change_password", "logout"):
        return redirect(url_for("change_password"))                     # wymuszona zmiana hasła
    return None


def can(permission):
    """Czy rola zalogowanego użytkownika ma uprawnienie."""
    return g.user is not None and permission in ROLE_PERMISSIONS[g.user["role"]]


def login_required(permission=None):
    """Wymaga zalogowania; z argumentem także uprawnienia roli (sprawdzane na serwerze, inaczej 403)."""
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            if permission and not can(permission):
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.context_processor
def template_variables():
    user = g.get("user")
    timeout = get_settings()["session_timeout_minutes"] * 60 if user else 0
    return {"current_user": user, "can": can, "ADMIN_LOGIN": ADMIN_LOGIN, "timeout_seconds": timeout}

# ===================== Strony =====================

# --- 1. Logowanie i wylogowanie ---

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = query("SELECT * FROM users WHERE login = ?", (request.form.get("login", ""),), one=True)
        if user is None or not check_password_hash(user["password_hash"], request.form.get("password", "")):
            error = "Login lub hasło niepoprawne"
        elif user["is_blocked"]:
            error = "Konto jest zablokowane."
        elif user["must_change_password"] and time.time() > user["otp_expires_at"]:
            error = "Hasło jednorazowe wygasło. Poproś administratora o reset hasła."
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["last_activity"] = time.time()
            return redirect(url_for("index"))
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    flash("Wylogowano.")
    return redirect(url_for("login"))


@app.route("/")
@login_required()
def index():
    return redirect(url_for("document" if can("document.read") else "users"))

# --- 2. i 3. Pierwsze logowanie i zmiana hasła ---

@app.route("/change-password", methods=["GET", "POST"])
@login_required()
def change_password():
    reason = password_change_reason(g.user)
    settings = get_settings()
    errors = []
    if request.method == "POST":
        old = request.form.get("old_password", "")
        new = request.form.get("new_password", "")
        if not check_password_hash(g.user["password_hash"], old):
            errors.append("Stare hasło jest niepoprawne.")
        elif new != request.form.get("repeat_password", ""):
            errors.append("Nowe hasło i jego powtórzenie nie są takie same.")
        else:
            errors = check_password_policy(new, settings)
            previous = {g.user["password_hash"]} | {row["password_hash"] for row in query(
                "SELECT password_hash FROM password_history WHERE user_id = ?", (g.user["id"],))}
            if not errors and any(check_password_hash(h, new) for h in previous):
                errors.append("Nowe hasło musi różnić się od poprzednich haseł.")
        if not errors:
            new_hash = generate_password_hash(new)
            execute("UPDATE users SET password_hash = ?, must_change_password = 0, otp_expires_at = NULL, "
                    "password_changed_at = ? WHERE id = ?", (new_hash, time.time(), g.user["id"]))
            execute("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
                    (g.user["id"], new_hash))
            flash("Hasło zostało zmienione.")
            return redirect(url_for("index"))
    return render_template("change_password.html", reason=reason, settings=settings, errors=errors)

# --- 4. i 5. Użytkownicy i hasła jednorazowe ---

def get_editable_user(user_id):
    """Konto do zmiany przez administratora; konto ADMIN chronione (403)."""
    user = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if user is None:
        abort(404)
    if user["login"] == ADMIN_LOGIN:
        abort(403)
    return user


@app.route("/users")
@login_required("users.read")
def users():
    return render_template("users.html", users=query("SELECT * FROM users ORDER BY id"))


@app.route("/users/new", methods=["GET", "POST"])
@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required("users.manage")
def user_form(user_id=None):
    edited = get_editable_user(user_id) if user_id is not None else None
    if request.method == "POST":
        new_login = request.form.get("login", "").strip()
        role = request.form.get("role")
        same_login = query("SELECT id FROM users WHERE login = ?", (new_login,), one=True)
        if not new_login or role not in USER_ROLES:
            flash("Podaj login i wybierz rolę.")
        elif same_login and (edited is None or same_login["id"] != edited["id"]):
            flash("Taki login już istnieje.")
        elif edited:
            execute("UPDATE users SET login = ?, role = ? WHERE id = ?", (new_login, role, user_id))
            return redirect(url_for("users"))
        else:
            execute("INSERT INTO users (login, role) VALUES (?, ?)", (new_login, role))
            flash(set_one_time_password(new_login))          # hasło jednorazowe: nowe konto
            return redirect(url_for("users"))
    return render_template("user_form.html", edited=edited, roles=USER_ROLES)


@app.route("/users/<int:user_id>/action", methods=["POST"])
@login_required("users.manage")
def user_action(user_id):
    """Blokada/odblokowanie, reset hasła, usunięcie konta."""
    user = get_editable_user(user_id)
    action = request.form.get("action")
    if action == "block":
        execute("UPDATE users SET is_blocked = ? WHERE id = ?", (0 if user["is_blocked"] else 1, user_id))
    elif action == "reset":
        flash(set_one_time_password(user["login"]))          # hasło jednorazowe: reset
    elif action == "delete":
        execute("DELETE FROM users WHERE id = ?", (user_id,))
    return redirect(url_for("users"))

# --- 4. Ustawienia: polityka haseł, ważność hasła, bezczynność ---

@app.route("/settings", methods=["GET", "POST"])
@login_required("settings.manage")
def settings_page():
    if request.method == "POST":
        try:
            new_settings = {
                "min_password_length": int(request.form["min_password_length"]),
                "require_distinct_chars": 1 if request.form.get("require_distinct_chars") else 0,
                "password_max_age_days": int(request.form["password_max_age_days"]),
                "session_timeout_minutes": int(request.form["session_timeout_minutes"]),
            }
        except (KeyError, ValueError):
            new_settings = None
        if (new_settings is None or new_settings["min_password_length"] < 1
                or new_settings["password_max_age_days"] < 0
                or not 1 <= new_settings["session_timeout_minutes"] <= 1440):
            flash("Podaj poprawne liczby.")
        else:
            for key, value in new_settings.items():
                execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
            flash("Zapisano ustawienia.")
            return redirect(url_for("settings_page"))
    return render_template("settings.html", settings=get_settings())

# --- 6. Dokument: odczyt (Redaktor, Czytelnik), edycja (Redaktor) ---

@app.route("/document", methods=["GET", "POST"])
@login_required("document.read")
def document():
    if request.method == "POST":
        if not can("document.edit"):
            abort(403)
        execute("UPDATE document SET content = ?", (request.form.get("content", ""),))
        flash("Zapisano dokument.")
        return redirect(url_for("document"))
    return render_template("document.html", content=query("SELECT content FROM document", one=True)["content"])

# ===================== Szablony HTML =====================

TEMPLATES = {
    "base.html": """<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<title>Moduł 1 - wariant 4</title>
<style>
  body { margin: 0; font-family: system-ui, "Segoe UI", Arial, sans-serif; background: #f3f4f6; color: #1f2937; }
  nav { display: flex; gap: 18px; align-items: center; padding: 14px 24px; background: #111827; }
  nav a { color: #e5e7eb; text-decoration: none; }
  nav span { margin-left: auto; color: #9ca3af; }
  main { max-width: 860px; margin: 32px auto; padding: 0 16px; }
  h1 { font-size: 22px; margin-top: 0; }
  .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px 24px; margin-bottom: 16px; }
  .narrow { max-width: 420px; margin: 40px auto; }
  label { display: block; margin-top: 12px; font-weight: 600; }
  input, select, textarea { display: block; width: 100%; box-sizing: border-box; margin-top: 4px; padding: 8px;
                            font: inherit; border: 1px solid #d1d5db; border-radius: 6px; }
  input[type=checkbox] { display: inline; width: auto; margin-right: 6px; }
  button, .button { display: inline-block; margin-top: 16px; padding: 8px 14px; border: 0; border-radius: 6px;
                    background: #1d4ed8; color: #fff; font: inherit; text-decoration: none; cursor: pointer; }
  table { width: 100%; border-collapse: collapse; background: #fff; margin-top: 16px; }
  th, td { padding: 10px; text-align: left; border-bottom: 1px solid #e5e7eb; }
  td form { display: inline; }
  td button { margin: 0 0 0 6px; padding: 4px 10px; font-size: 14px; }
  .message { padding: 10px 14px; margin-bottom: 16px; border-radius: 6px; background: #fef3c7; }
  .error { background: #fee2e2; color: #991b1b; }
</style>
</head>
<body>
{% if current_user %}
<nav>
  {% if can('document.read') %}<a href="{{ url_for('document') }}">Dokument</a>{% endif %}
  {% if can('users.read') %}<a href="{{ url_for('users') }}">Użytkownicy</a>{% endif %}
  {% if can('settings.manage') %}<a href="{{ url_for('settings_page') }}">Ustawienia</a>{% endif %}
  <a href="{{ url_for('change_password') }}">Zmiana hasła</a>
  <span>{{ current_user.login }} ({{ current_user.role }})</span>
  <a href="{{ url_for('logout') }}">Wyloguj</a>
</nav>
{% endif %}
<main>
  {% for message in get_flashed_messages() %}<div class="message">{{ message }}</div>{% endfor %}
  {% block content %}{% endblock %}
</main>
{% if current_user %}
<script>
  // po limicie bezczynności przeładuj stronę (wylogowuje serwer)
  setTimeout(function () { location.href = "{{ url_for('index') }}"; }, ({{ timeout_seconds }} + 2) * 1000);
</script>
{% endif %}
</body>
</html>""",

    "login.html": """{% extends "base.html" %}
{% block content %}
<div class="card narrow">
  <h1>Logowanie</h1>
  {% if error %}<div class="message error">{{ error }}</div>{% endif %}
  <form method="post">
    <label>Login <input name="login" required autofocus></label>
    <label>Hasło <input name="password" type="password" required></label>
    <button>Zaloguj</button>
  </form>
</div>
{% endblock %}""",

    "change_password.html": """{% extends "base.html" %}
{% block content %}
<div class="card narrow">
  <h1>{% if reason == 'otp' %}Pierwsze logowanie - ustaw własne hasło{% elif reason == 'expired' %}Hasło wygasło - ustaw nowe{% else %}Zmiana hasła{% endif %}</h1>
  {% for e in errors %}<div class="message error">{{ e }}</div>{% endfor %}
  <form method="post">
    <label>{{ 'Hasło jednorazowe' if reason == 'otp' else 'Stare hasło' }} <input name="old_password" type="password" required></label>
    <label>Nowe hasło <input name="new_password" type="password" required></label>
    <label>Powtórz nowe hasło <input name="repeat_password" type="password" required></label>
    <p>Wymagania: minimalna długość {{ settings.min_password_length }}{% if settings.require_distinct_chars %}, co najmniej 8 różnych znaków{% endif %}; hasło musi różnić się od poprzednich.</p>
    <button>Zmień hasło</button>
  </form>
</div>
{% endblock %}""",

    "users.html": """{% extends "base.html" %}
{% block content %}
<h1>Użytkownicy</h1>
{% if can('users.manage') %}<a class="button" href="{{ url_for('user_form') }}">Dodaj użytkownika</a>{% endif %}
<table>
  <tr><th>Login</th><th>Rola</th><th>Status</th>{% if can('users.manage') %}<th>Akcje</th>{% endif %}</tr>
  {% for u in users %}
  <tr>
    <td>{{ u.login }}</td>
    <td>{{ u.role }}</td>
    <td>{{ 'zablokowane' if u.is_blocked else 'aktywne' }}</td>
    {% if can('users.manage') %}
    <td>
      {% if u.login != ADMIN_LOGIN %}
      <a href="{{ url_for('user_form', user_id=u.id) }}">Edytuj</a>
      <form method="post" action="{{ url_for('user_action', user_id=u.id) }}">
        <button name="action" value="block">{{ 'Odblokuj' if u.is_blocked else 'Zablokuj' }}</button>
        <button name="action" value="reset">Reset hasła</button>
        <button name="action" value="delete">Usuń</button>
      </form>
      {% endif %}
    </td>
    {% endif %}
  </tr>
  {% endfor %}
</table>
{% endblock %}""",

    "user_form.html": """{% extends "base.html" %}
{% block content %}
<div class="card narrow">
  <h1>{{ 'Edycja użytkownika' if edited else 'Nowy użytkownik' }}</h1>
  <form method="post">
    <label>Login <input name="login" value="{{ edited.login if edited }}" required></label>
    <label>Rola
      <select name="role">{% for r in roles %}<option {{ 'selected' if edited and edited.role == r }}>{{ r }}</option>{% endfor %}</select>
    </label>
    <button>Zapisz</button>
  </form>
</div>
{% endblock %}""",

    "settings.html": """{% extends "base.html" %}
{% block content %}
<div class="card narrow">
  <h1>Ustawienia</h1>
  <form method="post">
    <label>Minimalna długość hasła <input type="number" name="min_password_length" min="1" value="{{ settings.min_password_length }}"></label>
    <label><input type="checkbox" name="require_distinct_chars" {{ 'checked' if settings.require_distinct_chars }}>Polityka haseł z wariantu 4: co najmniej 8 różnych znaków</label>
    <label>Ważność hasła w dniach (0 = bez limitu) <input type="number" name="password_max_age_days" min="0" value="{{ settings.password_max_age_days }}"></label>
    <label>Czas bezczynności sesji w minutach (1-1440) <input type="number" name="session_timeout_minutes" min="1" max="1440" value="{{ settings.session_timeout_minutes }}"></label>
    <button>Zapisz</button>
  </form>
</div>
{% endblock %}""",

    "document.html": """{% extends "base.html" %}
{% block content %}
<div class="card">
  <h1>Dokument</h1>
  {% if can('document.edit') %}
  <form method="post">
    <textarea name="content" rows="8">{{ content }}</textarea>
    <button>Zapisz</button>
  </form>
  {% else %}
  <p style="white-space: pre-wrap">{{ content }}</p>
  {% endif %}
</div>
{% endblock %}""",
}
app.jinja_loader = DictLoader(TEMPLATES)

# ===================== Uruchomienie =====================

if __name__ == "__main__":
    with app.app_context():
        if not DB_PATH.exists():
            init_db()
        # hasha nie da się odczytać, więc przy każdym starcie nadajemy nowe hasła jednorazowe
        pending = query("SELECT login FROM users WHERE must_change_password = 1")
        print("Hasła jednorazowe (ważne 8 godzin):" if pending else "Wszystkie konta mają już własne hasła.")
        for user in pending:
            set_one_time_password(user["login"])
    app.run()
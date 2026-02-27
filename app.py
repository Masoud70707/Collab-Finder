import os
import re
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, session, flash,
    send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from jinja2 import DictLoader


# -----------------------------
# Config
# -----------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "collab.db"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# =========================
# DB INIT FOR RENDER FIX
# =========================

def ensure_schema():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        photo_filename TEXT,
        title TEXT,
        full_name TEXT,
        country TEXT,
        university TEXT,
        school_faculty TEXT,
        highest_qualification TEXT,
        position TEXT,
        supervisor_name TEXT,
        bio TEXT,
        skills TEXT,
        device_access TEXT,
        created_at TEXT,
        updated_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        read_at TEXT,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(recipient_id) REFERENCES users(id)
    )
    """)

    con.commit()
    con.close()

# =========================

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
MAX_UPLOAD_MB = 5

COUNTRIES = ["Australia"]  # MVP for now

AU_UNIVERSITIES = [
    "Australian National University (ANU)",
    "University of Sydney",
    "University of Melbourne",
    "University of Queensland",
    "University of New South Wales (UNSW)",
    "Monash University",
    "University of Western Australia (UWA)",
    "University of Adelaide",
    "University of Technology Sydney (UTS)",
    "RMIT University",
    "Macquarie University",
    "Queensland University of Technology (QUT)",
    "University of Newcastle",
    "University of Wollongong",
    "Deakin University",
    "Griffith University",
    "La Trobe University",
    "University of Tasmania",
    "University of South Australia",
    "Curtin University",
    "Swinburne University of Technology",
    "Flinders University",
    "Western Sydney University",
    "James Cook University",
    "University of Canberra",
    "Charles Sturt University",
    "Murdoch University",
    "Victoria University",
    "Bond University",
    "University of New England",
    "Federation University Australia",
]

QUALIFICATIONS = [
    "High School",
    "Certificate/Diploma",
    "Bachelor",
    "Honours",
    "Master (Coursework)",
    "Master (Research)",
    "PhD",
    "Other",
]

# Note: any label containing "Student" triggers supervisor field in UI
POSITIONS = [
    "Undergraduate Student",
    "Honours Student",
    "Master Student",
    "PhD Candidate",
    "Postdoctoral Researcher",
    "Research Assistant",
    "Academic (Lecturer/Senior Lecturer/Professor)",
    "Industry Professional",
    "Other",
]

TITLES = ["Mr", "Ms", "Dr", "Prof", "Other"]


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


# -----------------------------
# DB Helpers
# -----------------------------
def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON;")
    return con


def column_exists(con, table: str, col: str) -> bool:
    cur = con.execute(f"PRAGMA table_info({table})")
    cols = [r["name"] for r in cur.fetchall()]
    return col in cols


def init_db():
    con = get_db()
    try:
        con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)

        con.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            photo_filename TEXT,
            title TEXT,
            full_name TEXT,
            highest_qualification TEXT,
            country TEXT,
            university TEXT,
            school_faculty TEXT,
            position TEXT,
            supervisor_name TEXT,
            bio TEXT,
            skills TEXT,
            device_access TEXT,
            updated_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        con.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        # Minimal migration (safe no-op if already exists)
        migrations = [
            ("photo_filename", "ALTER TABLE profiles ADD COLUMN photo_filename TEXT;"),
            ("title", "ALTER TABLE profiles ADD COLUMN title TEXT;"),
            ("full_name", "ALTER TABLE profiles ADD COLUMN full_name TEXT;"),
            ("highest_qualification", "ALTER TABLE profiles ADD COLUMN highest_qualification TEXT;"),
            ("country", "ALTER TABLE profiles ADD COLUMN country TEXT;"),
            ("university", "ALTER TABLE profiles ADD COLUMN university TEXT;"),
            ("school_faculty", "ALTER TABLE profiles ADD COLUMN school_faculty TEXT;"),
            ("position", "ALTER TABLE profiles ADD COLUMN position TEXT;"),
            ("supervisor_name", "ALTER TABLE profiles ADD COLUMN supervisor_name TEXT;"),
            ("bio", "ALTER TABLE profiles ADD COLUMN bio TEXT;"),
            ("skills", "ALTER TABLE profiles ADD COLUMN skills TEXT;"),
            ("device_access", "ALTER TABLE profiles ADD COLUMN device_access TEXT;"),
            ("updated_at", "ALTER TABLE profiles ADD COLUMN updated_at TEXT;"),
        ]
        for col, ddl in migrations:
            if not column_exists(con, "profiles", col):
                con.execute(ddl)

        con.commit()
    finally:
        con.close()


def reset_db():
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()


# -----------------------------
# Auth helpers
# -----------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def current_user_id():
    return session.get("user_id")


def fetch_user(con, user_id: int):
    return con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def fetch_profile(con, user_id: int):
    return con.execute("SELECT * FROM profiles WHERE user_id=?", (user_id,)).fetchone()


def row_to_dict(row):
    # sqlite3.Row has no .get()
    return dict(row) if row is not None else {}


def normalize_text(s: str) -> str:
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip()


def profile_is_complete(profile_row) -> bool:
    p = row_to_dict(profile_row)
    required = [
        "full_name",
        "highest_qualification",
        "country",
        "university",
        "position",
        "bio",
        "skills",
        # device_access intentionally NOT required
    ]
    return all(normalize_text(p.get(k, "")) for k in required)


# -----------------------------
# Upload helpers
# -----------------------------
def allowed_file(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def save_photo(file_storage, user_id: int) -> str:
    if not file_storage or file_storage.filename == "":
        return ""
    filename = secure_filename(file_storage.filename)
    if not filename:
        return ""
    if not allowed_file(filename):
        raise ValueError("Invalid file type. Use PNG/JPG/JPEG/WEBP only.")

    ext = Path(filename).suffix.lower()
    out_name = f"user_{user_id}_{int(datetime.utcnow().timestamp())}{ext}"
    out_path = UPLOAD_DIR / out_name
    file_storage.save(out_path)
    return out_name


# -----------------------------
# Templates (inline)
# -----------------------------
TEMPLATES = {}

TEMPLATES["base.html"] = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{ title or "Collab Finder" }}</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; margin:24px; max-width:1100px}
    a{color:#0b57d0; text-decoration:none}
    a:hover{text-decoration:underline}
    .nav{display:flex; gap:14px; align-items:center; margin-bottom:16px}
    .nav .spacer{flex:1}
    .card{border:1px solid #ddd; border-radius:14px; padding:16px; margin:12px 0}
    .grid{display:grid; grid-template-columns: 1fr 1fr; gap:12px}
    label{display:block; font-weight:600; margin:10px 0 6px}
    input, select, textarea{width:100%; padding:10px; border:1px solid #ccc; border-radius:10px; box-sizing:border-box}
    textarea{min-height:110px}
    .btn{display:inline-block; padding:10px 14px; border-radius:10px; background:#111; color:#fff; border:none; cursor:pointer}
    .btn.secondary{background:#444}
    .muted{color:#666; font-size:0.95rem}
    .flash{padding:10px 12px; border-radius:10px; margin:10px 0}
    .flash.info{background:#eef6ff; border:1px solid #cfe5ff}
    .flash.success{background:#ecfff0; border:1px solid #c9f5d1}
    .flash.warning{background:#fff6e5; border:1px solid #ffe1a8}
    .flash.error{background:#ffecec; border:1px solid #ffc9c9}
    .row{display:flex; gap:12px; align-items:center; flex-wrap:wrap}
    img.avatar{width:96px; height:96px; border-radius:18px; object-fit:cover; border:1px solid #ddd}
    .pill{display:inline-block; padding:4px 10px; border:1px solid #ddd; border-radius:999px; font-size:.9rem; margin-right:6px}
    .hr{height:1px; background:#eee; margin:14px 0}
    .small{font-size:.92rem}
    .radio-row{display:flex; gap:14px; flex-wrap:wrap; margin-top:6px}
    .radio{display:flex; gap:8px; align-items:center; border:1px solid #ddd; padding:8px 10px; border-radius:999px}
    .radio input{width:auto}
    .help{color:#777; font-size:.9rem; margin-top:6px}
    /* Profile card look */
    .vcard{
      border:1px solid #e5e5e5;
      border-radius:18px;
      padding:18px;
      background:linear-gradient(180deg, #fff, #fafafa);
      box-shadow:0 6px 18px rgba(0,0,0,.06);
    }
    .vcard h2{margin:0 0 6px 0}
    .vcard .top{display:flex; gap:14px; align-items:center; flex-wrap:wrap}
    .vcard .meta{display:flex; gap:10px; flex-wrap:wrap; margin-top:6px}
    .vcard .meta .pill{border-color:#e6e6e6}
  </style>
</head>
<body>
  <div class="nav">
    <div><strong><a href="{{ url_for('index') }}">Collab Finder</a></strong></div>
    <div class="spacer"></div>
    {% if session.user_id %}
      <a href="{{ url_for('search') }}">Search</a>
      <a href="{{ url_for('inbox') }}">Inbox</a>
      <a href="{{ url_for('profile_edit') }}">My Profile</a>
      <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
      <a href="{{ url_for('login') }}">Login</a>
      <a href="{{ url_for('register') }}">Register</a>
    {% endif %}
  </div>

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for cat, msg in messages %}
        <div class="flash {{cat}}">{{ msg }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {% block content %}{% endblock %}
</body>
</html>
"""

TEMPLATES["index.html"] = r"""
{% extends "base.html" %}
{% block content %}
  <h1>Collab Finder</h1>
  <p class="muted">Profiles + search + messaging (MVP).</p>

  {% if session.user_id %}
    <div class="card">
      <div class="row">
        <a class="btn" href="{{ url_for('search') }}">Search People</a>
        <a class="btn secondary" href="{{ url_for('profile_card') }}">View My Card</a>
        <a class="btn secondary" href="{{ url_for('profile_edit') }}">Edit My Profile</a>
      </div>
    </div>
  {% else %}
    <div class="card">
      <div class="row">
        <a class="btn" href="{{ url_for('register') }}">Create account</a>
        <a class="btn secondary" href="{{ url_for('login') }}">Log in</a>
      </div>
    </div>
  {% endif %}
{% endblock %}
"""

TEMPLATES["auth.html"] = r"""
{% extends "base.html" %}
{% block content %}
  <h1>{{ heading }}</h1>
  <div class="card">
    <form method="post">
      <label>Email</label>
      <input name="email" type="email" required value="{{ request.form.get('email','') }}">

      <label>Password</label>
      <input name="password" type="password" required>

      <div class="hr"></div>
      <button class="btn" type="submit">{{ button }}</button>
      {% if heading == "Login" %}
        <span class="muted small">or <a href="{{ url_for('register') }}">create account</a></span>
      {% else %}
        <span class="muted small">or <a href="{{ url_for('login') }}">log in</a></span>
      {% endif %}
    </form>
  </div>
{% endblock %}
"""

TEMPLATES["profile_edit.html"] = r"""
{% extends "base.html" %}
{% block content %}
  <h1>Edit Profile</h1>
  <div class="muted small">After saving, you will be taken to your profile card.</div>

  <div class="card">
    <form method="post" enctype="multipart/form-data">

      <!-- Photo -->
      <label>Photo (PNG/JPG/JPEG/WEBP, max {{max_mb}}MB)</label>
      <input type="file" name="photo" accept=".png,.jpg,.jpeg,.webp">
      <div class="help">Optional. If you upload a new one, it replaces your current photo.</div>

      <div class="hr"></div>

      <!-- Title -->
      <label>Title</label>
      <div class="radio-row">
        {% for t in titles %}
          <label class="radio">
            <input type="radio" name="title" value="{{t}}" {% if (profile.title or '')==t %}checked{% endif %}>
            <span>{{t}}</span>
          </label>
        {% endfor %}
      </div>
      <div class="help">Choose one. You can keep it blank if you prefer.</div>

      <!-- Full name -->
      <label>Full name *</label>
      <input name="full_name" value="{{ profile.full_name or '' }}" required>

      <!-- Highest qualification (moved right after name) -->
      <label>Highest qualification *</label>
      <select name="highest_qualification" required>
        <option value="">-- Select --</option>
        {% for q in qualifications %}
          <option value="{{q}}" {% if profile.highest_qualification==q %}selected{% endif %}>{{q}}</option>
        {% endfor %}
      </select>

      <!-- Country (MVP: Australia only) -->
      <label>Country *</label>
      <select name="country" required>
        <option value="">-- Select --</option>
        {% for c in countries %}
          <option value="{{c}}" {% if profile.country==c %}selected{% endif %}>{{c}}</option>
        {% endfor %}
      </select>

      <!-- University / Institution -->
      <label>University / Institution *</label>
      <select name="university" required>
        <option value="">-- Select --</option>
        {% for u in universities %}
          <option value="{{u}}" {% if profile.university==u %}selected{% endif %}>{{u}}</option>
        {% endfor %}
      </select>

      <!-- School/Faculty -->
      <label>School/Faculty</label>
      <input name="school_faculty" value="{{ profile.school_faculty or '' }}" placeholder="e.g., School of Engineering">

      <!-- Position -->
      <label>Position *</label>
      <select id="position" name="position" required>
        <option value="">-- Select --</option>
        {% for p in positions %}
          <option value="{{p}}" {% if profile.position==p %}selected{% endif %}>{{p}}</option>
        {% endfor %}
      </select>

      <!-- Supervisor name (conditional) -->
      <div id="supervisor_wrap" style="display:none;">
        <label>Supervisor name (optional)</label>
        <input name="supervisor_name" value="{{ profile.supervisor_name or '' }}" placeholder="e.g., A/Prof. Jane Doe">
        <div class="help">This appears only when Position is a Student option.</div>
      </div>

      <!-- Bio -->
      <label>Bio *</label>
      <textarea name="bio" required placeholder="What are you working on? What collaboration are you looking for?">{{ profile.bio or '' }}</textarea>

      <!-- Skills -->
      <label>Skills *</label>
      <textarea name="skills" required placeholder="Examples: software (SolidWorks, ANSYS), wet lab (GelMA), characterization (XPS), programming (Python), etc.">{{ profile.skills or '' }}</textarea>
      <div class="help">Tip: use commas or short lines for readability.</div>

      <!-- Device access (optional now) -->
      <label>Device access (optional)</label>
      <textarea name="device_access" placeholder="If relevant: instruments/devices you can access (e.g., XPS, SEM, plasma jet, bioprinter). Leave blank if not applicable.">{{ profile.device_access or '' }}</textarea>

      <div class="hr"></div>
      <button class="btn" type="submit">Save profile</button>
      <a class="btn secondary" href="{{ url_for('profile_card') }}">Cancel (view card)</a>
    </form>
  </div>

  <script>
    function isStudentPosition(val){
      if(!val) return false;
      return val.toLowerCase().includes("student");
    }
    function toggleSupervisor(){
      const pos = document.getElementById("position");
      const wrap = document.getElementById("supervisor_wrap");
      if(isStudentPosition(pos.value)){
        wrap.style.display = "block";
      } else {
        wrap.style.display = "none";
      }
    }
    document.getElementById("position").addEventListener("change", toggleSupervisor);
    toggleSupervisor();
  </script>
{% endblock %}
"""

TEMPLATES["profile_card.html"] = r"""
{% extends "base.html" %}
{% block content %}
  <h1>My Profile Card</h1>

  <div class="vcard">
    <div class="top">
      <div>
        {% if profile.photo_filename %}
          <img class="avatar" src="{{ url_for('uploaded_file', filename=profile.photo_filename) }}" alt="avatar">
        {% else %}
          <img class="avatar" src="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='96' height='96'><rect width='100%25' height='100%25' fill='%23eee'/><text x='50%25' y='54%25' text-anchor='middle' fill='%23999' font-family='Arial' font-size='14'>No Photo</text></svg>">
        {% endif %}
      </div>

      <div style="flex:1">
        <h2>
          {% if profile.title %}{{ profile.title }} {% endif %}
          {{ profile.full_name or "(name not set)" }}
        </h2>

        <div class="muted">
          {{ profile.position or "" }}
          {% if profile.highest_qualification %} · {{ profile.highest_qualification }}{% endif %}
        </div>

        <div class="muted small">
          {% if profile.country %}{{ profile.country }}{% endif %}
          {% if profile.university %}{% if profile.country %} · {% endif %}{{ profile.university }}{% endif %}
          {% if profile.school_faculty %} · {{ profile.school_faculty }}{% endif %}
        </div>

        {% if profile.supervisor_name %}
          <div class="muted small">Supervisor: {{ profile.supervisor_name }}</div>
        {% endif %}

        <div class="meta">
          {% if is_complete %}
            <span class="pill">Profile complete</span>
          {% else %}
            <span class="pill">Profile incomplete</span>
          {% endif %}
          {% if profile.updated_at %}
            <span class="pill">Updated {{ profile.updated_at }}</span>
          {% endif %}
        </div>

        <div class="hr"></div>

        <div><strong>Bio</strong></div>
        <div class="small">{{ profile.bio or "" }}</div>

        <div class="hr"></div>

        <div class="small"><strong>Skills:</strong> {{ profile.skills or "" }}</div>
        {% if profile.device_access %}
          <div class="small"><strong>Device access:</strong> {{ profile.device_access }}</div>
        {% endif %}
      </div>
    </div>

    <div class="hr"></div>
    <div class="row">
      <a class="btn" href="{{ url_for('profile_edit') }}">Edit my profile</a>
      <a class="btn secondary" href="{{ url_for('search') }}">Search people</a>
      <a class="btn secondary" href="{{ url_for('inbox') }}">Inbox</a>
    </div>
  </div>
{% endblock %}
"""

TEMPLATES["search.html"] = r"""
{% extends "base.html" %}
{% block content %}
  <h1>Search</h1>

  <div style="display:grid; grid-template-columns: 1fr 320px; gap:14px; align-items:start;">
    <!-- LEFT: main search -->
    <div>
      <div class="card">
        <form method="get" class="row">
          <div style="flex:1; min-width:260px">
            <label>Keyword</label>
            <input name="q" value="{{ request.args.get('q','') }}" placeholder="e.g., hydrogel, plasma, XPS, bioprinting">
            <div class="help">Matches name/title/bio/skills/device access.</div>
          </div>

          <div style="flex:1; min-width:260px">
            <label>University</label>
            <select name="university">
              <option value="">-- Any --</option>
              {% for u in universities %}
                <option value="{{u}}" {% if request.args.get('university')==u %}selected{% endif %}>{{u}}</option>
              {% endfor %}
            </select>
          </div>

          <div style="flex:1; min-width:260px">
            <label>Position</label>
            <select name="position">
              <option value="">-- Any --</option>
              {% for p in positions %}
                <option value="{{p}}" {% if request.args.get('position')==p %}selected{% endif %}>{{p}}</option>
              {% endfor %}
            </select>
          </div>

          <div style="align-self:end">
            <button class="btn" type="submit" name="do" value="1">Search</button>
          </div>
        </form>
      </div>

      {% if not did_search %}
        <div class="card">
          <div class="muted">No results shown yet.</div>
          <div class="small">Enter a keyword or choose filters, then click <strong>Search</strong>.</div>
        </div>
      {% else %}
        <div class="muted small">Found {{ results|length }} result(s).</div>

        {% for r in results %}
          <div class="card">
            <div class="row">
              <div>
                {% if r.photo_filename %}
                  <img class="avatar" src="{{ url_for('uploaded_file', filename=r.photo_filename) }}" alt="avatar">
                {% else %}
                  <img class="avatar" src="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='96' height='96'><rect width='100%25' height='100%25' fill='%23eee'/><text x='50%25' y='54%25' text-anchor='middle' fill='%23999' font-family='Arial' font-size='14'>No Photo</text></svg>">
                {% endif %}
              </div>
              <div style="flex:1">
                <div>
                  <strong><a href="{{ url_for('view_profile', user_id=r.user_id) }}">
                    {% if r.title %}{{ r.title }} {% endif %}{{ r.full_name or "(no name)" }}
                  </a></strong>
                </div>
                <div class="muted">{{ r.position or "" }}{% if r.highest_qualification %} · {{ r.highest_qualification }}{% endif %}</div>
                <div class="muted small">
                  {{ r.country or "" }}{% if r.country and r.university %} · {% endif %}{{ r.university or "" }}
                  {% if r.school_faculty %} · {{ r.school_faculty }}{% endif %}
                </div>
                {% if r.supervisor_name %}
                  <div class="muted small">Supervisor: {{ r.supervisor_name }}</div>
                {% endif %}
                <div class="hr"></div>
                <div class="small"><strong>Skills:</strong> {{ r.skills or "" }}</div>
                {% if r.device_access %}
                  <div class="small"><strong>Device access:</strong> {{ r.device_access }}</div>
                {% endif %}
              </div>
              <div>
                <a class="btn secondary" href="{{ url_for('view_profile', user_id=r.user_id) }}">View</a>
              </div>
            </div>
          </div>
        {% endfor %}
      {% endif %}
    </div>

    <!-- RIGHT: future AI helper (visual only) -->
    <div class="card" style="position:sticky; top:16px;">
      <div style="font-weight:800; margin-bottom:6px;">AI Helper (Coming soon)</div>
      <div class="muted small" style="margin-bottom:10px;">
        Soon you can live-search any unfamiliar skill or device directly inside the app.
        For example, if you see a skill you don’t recognize, you can ask here and get a quick explanation.
      </div>
      <label>Ask about a skill/device</label>
      <input disabled placeholder="e.g., What is XPS? (coming soon)">
      <div class="help">This box is visual only for now.</div>
      <div class="hr"></div>
      <button class="btn secondary" type="button" disabled style="width:100%;">Search (coming soon)</button>
    </div>
  </div>
{% endblock %}
"""

TEMPLATES["view_profile.html"] = r"""
{% extends "base.html" %}
{% block content %}
  <h1>Profile</h1>

  <div class="card">
    <div class="row">
      <div>
        {% if profile.photo_filename %}
          <img class="avatar" src="{{ url_for('uploaded_file', filename=profile.photo_filename) }}" alt="avatar">
        {% else %}
          <img class="avatar" src="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='96' height='96'><rect width='100%25' height='100%25' fill='%23eee'/><text x='50%25' y='54%25' text-anchor='middle' fill='%23999' font-family='Arial' font-size='14'>No Photo</text></svg>">
        {% endif %}
      </div>
      <div style="flex:1">
        <div><strong>{% if profile.title %}{{ profile.title }} {% endif %}{{ profile.full_name or "(no name)" }}</strong></div>
        <div class="muted">{{ profile.position or "" }}{% if profile.highest_qualification %} · {{ profile.highest_qualification }}{% endif %}</div>
        <div class="muted small">
          {{ profile.country or "" }}{% if profile.country and profile.university %} · {% endif %}{{ profile.university or "" }}
          {% if profile.school_faculty %} · {{ profile.school_faculty }}{% endif %}
        </div>
        {% if profile.supervisor_name %}
          <div class="muted small">Supervisor: {{ profile.supervisor_name }}</div>
        {% endif %}
        <div class="hr"></div>
        <div><strong>Bio</strong></div>
        <div class="small">{{ profile.bio or "" }}</div>
        <div class="hr"></div>
        <div class="small"><strong>Skills:</strong> {{ profile.skills or "" }}</div>
        {% if profile.device_access %}
          <div class="small"><strong>Device access:</strong> {{ profile.device_access }}</div>
        {% endif %}
      </div>
    </div>
  </div>

  {% if can_message %}
    <div class="card">
      <h3>Send a message</h3>
      <form method="post" action="{{ url_for('send_message', user_id=profile.user_id) }}">
        <label>Message</label>
        <textarea name="body" required placeholder="Write a message..."></textarea>
        <div class="hr"></div>
        <button class="btn" type="submit">Send</button>
        <a class="btn secondary" href="{{ url_for('thread', user_id=profile.user_id) }}">Open thread</a>
      </form>
    </div>
  {% endif %}
{% endblock %}
"""

TEMPLATES["inbox.html"] = r"""
{% extends "base.html" %}
{% block content %}
  <h1>Inbox</h1>
  <div class="muted small">Your recent conversations.</div>

  {% if threads|length == 0 %}
    <div class="card">
      No messages yet. Go to <a href="{{ url_for('search') }}">Search</a> and message someone.
    </div>
  {% endif %}

  {% for t in threads %}
    <div class="card">
      <div class="row">
        <div style="flex:1">
          <div><strong><a href="{{ url_for('thread', user_id=t.other_id) }}">{{ t.other_name }}</a></strong></div>
          <div class="muted small">{{ t.last_time }}</div>
          <div>{{ t.last_body }}</div>
        </div>
        <div>
          <a class="btn secondary" href="{{ url_for('thread', user_id=t.other_id) }}">Open</a>
        </div>
      </div>
    </div>
  {% endfor %}
{% endblock %}
"""

TEMPLATES["thread.html"] = r"""
{% extends "base.html" %}
{% block content %}
  <h1>Thread with {{ other_name }}</h1>

  <div class="card">
    {% for m in messages %}
      <div style="margin-bottom:10px">
        <div class="muted small">{{ m.created_at }} · {% if m.sender_id == me %}You{% else %}{{ other_name }}{% endif %}</div>
        <div>{{ m.body }}</div>
      </div>
      <div class="hr"></div>
    {% endfor %}

    {% if messages|length == 0 %}
      <div class="muted">No messages yet.</div>
      <div class="hr"></div>
    {% endif %}

    <form method="post" action="{{ url_for('send_message', user_id=other_id) }}">
      <label>New message</label>
      <textarea name="body" required></textarea>
      <div class="hr"></div>
      <button class="btn" type="submit">Send</button>
      <a class="btn secondary" href="{{ url_for('view_profile', user_id=other_id) }}">View profile</a>
    </form>
  </div>
{% endblock %}
"""

app.jinja_loader = DictLoader(TEMPLATES)


# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return app.jinja_env.get_template("index.html").render(title="Home")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = normalize_text(request.form.get("email", "")).lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("register"))

        con = get_db()
        try:
            existing = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if existing:
                flash("Email already registered. Please log in.", "warning")
                return redirect(url_for("login"))

            pw_hash = generate_password_hash(password)
            now = datetime.utcnow().isoformat(timespec="seconds")
            cur = con.execute(
                "INSERT INTO users(email, password_hash, created_at) VALUES (?,?,?)",
                (email, pw_hash, now),
            )
            user_id = cur.lastrowid

            # Create empty profile row
            con.execute(
                "INSERT INTO profiles(user_id, updated_at) VALUES (?,?)",
                (user_id, now),
            )
            con.commit()

            session["user_id"] = user_id
            flash("Account created. Please complete your profile.", "success")
            return redirect(url_for("profile_edit"))
        finally:
            con.close()

    return app.jinja_env.get_template("auth.html").render(
        heading="Register",
        button="Create account",
        title="Register",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = normalize_text(request.form.get("email", "")).lower()
        password = request.form.get("password", "")

        con = get_db()
        try:
            user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if not user or not check_password_hash(user["password_hash"], password):
                flash("Invalid email or password.", "error")
                return redirect(url_for("login"))

            session["user_id"] = user["id"]
            flash("Logged in.", "success")
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        finally:
            con.close()

    return app.jinja_env.get_template("auth.html").render(
        heading="Login",
        button="Log in",
        title="Login",
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    uid = current_user_id()
    con = get_db()
    try:
        prof = fetch_profile(con, uid)
        if prof is None:
            now = datetime.utcnow().isoformat(timespec="seconds")
            con.execute("INSERT INTO profiles(user_id, updated_at) VALUES (?,?)", (uid, now))
            con.commit()
            prof = fetch_profile(con, uid)

        if request.method == "POST":
            # Photo upload
            photo = request.files.get("photo")
            photo_filename = None
            if photo and photo.filename:
                try:
                    fn = save_photo(photo, uid)
                    if fn:
                        photo_filename = fn
                except ValueError as e:
                    flash(str(e), "error")
                    return redirect(url_for("profile_edit"))

            title = normalize_text(request.form.get("title", ""))
            full_name = normalize_text(request.form.get("full_name", ""))
            highest_qualification = normalize_text(request.form.get("highest_qualification", ""))
            country = normalize_text(request.form.get("country", ""))
            university = normalize_text(request.form.get("university", ""))
            school_faculty = normalize_text(request.form.get("school_faculty", ""))
            position = normalize_text(request.form.get("position", ""))
            supervisor_name = normalize_text(request.form.get("supervisor_name", ""))
            bio = normalize_text(request.form.get("bio", ""))
            skills = normalize_text(request.form.get("skills", ""))
            device_access = normalize_text(request.form.get("device_access", ""))  # optional
            updated_at = datetime.utcnow().isoformat(timespec="seconds")

            # Basic validation (device_access not required)
            if not (full_name and highest_qualification and country and university and position and bio and skills):
                flash("Please fill all required fields (device access is optional).", "warning")
                return redirect(url_for("profile_edit"))

            # If position is not a Student type, clear supervisor_name (or keep? we'll clear to avoid stale)
            if "student" not in position.lower():
                supervisor_name = ""

            con.execute(
                """
                UPDATE profiles SET
                    photo_filename = COALESCE(?, photo_filename),
                    title=?,
                    full_name=?,
                    highest_qualification=?,
                    country=?,
                    university=?,
                    school_faculty=?,
                    position=?,
                    supervisor_name=?,
                    bio=?,
                    skills=?,
                    device_access=?,
                    updated_at=?
                WHERE user_id=?
                """,
                (
                    photo_filename,
                    title,
                    full_name,
                    highest_qualification,
                    country,
                    university,
                    school_faculty,
                    position,
                    supervisor_name,
                    bio,
                    skills,
                    device_access,
                    updated_at,
                    uid,
                ),
            )
            con.commit()
            flash("Profile saved.", "success")
            return redirect(url_for("profile_card"))

        prof = fetch_profile(con, uid)
        return app.jinja_env.get_template("profile_edit.html").render(
            title="Edit Profile",
            profile=prof,
            universities=AU_UNIVERSITIES,
            qualifications=QUALIFICATIONS,
            positions=POSITIONS,
            countries=COUNTRIES,
            titles=TITLES,
            max_mb=MAX_UPLOAD_MB,
        )
    finally:
        con.close()


@app.route("/profile")
@login_required
def profile_card():
    uid = current_user_id()
    con = get_db()
    try:
        prof = fetch_profile(con, uid)
        if not prof:
            return redirect(url_for("profile_edit"))
        complete = profile_is_complete(prof)
        return app.jinja_env.get_template("profile_card.html").render(
            title="My Profile Card",
            profile=prof,
            is_complete=complete,
        )
    finally:
        con.close()


@app.route("/search")
@login_required
def search():
    uid = current_user_id()

    did_search = request.args.get("do") == "1"
    q = normalize_text(request.args.get("q", ""))
    university = normalize_text(request.args.get("university", ""))
    position = normalize_text(request.args.get("position", ""))

    results = []
    if did_search:
        like = f"%{q}%"
        con = get_db()
        try:
            sql = """
            SELECT p.*, p.user_id
            FROM profiles p
            WHERE p.user_id != ?
            """
            params = [uid]

            if university:
                sql += " AND p.university = ?"
                params.append(university)

            if position:
                sql += " AND p.position = ?"
                params.append(position)

            if q:
                sql += """
                AND (
                  p.full_name LIKE ?
                  OR p.title LIKE ?
                  OR p.bio LIKE ?
                  OR p.skills LIKE ?
                  OR p.device_access LIKE ?
                  OR p.school_faculty LIKE ?
                  OR p.supervisor_name LIKE ?
                )
                """
                params.extend([like, like, like, like, like, like, like])

            sql += """
            ORDER BY p.updated_at DESC
            LIMIT 200
            """
            results = con.execute(sql, tuple(params)).fetchall()
        finally:
            con.close()

    return app.jinja_env.get_template("search.html").render(
        title="Search",
        did_search=did_search,
        results=results,
        universities=AU_UNIVERSITIES,
        positions=POSITIONS,
    )


@app.route("/u/<int:user_id>")
@login_required
def view_profile(user_id):
    uid = current_user_id()
    con = get_db()
    try:
        prof = fetch_profile(con, user_id)
        if not prof:
            abort(404)
        can_message = (uid != user_id)
        return app.jinja_env.get_template("view_profile.html").render(
            title="Profile",
            profile=prof,
            can_message=can_message,
        )
    finally:
        con.close()


@app.route("/message/send/<int:user_id>", methods=["POST"])
@login_required
def send_message(user_id):
    uid = current_user_id()
    if uid == user_id:
        flash("You cannot message yourself.", "warning")
        return redirect(url_for("view_profile", user_id=user_id))

    body = normalize_text(request.form.get("body", ""))
    if not body:
        flash("Message body cannot be empty.", "error")
        return redirect(url_for("view_profile", user_id=user_id))

    con = get_db()
    try:
        if not fetch_user(con, user_id):
            abort(404)

        now = datetime.utcnow().isoformat(timespec="seconds")
        con.execute(
            "INSERT INTO messages(sender_id, receiver_id, body, created_at) VALUES (?,?,?,?)",
            (uid, user_id, body, now),
        )
        con.commit()
        flash("Message sent.", "success")
        return redirect(url_for("thread", user_id=user_id))
    finally:
        con.close()


@app.route("/inbox")
@login_required
def inbox():
    uid = current_user_id()
    con = get_db()
    try:
        rows = con.execute(
            """
            SELECT
              CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END AS other_id,
              MAX(m.id) AS last_msg_id
            FROM messages m
            WHERE m.sender_id = ? OR m.receiver_id = ?
            GROUP BY other_id
            ORDER BY last_msg_id DESC
            """,
            (uid, uid, uid),
        ).fetchall()

        threads = []
        for r in rows:
            other_id = r["other_id"]
            last_msg = con.execute("SELECT * FROM messages WHERE id=?", (r["last_msg_id"],)).fetchone()
            other_prof = fetch_profile(con, other_id)
            other_name = (other_prof["full_name"] if other_prof and other_prof["full_name"] else f"User {other_id}")

            threads.append({
                "other_id": other_id,
                "other_name": other_name,
                "last_time": last_msg["created_at"] if last_msg else "",
                "last_body": (last_msg["body"] if last_msg else ""),
            })

        return app.jinja_env.get_template("inbox.html").render(
            title="Inbox",
            threads=threads,
        )
    finally:
        con.close()


@app.route("/thread/<int:user_id>")
@login_required
def thread(user_id):
    uid = current_user_id()
    if uid == user_id:
        flash("No thread with yourself.", "warning")
        return redirect(url_for("inbox"))

    con = get_db()
    try:
        other_prof = fetch_profile(con, user_id)
        if not other_prof:
            abort(404)

        other_name = other_prof["full_name"] if other_prof["full_name"] else f"User {user_id}"

        msgs = con.execute(
            """
            SELECT * FROM messages
            WHERE (sender_id=? AND receiver_id=?)
               OR (sender_id=? AND receiver_id=?)
            ORDER BY id ASC
            LIMIT 500
            """,
            (uid, user_id, user_id, uid),
        ).fetchall()

        con.execute(
            """
            UPDATE messages SET is_read=1
            WHERE receiver_id=? AND sender_id=? AND is_read=0
            """,
            (uid, user_id),
        )
        con.commit()

        return app.jinja_env.get_template("thread.html").render(
            title="Thread",
            messages=msgs,
            other_id=user_id,
            other_name=other_name,
            me=uid,
        )
    finally:
        con.close()

ensure_schema()
# -----------------------------
# CLI entry
# -----------------------------
if __name__ == "__main__":
    import sys
    if "--reset-db" in sys.argv:
        reset_db()
        print("Database reset complete: collab.db recreated.")
    else:
        init_db()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
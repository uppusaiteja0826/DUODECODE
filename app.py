
import os
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from sqlalchemy import or_

load_dotenv()

app = Flask(__name__)

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-secret-key")

database_url = os.getenv("DATABASE_URL", "")

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://", "postgresql://", 1
    )

if database_url.startswith("postgresql://"):
    database_url = database_url.replace(
        "postgresql://", "postgresql+psycopg2://", 1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300
}

# Email configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

db = SQLAlchemy(app)
mail = Mail(app)


# --------------------------------------------------
# DATABASE MODELS
# --------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class OTPChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    purpose = db.Column(db.String(30), nullable=False)
    code_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    used = db.Column(db.Boolean, default=False)


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"),
        unique=True, nullable=False
    )
    role = db.Column(db.String(30), default="student")
    college = db.Column(db.String(150))
    course = db.Column(db.String(100))
    year = db.Column(db.String(30))
    bio = db.Column(db.Text)
    known_topics = db.Column(db.Text)
    learning_topics = db.Column(db.Text)

    user = db.relationship(
        "User", backref=db.backref("profile", uselist=False)
    )


class ConnectionRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    receiver_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    status = db.Column(db.String(30), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship(
        "User", foreign_keys=[sender_id]
    )
    receiver = db.relationship(
        "User", foreign_keys=[receiver_id]
    )


# --------------------------------------------------
# LOGIN PROTECTION
# --------------------------------------------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "warning")
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


# --------------------------------------------------
# OTP FUNCTIONS
# --------------------------------------------------

def create_otp(email, purpose):
    OTPChallenge.query.filter_by(
        email=email, purpose=purpose, used=False
    ).update({"used": True})

    code = str(secrets.randbelow(900000) + 100000)

    challenge = OTPChallenge(
        email=email,
        purpose=purpose,
        code_hash=generate_password_hash(code),
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )

    db.session.add(challenge)
    db.session.commit()

    message = Message(
        subject="DUODECODE Verification Code",
        recipients=[email],
        body=f"Your DUODECODE verification code is {code}. "
             "It expires in 5 minutes."
    )

    mail.send(message)


def verify_otp(email, purpose, code):
    challenge = OTPChallenge.query.filter_by(
        email=email,
        purpose=purpose,
        used=False
    ).order_by(OTPChallenge.id.desc()).first()

    if not challenge:
        return False

    if challenge.expires_at < datetime.utcnow():
        return False

    if challenge.attempts >= 5:
        return False

    challenge.attempts += 1

    if check_password_hash(challenge.code_hash, code):
        challenge.used = True
        db.session.commit()
        return True

    db.session.commit()
    return False


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password:
            flash("Please fill all required fields.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return redirect(url_for("register"))

        existing = User.query.filter_by(email=email).first()

        if existing:
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        user = User(
            name=name,
            email=email,
            password=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        session["pending_email"] = email

        try:
            create_otp(email, "register")
        except Exception:
            db.session.delete(user)
            db.session.commit()
            flash("Unable to send verification email. Try again.", "danger")
            return redirect(url_for("register"))

        return redirect(url_for("verify_email"))

    return render_template("register.html")


# --------------------------------------------------
# VERIFY REGISTRATION EMAIL
# --------------------------------------------------

@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():

    email = session.get("pending_email")

    if not email:
        return redirect(url_for("register"))

    if request.method == "POST":

        code = request.form.get("otp", "").strip()

        if verify_otp(email, "register", code):

            user = User.query.filter_by(email=email).first()

            if user:
                user.verified = True

                if not user.profile:
                    db.session.add(Profile(user_id=user.id))

                db.session.commit()

            session.pop("pending_email", None)

            flash("Account verified successfully. Please login.", "success")
            return redirect(url_for("login"))

        flash("Invalid or expired OTP.", "danger")

    return render_template("verify_email.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):

            if not user.verified:
                flash("Please verify your email first.", "warning")
                session["pending_email"] = email
                return redirect(url_for("verify_email"))

            session["login_email"] = email

            try:
                create_otp(email, "login")
            except Exception:
                flash("Unable to send login OTP.", "danger")
                return redirect(url_for("login"))

            return redirect(url_for("verify_login"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


# --------------------------------------------------
# VERIFY LOGIN OTP
# --------------------------------------------------

@app.route("/verify-login", methods=["GET", "POST"])
def verify_login():

    email = session.get("login_email")

    if not email:
        return redirect(url_for("login"))

    if request.method == "POST":

        code = request.form.get("otp", "").strip()

        if verify_otp(email, "login", code):

            user = User.query.filter_by(email=email).first()

            if user:
                session["user_id"] = user.id
                session.pop("login_email", None)

                return redirect(url_for("dashboard"))

        flash("Invalid or expired OTP.", "danger")

    return render_template("verify_login.html")


# --------------------------------------------------
# FORGOT PASSWORD
# --------------------------------------------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()

        if user:
            try:
                create_otp(email, "reset")
                session["reset_email"] = email
                return redirect(url_for("verify_reset"))
            except Exception:
                flash("Unable to send OTP.", "danger")

        else:
            flash("If the account exists, a reset code can be sent.", "info")

    return render_template("forgot_password.html")


# --------------------------------------------------
# VERIFY RESET OTP
# --------------------------------------------------

@app.route("/verify-reset", methods=["GET", "POST"])
def verify_reset():

    email = session.get("reset_email")

    if not email:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        code = request.form.get("otp", "").strip()

        if verify_otp(email, "reset", code):
            session["reset_verified"] = True
            return redirect(url_for("reset_password"))

        flash("Invalid or expired OTP.", "danger")

    return render_template("verify_reset.html")


# --------------------------------------------------
# RESET PASSWORD
# --------------------------------------------------

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    if not session.get("reset_verified"):
        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")

        elif password != confirm_password:
            flash("Passwords do not match.", "danger")

        else:

            email = session.get("reset_email")
            user = User.query.filter_by(email=email).first()

            if user:
                user.password = generate_password_hash(password)
                db.session.commit()

            session.pop("reset_email", None)
            session.pop("reset_verified", None)

            flash("Password updated successfully.", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    user = db.session.get(User, session["user_id"])

    if not user:
        session.clear()
        return redirect(url_for("login"))

    profile = user.profile

    return render_template(
        "dashboard.html",
        user=user,
        profile=profile
    )


# --------------------------------------------------
# PROFILE
# --------------------------------------------------

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():

    user = db.session.get(User, session["user_id"])

    if not user:
        return redirect(url_for("login"))

    profile = user.profile

    if not profile:
        profile = Profile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()

    if request.method == "POST":

        profile.role = request.form.get("role", "student")
        profile.college = request.form.get("college", "")
        profile.course = request.form.get("course", "")
        profile.year = request.form.get("year", "")
        profile.bio = request.form.get("bio", "")
        profile.known_topics = request.form.get("known_topics", "")
        profile.learning_topics = request.form.get("learning_topics", "")

        db.session.commit()

        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))

    return render_template(
        "profile.html",
        user=user,
        profile=profile
    )


# --------------------------------------------------
# MATCHING STUDENTS
# --------------------------------------------------

@app.route("/matches")
@login_required
def matches():

    current_id = session["user_id"]
    current_user = db.session.get(User, current_id)

    if not current_user or not current_user.profile:
        return redirect(url_for("profile"))

    my_profile = current_user.profile

    other_profiles = Profile.query.filter(
        Profile.user_id != current_id
    ).all()

    matched_users = []

    learning = (my_profile.learning_topics or "").lower()

    for profile in other_profiles:

        known = (profile.known_topics or "").lower()

        if learning and any(
            topic.strip() and topic.strip() in known
            for topic in learning.split(",")
        ):
            matched_users.append(profile.user)

    return render_template(
        "matches.html",
        users=matched_users
    )


# --------------------------------------------------
# SEND CONNECTION REQUEST
# --------------------------------------------------

@app.route("/send-request/<int:receiver_id>", methods=["POST"])
@login_required
def send_request(receiver_id):

    sender_id = session["user_id"]

    if sender_id == receiver_id:
        flash("You cannot send a request to yourself.", "danger")
        return redirect(url_for("matches"))

    receiver = db.session.get(User, receiver_id)

    if not receiver:
        flash("User not found.", "danger")
        return redirect(url_for("matches"))

    existing = ConnectionRequest.query.filter(
        or_(
            (
                (ConnectionRequest.sender_id == sender_id) &
                (ConnectionRequest.receiver_id == receiver_id)
            ),
            (
                (ConnectionRequest.sender_id == receiver_id) &
                (ConnectionRequest.receiver_id == sender_id)
            )
        )
    ).first()

    if existing:
        flash("A connection request already exists.", "info")
    else:
        connection = ConnectionRequest(
            sender_id=sender_id,
            receiver_id=receiver_id
        )

        db.session.add(connection)
        db.session.commit()

        flash("Connection request sent.", "success")

    return redirect(url_for("matches"))


# --------------------------------------------------
# VIEW CONNECTION REQUESTS
# --------------------------------------------------

@app.route("/requests")
@login_required
def requests():

    user_id = session["user_id"]

    received = ConnectionRequest.query.filter_by(
        receiver_id=user_id
    ).all()

    sent = ConnectionRequest.query.filter_by(
        sender_id=user_id
    ).all()

    return render_template(
        "requests.html",
        received=received,
        sent=sent
    )


# --------------------------------------------------
# ACCEPT OR REJECT REQUEST
# --------------------------------------------------

@app.route("/respond-request/<int:request_id>", methods=["POST"])
@login_required
def respond_request(request_id):

    connection = db.session.get(ConnectionRequest, request_id)

    if not connection:
        flash("Request not found.", "danger")
        return redirect(url_for("requests"))

    if connection.receiver_id != session["user_id"]:
        flash("You cannot modify this request.", "danger")
        return redirect(url_for("requests"))

    action = request.form.get("action")

    if connection.status != "pending":
        flash("This request has already been handled.", "info")

    elif action == "accept":
        connection.status = "accepted"
        db.session.commit()
        flash("Connection accepted.", "success")

    elif action == "reject":
        connection.status = "rejected"
        db.session.commit()
        flash("Connection rejected.", "info")

    return redirect(url_for("requests"))


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/health")
def health():

    try:
        db.session.execute(db.text("SELECT 1"))

        return jsonify({
            "status": "healthy",
            "database": "connected"
        }), 200

    except Exception:
        db.session.rollback()

        return jsonify({
            "status": "unhealthy",
            "database": "disconnected"
        }), 500


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

with app.app_context():
    db.create_all()


# --------------------------------------------------
# APPLICATION START
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )

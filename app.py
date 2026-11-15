
import os
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY", "development-only-change-this"
)

database_url = os.getenv("DATABASE_URL", "sqlite:///duodecode.db")

# Render PostgreSQL compatibility: explicitly use psycopg2
if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://", "postgresql+psycopg2://", 1
    )
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace(
        "postgresql://", "postgresql+psycopg2://", 1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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


class OTPChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    purpose = db.Column(db.String(30), nullable=False)
    code_hash = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    used = db.Column(db.Boolean, default=False)


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        unique=True,
        nullable=False
    )

    role = db.Column(db.String(30), nullable=False)
    known_topics = db.Column(db.Text, default="")
    learning_topics = db.Column(db.Text, default="")
    bio = db.Column(db.Text, default="")

    user = db.relationship(
        "User",
        backref=db.backref("profile", uselist=False)
    )


class ConnectionRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    sender_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    receiver_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    message = db.Column(db.Text, default="")
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship(
        "User",
        foreign_keys=[sender_id]
    )

    receiver = db.relationship(
        "User",
        foreign_keys=[receiver_id]
    )


# --------------------------------------------------
# LOGIN REQUIRED DECORATOR
# --------------------------------------------------

def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))

        return route_function(*args, **kwargs)

    return wrapper


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def split_topics(topic_text):
    """Convert comma-separated topics into a list."""

    if not topic_text:
        return []

    return [
        topic.strip().lower()
        for topic in topic_text.split(",")
        if topic.strip()
    ]


def hash_otp(code):
    secret = app.config["SECRET_KEY"]

    return hmac.new(
        secret.encode(),
        code.encode(),
        hashlib.sha256
    ).hexdigest()


# --------------------------------------------------
# OTP FUNCTIONS
# --------------------------------------------------

def send_otp(email, purpose):

    # Invalidate previous unused OTPs
    OTPChallenge.query.filter_by(
        email=email,
        purpose=purpose,
        used=False
    ).update({"used": True})

    code = f"{secrets.randbelow(1000000):06d}"

    challenge = OTPChallenge(
        email=email,
        purpose=purpose,
        code_hash=hash_otp(code),
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )

    db.session.add(challenge)
    db.session.commit()

    try:
        message = Message(
            subject="DUODECODE - Verification OTP",
            recipients=[email],
            body=f"""
Hello!

Your DUODECODE verification code is:

{code}

This OTP expires in 5 minutes.

If you did not request this code, please ignore this email.

DUODECODE Team
"""
        )

        mail.send(message)
        return True

    except Exception as error:
        app.logger.error("Email delivery failed: %s", error)
        return False


def verify_otp(email, purpose, code):

    challenge = OTPChallenge.query.filter_by(
        email=email,
        purpose=purpose,
        used=False
    ).order_by(OTPChallenge.id.desc()).first()

    if not challenge:
        return False, "No active OTP found."

    if datetime.utcnow() > challenge.expires_at:
        challenge.used = True
        db.session.commit()
        return False, "OTP expired. Request a new one."

    if challenge.attempts >= 5:
        challenge.used = True
        db.session.commit()
        return False, "Too many attempts. Request a new OTP."

    if not hmac.compare_digest(
        challenge.code_hash,
        hash_otp(code)
    ):
        challenge.attempts += 1
        db.session.commit()
        return False, "Incorrect OTP."

    challenge.used = True
    db.session.commit()

    return True, "OTP verified successfully."


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# USER REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password:
            flash("Please fill in all required fields.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        user = User.query.filter_by(email=email).first()

        if user and user.verified:
            flash("This email is already registered.")
            return redirect(url_for("register"))

        if not user:
            user = User(
                name=name,
                email=email,
                password=generate_password_hash(password)
            )
            db.session.add(user)

        else:
            user.name = name
            user.password = generate_password_hash(password)

        db.session.commit()

        if send_otp(email, "register"):

            session.clear()
            session["pending_email"] = email

            flash("OTP sent to your email.")
            return redirect(url_for("verify_email"))

        flash("Email could not be sent. Check email configuration.")
        return redirect(url_for("register"))

    return render_template("register.html")


# --------------------------------------------------
# EMAIL VERIFICATION
# --------------------------------------------------

@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():

    if "pending_email" not in session:
        return redirect(url_for("register"))

    if request.method == "POST":

        code = request.form.get("otp", "").strip()
        email = session["pending_email"]

        success, message = verify_otp(
            email, "register", code
        )

        if success:

            user = User.query.filter_by(email=email).first()

            if user:
                user.verified = True
                db.session.commit()

            session.pop("pending_email", None)

            flash("Email verified! You can now log in.")
            return redirect(url_for("login"))

        flash(message)

    return render_template("verify_otp.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(
            user.password, password
        ):
            flash("Incorrect email or password.")
            return redirect(url_for("login"))

        if not user.verified:

            session.clear()
            session["pending_email"] = email

            flash("Please verify your email first.")
            return redirect(url_for("verify_email"))

        if send_otp(email, "login"):

            session.clear()
            session["pending_login"] = email

            flash("Login OTP sent to your email.")
            return redirect(url_for("verify_login"))

        flash("Could not send OTP. Please try again.")

    return render_template("login.html")


# --------------------------------------------------
# LOGIN OTP VERIFICATION
# --------------------------------------------------

@app.route("/verify-login", methods=["GET", "POST"])
def verify_login():

    if "pending_login" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        email = session["pending_login"]
        code = request.form.get("otp", "").strip()

        success, message = verify_otp(
            email, "login", code
        )

        if success:

            user = User.query.filter_by(email=email).first()

            if user and user.verified:

                session.clear()
                session["user_id"] = user.id
                session["user_name"] = user.name

                flash("Login successful!")
                return redirect(url_for("dashboard"))

            flash("Account not found or not verified.")

        else:
            flash(message)

    return render_template("verify_otp.html")


# --------------------------------------------------
# FORGOT PASSWORD
# --------------------------------------------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        user = User.query.filter_by(
            email=email,
            verified=True
        ).first()

        if user:

            if send_otp(email, "reset"):

                session.clear()
                session["reset_email"] = email

                flash("Password reset OTP sent to your email.")
                return redirect(url_for("verify_reset"))

        flash(
            "If this verified email exists, a reset OTP will be sent."
        )

    return render_template("forgot_password.html")


# --------------------------------------------------
# RESET OTP VERIFICATION
# --------------------------------------------------

@app.route("/verify-reset", methods=["GET", "POST"])
def verify_reset():

    if "reset_email" not in session:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        code = request.form.get("otp", "").strip()
        email = session["reset_email"]

        success, message = verify_otp(
            email, "reset", code
        )

        if success:
            session["reset_verified"] = True
            return redirect(url_for("reset_password"))

        flash(message)

    return render_template("verify_otp.html")


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
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("reset_password"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("reset_password"))

        user = User.query.filter_by(
            email=session["reset_email"]
        ).first()

        if user:
            user.password = generate_password_hash(password)
            db.session.commit()

        session.clear()

        flash("Password changed successfully. Please log in.")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        name=session.get("user_name")
    )


# --------------------------------------------------
# STUDENT PROFILE
# --------------------------------------------------

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():

    user = db.session.get(User, session["user_id"])

    if not user:
        session.clear()
        return redirect(url_for("login"))

    student_profile = Profile.query.filter_by(
        user_id=user.id
    ).first()

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        role = request.form.get("role", "student").strip()
        known_topics = request.form.get(
            "known_topics", ""
        ).strip()
        learning_topics = request.form.get(
            "learning_topics", ""
        ).strip()
        bio = request.form.get("bio", "").strip()

        if not name:
            flash("Please enter your name.")
            return redirect(url_for("profile"))

        if role not in ["student", "teacher", "both"]:
            flash("Please select a valid role.")
            return redirect(url_for("profile"))

        if not student_profile:

            student_profile = Profile(
                user_id=user.id,
                role=role,
                known_topics=known_topics,
                learning_topics=learning_topics,
                bio=bio
            )

            db.session.add(student_profile)

        else:

            student_profile.role = role
            student_profile.known_topics = known_topics
            student_profile.learning_topics = learning_topics
            student_profile.bio = bio

        user.name = name
        session["user_name"] = name

        db.session.commit()

        flash("Profile saved successfully!")
        return redirect(url_for("dashboard"))

    return render_template(
        "profile.html",
        profile=student_profile,
        name=user.name
    )


# --------------------------------------------------
# FIND STUDENTS / MATCHING
# --------------------------------------------------

@app.route("/matches")
@login_required
def matches():

    current_user = db.session.get(User, session["user_id"])

    if not current_user:
        session.clear()
        return redirect(url_for("login"))

    current_profile = Profile.query.filter_by(
        user_id=current_user.id
    ).first()

    search_topic = request.args.get("topic", "").strip()

    matched_students = []

    if current_profile:

        if search_topic:
            topics_to_find = [search_topic.lower()]
        else:
            topics_to_find = split_topics(
                current_profile.learning_topics
            )

        all_profiles = Profile.query.join(User).filter(
            User.verified.is_(True),
            User.id != current_user.id
        ).all()

        for other_profile in all_profiles:

            their_topics = split_topics(
                other_profile.known_topics
            )

            common_topics = [
                topic for topic in topics_to_find
                if topic in their_topics
            ]

            if common_topics:
                matched_students.append(other_profile.user)

    return render_template(
        "matches.html",
        matches=matched_students,
        topic=search_topic
    )


# --------------------------------------------------
# SEND CONNECTION REQUEST
# --------------------------------------------------

@app.route(
    "/send-request/<int:receiver_id>",
    methods=["POST"]
)
@login_required
def send_request(receiver_id):

    sender_id = session["user_id"]

    if sender_id == receiver_id:
        flash("You cannot send a request to yourself.")
        return redirect(url_for("matches"))

    receiver = db.session.get(User, receiver_id)

    if not receiver or not receiver.verified:
        flash("Student not found.")
        return redirect(url_for("matches"))

    existing_request = ConnectionRequest.query.filter(
        ConnectionRequest.sender_id == sender_id,
        ConnectionRequest.receiver_id == receiver_id,
        ConnectionRequest.status == "pending"
    ).first()

    if existing_request:
        flash("You have already sent a pending request.")
        return redirect(url_for("matches"))

    reverse_request = ConnectionRequest.query.filter(
        ConnectionRequest.sender_id == receiver_id,
        ConnectionRequest.receiver_id == sender_id,
        ConnectionRequest.status == "pending"
    ).first()

    if reverse_request:
        flash("This student has already sent you a request.")
        return redirect(url_for("requests"))

    new_request = ConnectionRequest(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message="I would like to connect and learn together.",
        status="pending"
    )

    db.session.add(new_request)
    db.session.commit()

    flash("Connection request sent!")
    return redirect(url_for("matches"))


# --------------------------------------------------
# VIEW CONNECTION REQUESTS
# --------------------------------------------------

@app.route("/requests")
@login_required
def requests():

    current_user_id = session["user_id"]

    incoming_requests = ConnectionRequest.query.filter_by(
        receiver_id=current_user_id
    ).order_by(ConnectionRequest.created_at.desc()).all()

    outgoing_requests = ConnectionRequest.query.filter_by(
        sender_id=current_user_id
    ).order_by(ConnectionRequest.created_at.desc()).all()

    return render_template(
        "requests.html",
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        received_requests=incoming_requests,
        sent_requests=outgoing_requests
    )


# --------------------------------------------------
# ACCEPT OR REJECT CONNECTION REQUEST
# --------------------------------------------------

@app.route(
    "/respond-request/<int:request_id>/<action>",
    methods=["POST"]
)
@login_required
def respond_request(request_id, action):

    connection = db.session.get(
        ConnectionRequest, request_id
    )

    if not connection:
        flash("Connection request not found.")
        return redirect(url_for("requests"))

    if connection.receiver_id != session["user_id"]:
        flash("You are not allowed to respond to this request.")
        return redirect(url_for("requests"))

    if connection.status != "pending":
        flash("This request has already been handled.")
        return redirect(url_for("requests"))

    if action == "accept":
        connection.status = "accepted"
        flash("Connection request accepted!")

    elif action == "reject":
        connection.status = "rejected"
        flash("Connection request rejected.")

    else:
        flash("Invalid action.")
        return redirect(url_for("requests"))

    db.session.commit()

    return redirect(url_for("requests"))


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["GET", "POST"])
def logout():

    session.clear()
    flash("You have been logged out.")

    return redirect(url_for("home"))


# --------------------------------------------------
# CREATE DATABASE TABLES
# --------------------------------------------------

with app.app_context():
    db.create_all()


# --------------------------------------------------
# RUN APPLICATION LOCALLY
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)

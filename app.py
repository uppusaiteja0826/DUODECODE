
import os
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Application configuration
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "development-only-change-this")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///duodecode.db"
)
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


# DATABASE MODELS

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


# OTP FUNCTIONS

def hash_otp(code):
    secret = app.config["SECRET_KEY"]
    return hmac.new(
        secret.encode(),
        code.encode(),
        hashlib.sha256
    ).hexdigest()


def send_otp(email, purpose):
    # Invalidate previous OTPs
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
            subject="DUODECODE - Email Verification OTP",
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
        challenge.code_hash, hash_otp(code)
    ):
        challenge.attempts += 1
        db.session.commit()
        return False, "Incorrect OTP."

    challenge.used = True
    db.session.commit()
    return True, "OTP verified successfully."


# HOME PAGE

@app.route("/")
def home():
    return render_template("index.html")


# USER REGISTRATION

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
            session["pending_email"] = email
            flash("OTP sent to your email.")
            return redirect(url_for("verify_email"))

        flash("Email could not be sent. Check email configuration.")
        return redirect(url_for("register"))

    return render_template("register.html")


# EMAIL VERIFICATION

@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    if "pending_email" not in session:
        return redirect(url_for("register"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        email = session["pending_email"]

        success, message = verify_otp(email, "register", code)

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


# LOGIN WITH EMAIL OTP

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash("Incorrect email or password.")
            return redirect(url_for("login"))

        if not user.verified:
            session["pending_email"] = email
            flash("Please verify your email first.")
            return redirect(url_for("verify_email"))

        if send_otp(email, "login"):
            session["pending_login"] = email
            flash("Login OTP sent to your email.")
            return redirect(url_for("verify_login"))

        flash("Could not send OTP. Please try again.")

    return render_template("login.html")


@app.route("/verify-login", methods=["GET", "POST"])
def verify_login():
    if "pending_login" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        email = session["pending_login"]
        code = request.form.get("otp", "").strip()

        success, message = verify_otp(email, "login", code)

        if success:
            user = User.query.filter_by(email=email).first()

            if user and user.verified:
                session.clear()
                session["user_id"] = user.id
                session["user_name"] = user.name
                flash("Login successful!")
                return redirect(url_for("dashboard"))

        flash(message)

    return render_template("verify_otp.html")


# FORGOT PASSWORD

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email, verified=True).first()

        if user:
            if send_otp(email, "reset"):
                session["reset_email"] = email
                flash("Password reset OTP sent to your email.")
                return redirect(url_for("verify_reset"))

        flash("If this verified email exists, a reset OTP will be sent.")

    return render_template("forgot_password.html")


@app.route("/verify-reset", methods=["GET", "POST"])
def verify_reset():
    if "reset_email" not in session:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        email = session["reset_email"]

        success, message = verify_otp(email, "reset", code)

        if success:
            session["reset_verified"] = True
            return redirect(url_for("reset_password"))

        flash(message)

    return render_template("verify_otp.html")


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

        session.pop("reset_email", None)
        session.pop("reset_verified", None)

        flash("Password changed successfully. Please log in.")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


# DASHBOARD

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        name=session.get("user_name")
    )


# LOGOUT

@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.")
    return redirect(url_for("login"))


# CREATE DATABASE

with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)

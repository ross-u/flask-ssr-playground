"""
This is a server-side rendered (SSR) Flask application for a job board platform. 
It provides user signup, login, session management, and routes
for rendering the web application pages and performing CRUD operations.
"""

import os

from datetime import timedelta
from flask import (
    Flask,
    Response,
    render_template,
    request,
    redirect,
    flash,
    session,
    url_for,
)
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash
from jinja2 import TemplateNotFound
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from cs50 import SQL
from flask_session import Session

from helpers import (
    render_error_message,
    login_required,
    anonymous_required,
    recruiter_required,
)
from validators import (
    is_valid_email,
    is_valid_password,
    is_valid_name,
    is_valid_role,
)

load_dotenv()

app = Flask(__name__)

# Set session and email serializer secret keys
app.config["SECRET_KEY"] = os.getenv("SESSION_SECRET_KEY")
app.config["VERIFICATION_TOKEN_SECRET_KEY"] = os.getenv("EMAIL_TOKEN_SECRET_KEY")

# Configure sessions
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=90)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure email server
app.config["MAIL_SERVER"] = "sandbox.smtp.mailtrap.io"
app.config["MAIL_PORT"] = 2525
app.config["MAIL_USERNAME"] = os.environ.get("MAILTRAP_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAILTRAP_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER")
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
mail = Mail(app)

# Database connection
db = SQL("sqlite:///qturn.db")


# Initialize the token serializer
s = URLSafeTimedSerializer(app.config["VERIFICATION_TOKEN_SECRET_KEY"])


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET"])
def index():
    """Render the index page"""
    try:
        #  query the sqlite database to get the 10 latest created jobs and have pagination
        rows = db.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 50")

        favorite_jobs = []
        if session.get("user_id"):
            favorites_rows = db.execute(
                "SELECT job_id FROM favorites WHERE user_id = ?", session.get("user_id")
            )
            favorite_jobs = [row["job_id"] for row in favorites_rows]

        # If a row id is favorite by the user, add a new key to the row with the value True
        for row in rows:
            row["is_favorite"] = row["id"] in favorite_jobs

        return render_template("index.html", jobs=rows)

    except (TemplateNotFound, RuntimeError, ValueError) as e:
        print(f"An error occurred: {e}")
        return render_error_message("Something went wrong", code=500)


@app.route("/about", methods=["GET"])
def about():
    """Render the about page"""
    try:
        return render_template("about.html")
    except (TemplateNotFound, RuntimeError, ValueError) as e:
        print(f"An error occurred: {e}")
        return render_error_message("Something went wrong", code=500)


@app.route("/signup", methods=["GET", "POST"])
@anonymous_required
def signup():
    """
    Manages user signup.

    On GET request, renders a signup form.
    On POST request, validates the form data, creates a new user,
    sends a verification email, and redirects to the home page.
    """
    try:
        error_message = None
        error_code = None

        if request.method == "POST":
            # Get form data
            first_name = request.form.get("first_name")
            last_name = request.form.get("last_name")
            email = request.form.get("email")
            password = request.form.get("password")
            confirmation = request.form.get("confirmation")
            role = request.form.get("role")

            # Check if the form data was submitted
            if (
                not first_name
                or not last_name
                or not is_valid_name(first_name)
                or not is_valid_name(last_name)
            ):
                error_message = "Must provide valid first and last name"
                error_code = 400

            elif not email or not is_valid_email(email):
                error_message = "Must provide valid email"
                error_code = 400

            elif not password or not is_valid_password(password):
                flash(
                    "Password must be at least 8 characters with a mix of "
                    "uppercase, lowercase, and a number."
                )
                error_message = "Must provide valid password"
                error_code = 400

            elif not confirmation or not is_valid_password(confirmation):
                flash(
                    "Password must be at least 8 characters with a mix of "
                    "uppercase, lowercase, and a number."
                )
                error_message = "Must provide valid password confirmation"
                error_code = 400

            elif not role or not is_valid_role(role):
                flash("Please select a role")
                error_message = "Must select a role"
                error_code = 400

            elif password != confirmation:
                flash("Passwords don't match")
                error_message = "Passwords don't match"
                error_code = 400

            if error_message:
                return render_error_message(error_message, code=error_code)

            # Hash the password
            hashed_password = generate_password_hash(request.form.get("password"))

            # Create a new user in the database
            db.execute(
                """
                INSERT INTO users (first_name, last_name, email, role, hash) 
                VALUES (?, ?, ?, ?, ?)
                """,
                first_name,
                last_name,
                email,
                role,
                hashed_password,
            )
            rows = db.execute("SELECT * FROM users WHERE email = ?", email)
            user = rows[0]

            if not user:
                raise ValueError("User not found")

            # Generate a unique verification token for the user
            token = s.dumps(email, salt="email-confirm")

            # Create a verification link
            link = url_for("confirm_email", token=token, _external=True)

            # Send a verification email to the user -
            # TODO: Make it asynchronous with Celery task queue
            msg = Message(subject="QTurn - Confirm Your Email", recipients=[email])
            msg.html = f"""
                <p>Thanks for signing up for QTurn! Please click the link below to verify your email address and complete your registration.</p>
                <p>
                  <a href={link}>Verify your email</a>
                </p>
              """
            mail.send(msg)

            # Set a flash message to remind the user to verify their account
            flash("Sign up successful! Please check your email to verify your account.")

            # Redirect user to home page
            return redirect("/")

        return render_template("auth/signup.html")

    except (TemplateNotFound, ConnectionError, RuntimeError, ValueError) as e:
        print(f"An error occurred: {e}")
        return render_error_message("Something went wrong", code=500)


@app.route("/login", methods=["GET", "POST"])
@anonymous_required
def login():
    """
    Manages user login

      On GET request, renders template `login.html`.
      On POST request, validates the form data, creates a session, and redirects to the home page.
    """
    if request.method == "POST":
        try:
            error_message = None
            error_code = None

            # Get form data
            email = request.form.get("email")
            password = request.form.get("password")

            if not email or not is_valid_email(email):
                error_message = "Must provide valid credentials"
                error_code = 403

            elif not password or not is_valid_password(password):
                error_message = "Must provide valid credentials"
                error_code = 403

            if error_message:
                return render_error_message(error_message, code=error_code)

            rows = db.execute("SELECT * FROM users WHERE email = ? LIMIT 1", email)

            # Check if the user with the given email exists - check if the query returned any rows
            if len(rows) != 1:
                error_message = "Must provide valid credentials"
                error_code = 403

            user = rows[0]

            # Check if the password is correct
            if not check_password_hash(user["hash"], password):
                return render_error_message("Provide valid credentials", code=403)

            if user["is_verified"] is False:
                return render_error_message(
                    "Before you can log in, please verify your email", code=403
                )

            # Create a new session for the user
            session["user_id"] = user["id"]
            session["user_role"] = user["role"]

            return redirect("/")

        except (TemplateNotFound, RuntimeError, ValueError, IndexError) as e:
            print(f"An error occurred: {e}")
            return render_error_message("Something went wrong", code=500)

    else:
        return render_template("auth/login.html")


@app.route("/logout")
@login_required
def logout():
    """Logs user out"""
    try:
        # Forget any user_id
        session.clear()

        # Redirect user to login form
        flash("Logged out successfully")
        return redirect("/")

    except (TemplateNotFound, RuntimeError, ValueError) as e:
        print(f"An error occurred: {e}")
        return render_error_message("Something went wrong", code=500)


@app.route("/confirm/<token>", methods=["GET"])
def confirm_email(token):
    """
    Verifies an email confirmation token and updates the user's verification status.

    Args:
        token (str): The email confirmation token to verify.

    Returns:
        - A redirect to the login page if the token is valid,
        - A rendered error template `error.html` if the token is invalid or expired.
    """
    try:
        # Verify the token
        email = s.loads(token, salt="email-confirm", max_age=1800)

        # Update the user's is_verified field to True
        db.execute("UPDATE users SET is_verified = 1 WHERE email = ?", email)

    except (BadSignature, SignatureExpired, RuntimeError, ValueError) as e:
        print(f"An error occurred: {e}")
        # If the token is invalid or expired, show an error message
        return render_error_message("Invalid token", code=403)

    # Redirect the user to the login page with a success message
    flash("Email confirmed. Please log in.")
    return redirect(url_for("login"))


@app.route("/jobs/<int:job_id>", methods=["GET"])
@login_required
def job_details(job_id):
    """
    Renders a job details page.

    Args:
        job_id (int): The id of the job to render.

    Returns:
        - A rendered template `job_details.html` if the job exists,
        - A rendered error template `error.html` if the job is not found.
    """
    try:
        # Get the job from the database
        rows = db.execute("SELECT * FROM jobs WHERE id = ?", job_id)
        job = rows[0]

        # Check if the job exists
        if not job:
            return render_error_message("Job not found", code=404)

        # Check if the user is logged in
        if session.get("user_id"):
            # Check if the job is favorite by the user
            rows = db.execute(
                "SELECT job_id FROM favorites WHERE user_id = ? AND job_id = ?",
                session.get("user_id"),
                job_id,
            )
            job["is_favorite"] = len(rows) > 0

        # Check if the user is the creator of the job and add current user is owner
        if job["creator_id"] and session.get("user_id") == job["creator_id"]:
            job["is_owned_by_user"] = True

        return render_template("jobs/job_details.html", job=job)

    except (TemplateNotFound, RuntimeError, ValueError) as e:
        print(f"An error occurred: {e}")
        return render_error_message("Something went wrong", code=500)


@app.route("/jobs/<int:job_id>", methods=["DELETE"])
@login_required
@recruiter_required
def delete_job(job_id):
    """
    Deletes a job.

    Args:
        job_id (int): The id of the job to delete.

    Returns:
        - A response with status code 200 if the job is deleted,
        - A response with status code 404 if the job is not found,
    """
    try:
        # Delete the job
        rows_deleted = db.execute("DELETE FROM jobs WHERE id = ?", job_id)
        if rows_deleted != 1:
            return Response("Job not found", status=404)

        return Response("Job deleted", status=200)

    except (RuntimeError, ValueError) as e:
        print(f"An error occurred: {e}")
        return render_error_message("Something went wrong", code=500)


@app.route("/jobs", methods=["GET", "POST"])
@login_required
@recruiter_required
def create_job():
    """
    Renders a job creation form and creates a new job.

    Returns:
        - A rendered template `create_job.html` on GET request,
        - A redirect to the job details page on POST request.
    """
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        company = request.form.get("company")
        image = request.form.get("image")
        tags = request.form.get("tags")
        url = request.form.get("url")
        creator_id = session.get("user_id")

        validation_error = False

        if not title:
            flash("Please provide a title")
            validation_error = True

        elif not description:
            flash("Please provide a description")
            validation_error = True

        elif not company:
            flash("Please provide a name for the company")
            validation_error = True

        elif not image:
            flash("Please provide a link to the image of the company logo")
            validation_error = True

        elif not url:
            flash("Please provide a link to the job posting")
            validation_error = True

        if validation_error:
            return render_template("jobs/create_job.html")

        new_job_id = db.execute(
            """
            INSERT INTO jobs (title, description, company, image, tags, url, creator_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            title,
            description,
            company,
            image,
            tags,
            url,
            creator_id,
        )

        flash("Job created successfully")
        return redirect(url_for("job_details", job_id=new_job_id))

    return render_template("jobs/create_job.html")


@app.route("/favorites/<int:job_id>", methods=["POST", "DELETE"])
@login_required
def favorite_job(job_id):
    """
    Adds or removes a job from the user's favorites.

    Args:
        job_id (int): The id of the job to add or remove from the user's favorites.

    Returns:
        - A response with status code 200 if the job is added or 204 if the job is removed,
        - A response with status code 404 if the job is not found,
    """
    try:
        # Check if the job exists
        jobs_rows = db.execute("SELECT * FROM jobs WHERE id = ?", job_id)
        if len(jobs_rows) != 1:
            return Response("Job not found", status=404)

        # Check if the job is already favorite by the user
        favorites_rows = db.execute(
            "SELECT id FROM favorites WHERE user_id = ? AND job_id = ?",
            session.get("user_id"),
            job_id,
        )

        # If the job is already favorite by the user, remove it from the user's favorites
        if len(favorites_rows) == 1 and request.method == "DELETE":
            db.execute(
                "DELETE FROM favorites WHERE user_id = ? AND job_id = ?",
                session.get("user_id"),
                job_id,
            )
            return Response("Removed from favorites", status=204)

        if len(favorites_rows) == 0 and request.method == "POST":
            # Add the job to the user's favorites
            db.execute(
                "INSERT INTO favorites (user_id, job_id) VALUES (?, ?)",
                session.get("user_id"),
                job_id,
            )
            return Response("Added to favorites", status=200)

        raise RuntimeError("Unable to add or remove job from favorites")

    except (RuntimeError, ValueError) as e:
        print(f"An error occurred: {e}")
        return render_error_message("Something went wrong", code=500)

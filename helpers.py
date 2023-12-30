import requests
from flask import redirect, render_template, session, flash
from functools import wraps


def render_error_message(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    category = "primary" if (code < 400) else "danger"
            
    print(f"An error occurred: {message}")
    flash(message, category)
    return render_template("error_message.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


# Decorator function to check admin access
def admin_required(f):
    '''
    Decorate routes to require admin access
    '''
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_role") != "admin":
            return redirect("/")
        return f(*args, **kwargs)

    return decorated_function


def recruiter_required(f):
    '''
    Decorate routes to require recruiter access
    '''
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_role") != "recruiter":
            return redirect("/")
        return f(*args, **kwargs)

    return decorated_function

def anonymous_required(f):
    '''
    Decorate routes to allow only anonymous users who are not logged in
    '''
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is not None:
            return redirect("/")
        return f(*args, **kwargs)

    return decorated_function
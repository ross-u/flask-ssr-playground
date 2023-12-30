import re


def is_valid_email(email):
    # Check if the email format is valid
    return bool(re.search(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", email))


def is_valid_password(password):
    # Check if the password format is valid, and allow special characters
    return bool(
        re.fullmatch(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$", password)
    )


def is_valid_name(name):
    # Check if the name format is valid, at least 2 characters long, and at most 30 characters long
    return bool(re.fullmatch(r"[a-zA-Z]{2,30}", name))


def is_valid_datetime(datetime):
    # Check if the datetime format is valid
    return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", datetime))


def is_valid_role(role):
    # Check if the role is one of the allowed string values
    return role in ["candidate", "recruiter", "admin"]
from flask import Blueprint

views = Blueprint("views")

@views.route("/")
def home():
    return "This is the home page"
import os
from flask import (
    Flask, flash, render_template, 
    redirect, request, session, url_for)
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash 
if os.path.exists("env.py"):
    import env


app = Flask(__name__)

app.config["MONGO_DBNAME"] = os.environ.get("MONGO_DBNAME")
app.config["MONGO_URI"] = os.environ.get("MONGO_URI")
app.secret_key = os.environ.get("SECRET_KEY")

mongo = PyMongo(app)


@app.route("/")
@app.route("/get_character")
def get_character():
    character = mongo.db.character.find()
    return render_template("characters.html", character=character)


@app.route("/register", methods=["Get","POST"])

@app.route("/register", methods=["Get","POST"])

def register():
    if request.method == "POST":
        # check if username already exists in db
        existing_user = mongo.db.users.find_one(
            {"username": request.form.get("username").lower()})

        if existing_user:
            flash("Username already exists")
            return redirect(url_for("register"))
        
        # check the passwords match 
        
        password1 = request.form.get("password")
        password2 = request.form.get("password2")
        
        if password1 != password2:
            flash("Please make sure your passwords match")
            return redirect(url_for("register"))
        
        # if the username is unique and the passwords match then register the account
        # in the db
        
        register = {
            "first_name": request.form.get("first-name"),
            "last_name": request.form.get("last-name"),
            "username": request.form.get("username").lower(),
            "password": generate_password_hash(request.form.get("password")),
            "email_address" : request.form.get("email").lower()
        }
        mongo.db.users.insert_one(register)

        # put the new user into 'session' cookie
        session["user"] = request.form.get("username").lower()
        flash("Registration Successful!")
        return redirect(url_for("profile", username=session["user"]))
    
    return render_template("register.html")

#logging into account
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        existing_user = mongo.db.users.find_one(
            {"username": request.form.get("username").lower()})        
        if existing_user:
            # ensure hashed password matches user input
            if check_password_hash(
                existing_user["password"], request.form.get("password")):
                        session["user"] = request.form.get("username").lower()
                        flash("Welcome, {}".format(
                            request.form.get("username")))
                        return redirect(url_for(
                            "profile", username=session["user"]))
            else:
                # invalid password match
                flash("Incorrect Username and/or Password")
                return redirect(url_for("login"))
        else: 
            flash("Incorrect Username or Password")
            return redirect(url_for("login"))
    return render_template("login.html")

#get to the users profile page
@app.route("/profile/<username>", methods=["GET", "POST"])
def profile(username):
    # grab the session user's username from db
    username = mongo.db.users.find_one(
        {"username": session["user"]})["username"]
    
    if session["user"]:
        return render_template("profile.html", username=username)
    
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    # remove user from session cookie
    flash("You have been logged out")
    session.pop("user")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host=os.environ.get("IP"),
            port=int(os.environ.get("PORT")),
            debug=True)
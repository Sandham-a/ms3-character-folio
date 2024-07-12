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
        characters = list(mongo.db.character.find())
        return render_template("profile.html", username=username, characters=characters)
    
    return redirect(url_for("login"))


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

@app.route("/get_character")
def get_character():
    characters = mongo.db.character.find()
    return render_template("characters.html", characters=characters)

@app.route("/logout")
def logout():
    # remove user from session cookie
    flash("You have been logged out")
    session.pop("user")
    return redirect(url_for("login"))

@app.route("/new_character", methods=["GET","POST"])
def add_character():
    if request.method == "POST":
        character = {
            "character_name": request.form.get("character_name"),
            "race": request.form.get("race"),
            "class_name": request.form.get("class_name"),
            "background_name": request.form.get("background_name"),
            "character_strength": request.form.get("character_strength"),
            "character_dexterity": request.form.get("character_dexterity"),
            "character_constitution": request.form.get("character_constitution"),
            "character_intelligence": request.form.get("character_intelligence"),
            "character_wisdom": request.form.get("character_wisdom"),
            "character_charisma": request.form.get("character_charisma"),
            "created_by": session["user"]
        }
        mongo.db.character.insert_one(character)
        flash("Character Created")
        return redirect(url_for("new_character"))
    
    races = mongo.db.race.find().sort("race", 1)
    backgrounds = mongo.db.background.find().sort("background_name", 1)
    character_classes = mongo.db.character_class.find().sort("class_name", 1)
    return render_template("new_character.html", races=races, character_classes=character_classes, backgrounds=backgrounds)

@app.route("/edit_character/<character_id>", methods=["GET", "POST"])
def edit_character(character_id):

    if request.method == "POST":
        # Get form data
        character_name = request.form.get("character_name")
        race = request.form.get("race")
        class_name = request.form.get("class_name")
        background_name = request.form.get("background_name")
        character_strength = request.form.get("character_strength")
        character_dexterity = request.form.get("character_dexterity")
        character_constitution = request.form.get("character_constitution")
        character_intelligence = request.form.get("character_intelligence")
        character_wisdom = request.form.get("character_wisdom")
        character_charisma = request.form.get("character_charisma")

        # Update the character document
        mongo.db.character.update_one(
            {"_id": ObjectId(character_id)},
            {
                "$set": {
                    "character_name": character_name,
                    "race": race,
                    "class_name": class_name,
                    "background_name": background_name,
                    "character_strength": character_strength,
                    "character_dexterity": character_dexterity,
                    "character_constitution": character_constitution,
                    "character_intelligence": character_intelligence,
                    "character_wisdom": character_wisdom,
                    "character_charisma": character_charisma
                }
            }
        )
        flash("Character Updated Successfully")
        return redirect(url_for("get_character"))

    character = mongo.db.character.find_one({"_id": ObjectId(character_id)})
    races = mongo.db.race.find().sort("race", 1)
    backgrounds = mongo.db.background.find().sort("background_name", 1)
    character_classes = mongo.db.character_class.find().sort("class_name", 1)
    return render_template("edit_character.html", races=races, character= character,
                            character_classes = character_classes, backgrounds=backgrounds)

@app.route("/delete_character/<character_id>")
def delete_character(character_id):
    mongo.db.character.delete_one({"_id": ObjectId(character_id)})
    flash("Task Successfully Deleted")
    return redirect(url_for('profile', username=session['user']))


@app.route("/contact")
def contact():
    return render_template("contact.html")

if __name__ == "__main__":
    app.run(host=os.environ.get("IP"),
            port=int(os.environ.get("PORT")),
            debug=True)
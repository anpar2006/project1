import os, bcrypt, functools

from flask import Flask, session, render_template, request, redirect, flash
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# DATABASE_URL=postgres://zgewnjrzrplepp:eb69c7e8f672d9474d1315e4e7cb61fa5ecc06bb5088d904c1bc0fd86bc58987@ec2-50-16-198-4.compute-1.amazonaws.com:5432/d740ra6jrg6i37
# psql "dbname=d740ra6jrg6i37 host=ec2-50-16-198-4.compute-1.amazonaws.com user=zgewnjrzrplepp password=eb69c7e8f672d9474d1315e4e7cb61fa5ecc06bb5088d904c1bc0fd86bc58987 port=5432 sslmode=require" 
# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect("/login")
    return wrap

@app.route("/")
@login_required
def index():
    return render_template("index.html")
    
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register."""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        if not username:
            return render_template("error.html", message="Username has not been entered")

        elif not password:
            return render_template("error.html", message="Password has not been entered")

        if db.execute("SELECT * FROM users WHERE username = :username", {"username": username}).rowcount == 1:
           return render_template("register.html", message="This Username is Already Taken.")
        db.execute("INSERT INTO users (username, password) VALUES (:username, :hashed)",{"username": username, "hashed": hashed})
        db.commit()
        return render_template("success.html")
    
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        session.pop('user_id', None)

        username = request.form.get("username")
        password = request.form.get("password")

        info = db.execute("SELECT * FROM users WHERE username = :username", {"username": username})
        info2 = info.fetchone()

        if not username:
            return render_template("error.html", message="Username has not been entered")

        elif not password:
            return render_template("error.html", message="Password has not been entered")

        if info2 == None or not check_password_hash(info2[2], password):
            return render_template("error.html", message="invalid username and/or password")

        session["user_id"] = info2[0]
        session["logged_in"] = True

        return redirect("/")
    
    else:
        return render_template("login.html")
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    return render_template("search.html")

@app.route("/getresults", methods=["GET"])
@login_required
def getresults():

    search = request.args.get("search")

    if not search:
        return render_template("error.html", message="Nothing was entered in the search bar.")

    typed = f"%{search}%"

    typed = typed.title()

    query = db.execute("SELECT isbn, title, author, year FROM books WHERE \
                       title LIKE :typed",
                        {"typed": typed})

    if query.rowcount == 0:
        return render_template("error.html", message="Book not found.")

    result = query.fetchall()

    return render_template("results.html", result=result)
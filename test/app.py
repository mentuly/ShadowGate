from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = "change_this_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# ---------------- Models ---------------- #

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(50), unique=True, nullable=False)

    password = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), default="user")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(50), nullable=False)

    text = db.Column(db.Text, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- Routes ---------------- #

@app.route("/")
def index():
    comments = Comment.query.order_by(Comment.id.desc()).all()
    return render_template("index.html", comments=comments)


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        if User.query.filter_by(username=username).first():
            flash("User already exists.")
            return redirect(url_for("register"))

        user = User(
            username=username,
            password=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        flash("Registration successful.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):

            login_user(user)

            return redirect(url_for("index"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("index"))


@app.route("/comment", methods=["POST"])
@login_required
def comment():

    text = request.form["text"]

    if len(text.strip()) == 0:
        flash("Comment cannot be empty.")
        return redirect(url_for("index"))

    comment = Comment(
        username=current_user.username,
        text=text
    )

    db.session.add(comment)
    db.session.commit()

    flash("Comment added.")

    return redirect(url_for("index"))


@app.route("/search")
@login_required
def search():

    username = request.args.get("username", "")

    users = []

    if username:
        users = User.query.filter(
            User.username.contains(username)
        ).all()

    return render_template(
        "index.html",
        users=users,
        comments=Comment.query.order_by(Comment.id.desc()).all()
    )


@app.route("/admin")
@login_required
def admin():

    if current_user.role != "admin":
        flash("Access denied.")
        return redirect(url_for("index"))

    users = User.query.all()

    return render_template(
        "admin.html",
        users=users
    )


@app.route("/delete_user/<int:user_id>")
@login_required
def delete_user(user_id):

    if current_user.role != "admin":
        return redirect(url_for("index"))

    user = User.query.get_or_404(user_id)

    if user.id != current_user.id:

        db.session.delete(user)
        db.session.commit()

    return redirect(url_for("admin"))


# ---------------- Create DB ---------------- #

with app.app_context():

    db.create_all()

    admin = User.query.filter_by(username="admin").first()

    if not admin:

        admin = User(
            username="admin",
            password=generate_password_hash("admin123"),
            role="admin"
        )

        db.session.add(admin)

        db.session.commit()


# ---------------- Run ---------------- #

if __name__ == "__main__":
    app.run(debug=True)
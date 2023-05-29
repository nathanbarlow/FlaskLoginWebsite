from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
)
from passlib.hash import sha256_crypt

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo

from models import db, User
import os

app: Flask = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(
    app.root_path, 'database.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager: LoginManager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id: int) -> User:
    return User.query.get(user_id)


@app.route('/')
def index() -> str:
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login() -> str:
    if request.method == 'POST':
        username: str = request.form['username']
        password: str = request.form['password']

        user: User = User.query.filter_by(username=username).first()

        if user and sha256_crypt.verify(password, user.password):
            login_user(user)
            return redirect(url_for('protected'))

        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/protected')
@login_required
def protected() -> str:
    return render_template('protected.html')


@app.route('/content')
@login_required
def content() -> str:
    return render_template('content.html')


@app.route('/logout')
@login_required
def logout() -> str:
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register() -> str:
    form: RegistrationForm = RegistrationForm()
    if form.validate_on_submit():
        username: str = form.username.data
        password: str = form.password.data

        existing_user: User = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.')
            return redirect(url_for('register'))

        new_user: User = User(username=username, password=sha256_crypt.hash(password))
        db.session.add(new_user)
        db.session.commit()
        db.session.refresh(new_user)

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.errorhandler(401)
def unauthorized(error) -> str:
    return render_template('unauthorized.html'), 401


class RegistrationForm(FlaskForm):
    username: StringField = StringField('Username', validators=[DataRequired()])
    password: PasswordField = PasswordField('Password', validators=[DataRequired()])
    confirm_password: PasswordField = PasswordField(
        'Confirm Password', validators=[DataRequired(), EqualTo('password')]
    )
    submit: SubmitField = SubmitField('Register')


if __name__ == '__main__':
    app.run()

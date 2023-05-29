from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from passlib.hash import sha256_crypt

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo

from models import db, User
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Create the tables
# with app.app_context():
#     db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve the user from the database based on the username
        user = User.query.filter_by(username=username).first()
        
        if user and sha256_crypt.verify(password, user.password):
            # Use the user object to log in the user
            login_user(user)
            return redirect(url_for('protected'))
        
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/protected')
@login_required
def protected():
    return render_template('protected.html')

@app.route('/content')
@login_required
def content():
    return render_template('content.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Check if the user already exists in the database
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            # User already exists, handle the error appropriately
            flash('Username already exists. Please choose a different username.')
            return redirect(url_for('register'))
        
        # Create a new User instance without specifying the id
        new_user = User(username=username, password=sha256_crypt.hash(password))
        
        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()
        
        # Retrieve the auto-generated id
        db.session.refresh(new_user)
        
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.errorhandler(401)
def unauthorized(error):
    return render_template('unauthorized.html'), 401


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


if __name__ == '__main__':
    app.run()

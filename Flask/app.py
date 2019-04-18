from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisisssupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(60), unique=True)
    password = db.Column(db.String(80))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), length(min=5, max=15)])
    password = PasswordField('password', validators=[InputRequired(), length(min=7, max=60)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), length(min=5, max=60)])
    username = StringField('username', validators=[InputRequired(), length(min=5, max=15)])
    password = PasswordField('password', validators=[InputRequired(), length(min=7, max=60)])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET', 'POST'])
def login():

    form = LoginForm()

    if form.validate_on_submit():

        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password, form.password.data):

                login_user(user, remember=form.remember.data)
                return redirect(url_for('schedule'))

        else:

            flash('Login unsuccessful. Please, check your Login or password', 'danger')



    return render_template('login.html', form=form)


@app.route('/SignUp',  methods=['GET', 'POST'])
def signup():

    form = RegisterForm()

    if form.validate_on_submit():

        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        log_test = User.query.filter_by(login=form.login.data).first()
        em_test = User.query.filter_by(login=form.email.data).first()
        if em_test:
            flash(f'This E-Mail alrealy exists. Please, change another one', 'error')
        if log_test:
            flash(f'This Login alrealy exists. Please, change another one', 'error')
        if em_test == None and log_test == None:
            db.session.add(new_user)
            db.session.commit()
            flash(f'Your account has been created. Now Log In!','success')
            return redirect(url_for('login'))

    return render_template('signup.html', form=form)


@app.route('/schedule')
@login_required
def schedule():
    return render_template('schedule.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)


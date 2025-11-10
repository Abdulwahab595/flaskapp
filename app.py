from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
from flask_wtf.csrf import CSRFError, CSRFProtect # <<< --- 1. IMPORT CSRFProtect

app = Flask(__name__)
# SECRET_KEY is crucial for CSRF protection and session management
app.config['SECRET_KEY'] = 'a_very_secret_and_hard_to_guess_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firstapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app) # <<< --- 2. INITIALIZE GLOBAL CSRF PROTECTION

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Database Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

# --- WTForms Form Class ---
class UserForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired(), Length(min=7, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Add User')

# --- WTForms Form Class for Updating ---
class UpdateUserForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired(), Length(min=7, max=20)])
    submit = SubmitField('Update User')

# --- Routes ---
@app.route('/')
def index():
    users = User.query.all()
    form = UserForm()
    return render_template('index.html', users=users, form=form)

@app.route('/add', methods=['POST'])
def add():
    form = UserForm()
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                email=form.email.data,
                phone=form.phone.data,
                password_hash=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Error: This email address is already registered.', 'danger')
        return redirect(url_for('index'))
    # This part of the code will now only be reached for validation errors (e.g., bad email format), not CSRF errors.
    users = User.query.all()
    return render_template('index.html', users=users, form=form)

@app.route('/delete/<int:id>')
def delete(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'danger')
    return redirect(url_for('index'))

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    user = User.query.get_or_404(id)
    form = UpdateUserForm(obj=user)
    if form.validate_on_submit():
        try:
            user.first_name = form.first_name.data
            user.last_name = form.last_name.data
            user.email = form.email.data
            user.phone = form.phone.data
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('index'))
        except IntegrityError:
            db.session.rollback()
            flash('Error: That email is already in use by another account.', 'danger')
            return render_template('update.html', form=form)
    return render_template('update.html', form=form)

# --- Custom Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

# --- Application Runner ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
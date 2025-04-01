from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, DateField
from wtforms.validators import DataRequired, Email
import bcrypt
from flask_sqlalchemy import SQLAlchemy
import random
from datetime import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = '\x8bO|\xc3\xe3\x99&h%\xb9\xebU\xf9\x1eb\xee$\x85\xf1Z\x95\x85\xe3\xdd'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    interviews = db.relationship('Interview', backref='user', lazy=True)

class Interview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='Upcoming')
    performance = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class CompanyQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company = db.Column(db.String(100), nullable=False)
    question = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    frequency = db.Column(db.Integer, nullable=False, default=1)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class RegistrationForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class InterviewForm(FlaskForm):
    company = StringField("Company", validators=[DataRequired()])
    position = StringField("Position", validators=[DataRequired()])
    date = DateField("Interview Date", validators=[DataRequired()], format='%Y-%m-%d')
    notes = TextAreaField("Notes")
    status = SelectField("Status", choices=[('Upcoming', 'Upcoming'), ('Completed', 'Completed'), ('Rejected', 'Rejected'), ('Offered', 'Offered')])
    performance = SelectField("Performance (1-10)", choices=[(str(i), str(i)) for i in range(1, 11)], validators=[])
    submit = SubmitField("Save")

class CompanyQuestionForm(FlaskForm):
    company = StringField("Company", validators=[DataRequired()])
    question = TextAreaField("Question", validators=[DataRequired()])
    category = SelectField("Category", choices=[('Technical', 'Technical'), ('Behavioral', 'Behavioral'), ('System Design', 'System Design'), ('Coding', 'Coding'), ('Other', 'Other')])
    submit = SubmitField("Add Question")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(name=name, email=email, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash("An error occurred while registering. Please try again.", "danger")
            print("Database Error:", e)
            db.session.rollback()
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            session['user_id'] = user.id
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Login unsuccessful. Please check your email and password.", "danger")
    return render_template('login.html', form=form)

@app.route('/resume_template')
def resume_template():
    return render_template('resume_template.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access the dashboard.", "warning")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    # Get the user's interviews for the dashboard
    interviews = Interview.query.filter_by(user_id=user.id).order_by(Interview.date.desc()).all()
    
    # Calculate some statistics
    completed_interviews = [i for i in interviews if i.status == 'Completed']
    upcoming_interviews = [i for i in interviews if i.status == 'Upcoming']
    offers = [i for i in interviews if i.status == 'Offered']
    
    avg_performance = 0
    if completed_interviews:
        performances = [i.performance for i in completed_interviews if i.performance]
        if performances:
            avg_performance = sum(performances) / len(performances)
    
    stats = {
        'total': len(interviews),
        'completed': len(completed_interviews),
        'upcoming': len(upcoming_interviews),
        'offers': len(offers),
        'avg_performance': round(avg_performance, 1)
    }
    
    return render_template('dashboard.html', user=user, interviews=interviews, stats=stats)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/dsa')
def dsa():
    return render_template('dsa.html')

@app.route('/more')
def more():
    return render_template('more.html')

@app.route('/interview_progress', methods=['GET', 'POST'])
def interview_progress():
    if 'user_id' not in session:
        flash("Please log in to access interview progress tracking.", "warning")
        return redirect(url_for('login'))
    
    form = InterviewForm()
    if form.validate_on_submit():
        new_interview = Interview(
            company=form.company.data,
            position=form.position.data,
            date=form.date.data,
            notes=form.notes.data,
            status=form.status.data,
            user_id=session['user_id']
        )
        
        if form.status.data == 'Completed':
            new_interview.performance = int(form.performance.data)
        
        db.session.add(new_interview)
        db.session.commit()
        flash("Interview added successfully!", "success")
        return redirect(url_for('interview_progress'))
    
    # Get all interviews for the current user
    interviews = Interview.query.filter_by(user_id=session['user_id']).order_by(Interview.date.desc()).all()
    
    return render_template('interview_progress.html', form=form, interviews=interviews)

@app.route('/edit_interview/<int:id>', methods=['GET', 'POST'])
def edit_interview(id):
    if 'user_id' not in session:
        flash("Please log in to edit interviews.", "warning")
        return redirect(url_for('login'))
    
    interview = Interview.query.get_or_404(id)
    # Make sure the interview belongs to the current user
    if interview.user_id != session['user_id']:
        flash("You do not have permission to edit this interview.", "danger")
        return redirect(url_for('interview_progress'))
    
    form = InterviewForm(obj=interview)
    if form.validate_on_submit():
        interview.company = form.company.data
        interview.position = form.position.data
        interview.date = form.date.data
        interview.notes = form.notes.data
        interview.status = form.status.data
        
        if form.status.data == 'Completed':
            interview.performance = int(form.performance.data)
        
        db.session.commit()
        flash("Interview updated successfully!", "success")
        return redirect(url_for('interview_progress'))
    
    return render_template('edit_interview.html', form=form, interview=interview)

@app.route('/delete_interview/<int:id>', methods=['POST'])
def delete_interview(id):
    if 'user_id' not in session:
        flash("Please log in to delete interviews.", "warning")
        return redirect(url_for('login'))
    
    interview = Interview.query.get_or_404(id)
    # Make sure the interview belongs to the current user
    if interview.user_id != session['user_id']:
        flash("You do not have permission to delete this interview.", "danger")
        return redirect(url_for('interview_progress'))
    
    db.session.delete(interview)
    db.session.commit()
    flash("Interview deleted successfully!", "success")
    return redirect(url_for('interview_progress'))

@app.route('/company_questions', methods=['GET', 'POST'])
def company_questions():
    if 'user_id' not in session:
        flash("Please log in to access company questions.", "warning")
        return redirect(url_for('login'))
    
    form = CompanyQuestionForm()
    if form.validate_on_submit():
        new_question = CompanyQuestion(
            company=form.company.data,
            question=form.question.data,
            category=form.category.data,
            added_by=session['user_id']
        )
        db.session.add(new_question)
        db.session.commit()
        flash("Question added successfully!", "success")
        return redirect(url_for('company_questions'))
    
    # Get distinct companies
    companies = db.session.query(CompanyQuestion.company).distinct().all()
    companies = [c[0] for c in companies]
    
    # Get questions for a specific company if requested
    selected_company = request.args.get('company', '')
    if selected_company:
        questions = CompanyQuestion.query.filter_by(company=selected_company).all()
    else:
        questions = []
    
    return render_template('company_questions.html', form=form, companies=companies, 
                           selected_company=selected_company, questions=questions)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

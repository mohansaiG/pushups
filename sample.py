from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask.globals import request_ctx
from flask_bcrypt import Bcrypt
import bcrypt
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///newsample.db'
app.config['SECRET_KEY'] = "supersecretkey"
db = SQLAlchemy()
bcrypt = Bcrypt(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(240), unique=True)
    name = db.Column(db.String(200))
    password = db.Column(db.String(540))
    workouts = db.relationship('Workout', backref='author', lazy=True)
    
class Workout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pushups = db.Column(db.Integer, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    comment = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


db.init_app(app)

#bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create database within app context
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html',name=current_user.name)


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False
    
    #print(email, password)
    
    
    #password_hash=bcrypt.generate_password_hash(password)
    
    user = User.query.filter_by(email=email).first()
    
    #return "user.password"

    #passwd = password.encode('utf-8')
    
    #hash_pwd = user.password.encode('utf-8')
     
    #is_valid = bcrypt.check_password_hash(user.password, password) 
    #return f"Password: {password}<br>Hashed Password:{user.password}<br>Is Valid: {is_valid}"

    if bcrypt.check_password_hash(user.password, password):
        login_user(user, remember=remember)
        return redirect(url_for('profile'))


    return redirect(url_for('login'))

    
    
    


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    
    
    user = User.query.filter_by(email=email).first()
    
    if user:
       return redirect(url_for('login'))
       
    
    new_user = User(email=email, name=name, password=bcrypt.generate_password_hash(password).decode('utf-8'))

    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/new')
@login_required
def new_workout():
    return render_template('create_workout.html')


@app.route('/new', methods=['POST'])
@login_required
def new_workout_post():
    pushups = request.form.get('pushups')
    comment = request.form.get('comment')

    workout = Workout(pushups=pushups, comment=comment, author=current_user)
    db.session.add(workout)
    db.session.commit()

    flash('Your workout has been added!')

    return redirect(url_for('user_workouts'))

@app.route('/all')
@login_required
def user_workouts():
    user = User.query.filter_by(email=current_user.email).first_or_404()
    workouts = user.workouts
    
    return render_template('all_workouts.html', workouts=workouts, user=user)


@app.route('/workout/<int:workout_id>/update', methods=['GET','POST'])
@login_required
def update_workout(workout_id):
    workout = Workout.query.get_or_404(workout_id)
    if request.method == 'POST':
        workout.pushups = request.form['pushups']
        workout.pushups = request.form['comment']
        db.session.commit()
        flash("info updated")
        return redirect(url_for('user_workouts')) 

    return render_template('update_workout.html', workout=workout)


@app.route('/workout/<int:workout_id>/delete', methods=['GET','POST'])
@login_required
def delete_workout(workout_id):
    workout = Workout.query.get_or_404(workout_id)
    db.session.delete(workout)
    db.session.commit()
    flash("info deleted")
    return redirect(url_for('user_workouts'))


if __name__ == '__main__':
	app.run(debug=True)
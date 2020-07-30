from flask import Flask, render_template, redirect,request, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    scriptures = db.relationship("Scripture", backref="scriptures", lazy=True, cascade="delete")
    
    def __repr__(self):
        return f'User({self.id}: Username:{self.username} Email:{self.email})'
    
# class ScriptureModel(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     book = db.Column(db.String(15))
#     chapter = db.Column(db.String(15))
#     verse = db.Column(db.String(15))
#     passage = db.Column(db.String(200))
    


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=6, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=6, max=80)])
    



@app.route('/')
def index():
    return render_template('index.html')

            

@app.route('/login', methods=['GET', 'POST'])
def login():
    
    form = LoginForm()
    
    
    
    
    print('hi',request.get_json())
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                print('Hello')
                return redirect(url_for('dashboard'))
        else:
            print('here')
            return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    
    return render_template('login.html', form=form)
    

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    print('CU', current_user)
    scriptures = Scripture.query.filter_by(user_id = current_user.id).order_by(Scripture.date_created).all()
    return render_template('dashboard.html', name=current_user.username, scriptures=scriptures)
    


class Scripture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book = db.Column(db.String(200), nullable=False)
    chapter = db.Column(db.String(200), nullable=False)
    verse = db.Column(db.String(200), nullable=False)
    passage = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def __repr__(self):
        return f'Scripture(book = {self.book},chapter = {self.chapter}, verse = {self.verse}, passage = {self.passage})'

@app.route('/scriptures', methods=['POST', 'GET'])
def passage():
    if request.method == 'POST':
        book = request.form['book']
        chapter = request.form['chapter']
        verse = request.form['verse']
        passage = request.form['passage']
        scrip = Scripture(book=book, chapter=chapter, verse=verse, passage=passage, user_id=current_user.id)
        

        try:
            db.session.add(scrip)
            db.session.commit()
            
            return redirect('/dashboard')
        except:
            return 'There was an issue adding your scripture'

    else:
        scriptures = Scripture.query.order_by(Scripture.date_created).all()
        print(scriptures)
        return render_template('dashboard.html', scriptures=scriptures)
    
    
@app.route('/delete/<int:id>')
def delete(id):
    scripture_to_delete = Scripture.query.get_or_404(id)

    try:
        db.session.delete(scripture_to_delete)
        db.session.commit()
        return redirect('/dashboard')
    except:
        return 'There was a problem deleting that scripture'
    
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    scripture = Scripture.query.get_or_404(id)
    print(scripture, id)
    if request.method == 'POST':
        scripture.book = request.form['book']
        scripture.chapter = request.form['chapter']
        scripture.verse = request.form['verse']
        scripture.passage = request.form['passage']
        

        try:
            db.session.commit()
            return redirect('/dashboard')
        except:
            return 'There was an issue updating your task'

    else:
        return render_template('update.html', scripture=scripture)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
    
    
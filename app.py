from flask import Flask, flash, redirect, request, jsonify , render_template , session , url_for
from flask_sqlalchemy import SQLAlchemy 
from datetime import timedelta
from flask_migrate import Migrate
from flask_jwt_extended import (JWTManager,create_access_token, 
jwt_required , create_refresh_token , decode_token
, get_jwt_identity)



app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///parties.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "Alr3doi-110com" 
db = SQLAlchemy(app)

migrate = Migrate(app , db)
app.config["JWT_SECRET_KEY"] = "super-secret110" 
jwt = JWTManager(app)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)

class Party(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hall = db.Column(db.String(100))
    location = db.Column(db.String(100))
    members = db.Column(db.Integer)
    members_names = db.Column(db.String(300))
    salary = db.Column(db.Integer)
    date = db.Column(db.String(20))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    birthdate = db.Column(db.String(20), nullable=False)
    parties = db.relationship('Party', backref='user', lazy=True)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

with app.app_context():
    db.create_all()

@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form        
        username = data.get('username')
        password = data.get('password')
        print(password)
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            
            session.pop('token' , None)
            session['user_id'] = user.id
            token = create_access_token(identity=user.username)
            refresh_token = create_refresh_token(identity=user.username)

            session['token'] = token
            session['refresh_token'] = refresh_token
            session['username'] = username
            return redirect('/')
        else:
            flash({'message': 'Invalid credentials!'})
            return render_template('/auth/login.html')

    return render_template('/auth/login.html')

@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form.get('username') : 
            username = request.form.get('username')
            password = request.form.get('password')
            password2 = request.form.get('password2')
            birth = request.form.get('birthdate')
            if password != password2 :
                flash('Passwords do not match!')
                return redirect('/auth/register')
            if User.query.filter_by(username=username).first():
                return jsonify({'message': 'Username already exists!'}), 400
            else:
                new_user = User(username=username, birthdate=birth)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                return redirect('/auth/login')
        
    return render_template('/auth/register.html')

@app.route("/auth/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    user = session.get("username") 
    return render_template('index.html' ,user=user ) if  user else  redirect(url_for('login'))
    
@app.route('/kg-lb', methods=['GET', 'POST'])
def kg_lb():  
    if request.method == 'POST':
        num_kglb = request.form.get('kg-lb')
        what = request.form.get('what')
        if num_kglb:
            if what == "kg-to-lb":
                num_kglb = float(num_kglb) * 2.20462
            elif what == "lb-to-kg":
                num_kglb = float(num_kglb) / 2.20462
        return render_template('kg-lb.html', num_kglb=num_kglb )
    return render_template('kg-lb.html' ) 

@app.route('/parties', methods=['GET', 'POST' ])
def manage_parties():
    user_id = session.get('user_id')
    if request.method == 'GET':
        y = request.args.get('year')
        parties = Party.query.filter_by(user_id=user_id).all()
        numOFparty = len(parties)
        return render_template('parties.html',  parties=parties , y=y, numOFparty=numOFparty) 
    if request.method == 'POST':
        token = request.form.get('token')
        data = request.get_json() if request.is_json else request.form
        if data.get("hall") :
            party = Party(
            hall=data.get("hall"),
            location=data.get("location"),
            members=data.get("members"),
            salary=data.get("salary"),
            date=data.get("date"),
            members_names=data.get("members_names"),
            user_id=session.get('user_id')
        )
            db.session.add(party)
            db.session.commit()
           
        return redirect("/parties" )  
    return redirect('/crateparty' )
@app.route('/parties/<int:id>', methods=['POST'])
def Deleteparty(id):
    if request.method == 'POST' and id :
        party = Party.query.get(id)
        if party:
            db.session.delete(party)
            db.session.commit()
            flash(party.hall , "has been deleted!")
            return redirect("/parties")
        else:
            return jsonify({"message": "Party not found!"}), 404

@app.route('/createparty')
def crateparty():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    decoded = decode_token(token)
    user_identity = decoded['sub']  

    return render_template('createparty.html', token=token, user=user_identity)

@app.route('/updateparty/<int:id>', methods=['GET', 'POST'])
def updateparty(id):
    party = Party.query.get(id)
    if request.method == 'GET':
        return render_template('updateparty.html', party=party)
    if request.method == 'POST':
        data = request.form
        if data : 
            party.hall = data.get("hall")
            party.location = data.get("location")
            party.members = data.get("members")
            party.salary = data.get("salary")
            party.date = data.get("date")
            party.user_id = session.get('user_id')
            db.session.commit()
            return redirect("/parties")
    return render_template('updateparty.html', party=party)

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == "__main__":
    app.run(debug=True)

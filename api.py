from flask import Flask, request, jsonify, make_response, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import subprocess
import click
from flask.cli import with_appcontext
import sys
import os
from werkzeug.utils import secure_filename
from rq.job import Job
from worker import conn
from sqlalchemy.orm import relationship
from rq import Worker, Queue, Connection
import redis
app = Flask(__name__, instance_path='/home/kamila/Pulpit/AIIR/backend')
CORS(app)

UPLOAD_FOLDER = '//home/kamila/Pulpit/AIIR/backend/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif','tsp','atsp'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///home/kamila/Pulpit/AIIR/backend/todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REDIS_URL'] = os.getenv('REDISTOGO_URL', 'redis://localhost:6379')
db = SQLAlchemy(app)
q = Queue(connection=conn, name='waiting_tasks')#, is_async=False)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


'''
class Result(db.Model):
    __tablename__ = 'result'
    id = db.Column(db.Integer, primary_key=True)
    cost = db.Column(db.Integer)
    tsp_path = db.Column(db.String(2000)) #wypisane miasta w kolejnosci odwiedzania?
    # można dołożyć pole task, jeśli chcemy mieć relację w obie strony

class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    user = relationship("User")
    result = relationship("Result") 
    completed = db.Column(db.Boolean)
'''

#odpalanie z konsoli: flask run_worker albo "ogólnie" rqworker waiting_tasks
@click.command('run_worker')
@with_appcontext 
def run_worker():
    print("aaaaaaaa", file=sys.stdout)
    redis_url = app.config['REDIS_URL']
    redis_connection = redis.from_url(redis_url)
    with Connection(redis_connection):
        worker = Worker('waiting_tasks')
        worker.work()

app.cli.add_command(run_worker)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Brak tokena'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Zły token'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Nie jesteś adminem, nie możesz tego wykonać'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Nie jesteś adminem, nie możesz tego wykonać'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'Nie znaleziono użytkownika'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Nie jesteś adminem, nie możesz tego wykonać'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'Nie znaleziono użytkownika'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'Zmieniono uprawnienia na admina'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Nie jesteś adminem, nie możesz tego wykonać'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'Nie znaleziono użytkownika'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'Usunięto użytkownika'})

#głupie funkcje testujące wywołanie zwykłego programu i kolejkowanie zadań
@app.route('/koty/')
def koty():
    aaa="/home/kamila/Pulpit/AIIR/backend/hello1 20 koty"# > /home/kamila/Pulpit/AIIR/backend/koty.txt"
    os.system(aaa)
    pass
    #return jsonify({'message' : 'Koty sa mile'})

@app.route('/piesy/')
def piesy():
    print('AAA', file=sys.stdout)
    aaa="/home/kamila/Pulpit/AIIR/backend/hello1 20 piesy"
    os.system(aaa)
    return jsonify({'message' : 'Piesy sa mile'})

@app.route('/razem/')
def razem():
    
    q.enqueue_call(
            func=piesy
        )
    #dane są dodawane do bazy od razu po zakolejkowaniu zadania - można dodać taska "completed=False"
    hashed_password = generate_password_hash('aaa', method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name='KOTY888', password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'Razem sa mile'})

#właściwa funkcja do zlecenia obliczeń
@app.route('/startCalc', methods=['POST'])
@token_required
def start_calc(current_user):
    target=os.path.join(UPLOAD_FOLDER,'test_docs')
    if not os.path.isdir(target):
        os.mkdir(target)
    file = request.files['file'] 
    print(file)
    filename = secure_filename(file.filename)
    destination = "/".join([target, filename])
    file.save(destination)
    session['uploadFilePath'] = destination
    n = session['uploadFilePath'] #Sciezka do pliku
    new_task = Task(user=current_user, completed=False)
    db.session.add(new_task)
    db.session.commit()
    q.enqueue_call(
            func=mpi, args=(n, new_task)
        )
    return jsonify({'message' : 'Rozpoczęto obliczenia'})

def mpi(n, task):
    #myCMD = 'mpirun -n 2 /home/lukasz/MPITest 1 ' #ta będzie docelowo
    myCMD = '/home/kamila/Pulpit/AIIR/backend/hello1 20 piesy' 
    out = ' > out.txt'
    #cmd = myCMD + n + out
    cmd = myCMD + out
    os.system(cmd)
    print(cmd)
    f = open("out.txt","r")

    contents = f.read()
    print(contents)
    f.close()
    
    new_result = Result(cost=-1, tsp_path='brak danych')
    task.completed = True
    result.tsp_path = contents
    task.result = new_result
    db.session.commit()

    return jsonify({'result' : str(contents)}) 

'''def connect():
    HOST="lukasz@192.168.0.110"
    data = request.get_json()
    n = data['problem_name']
    COMMAND="mpirun -n 2 MPITest 0"
    command2 = COMMAND + n
    ssh = subprocess.Popen(["ssh", "%s" % HOST, command2],
                       shell=False,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    result = ssh.stdout.readlines()
    if result == []:
        error = ssh.stderr.readlines()
    #print >>sys.stderr, "ERROR: %s" % error
    else:
        print (result)
'''
@app.route('/user/register', methods=['POST'])
# @token_required
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['username'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'Stworzono użytkownika!'})

@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    data = request.get_json()

    user = User.query.filter_by(name=data['username']).first()

    if check_password_hash(user.password, data['password']):
        return jsonify({'message' : 'Zalogowano użytkownika'})
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Wymagany login"'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

from flask import Flask, request
import signal
from flask_cors import CORS
from celery import Celery
from .auth import AuthGuard, REFRESH_TOKEN_KEY
from gevent import monkey
from gevent.pywsgi import WSGIServer
import json

monkey.patch_all()

app = Flask(__name__)
CORS(app)

rabbit = Celery("tasks", backend='rpc://',
                    broker='amqp://guest:guest@35.196.180.90:5672', queue="celery")


rabbit.conf.task_routes = {
    'user.tasks.*': {'queue': 'user'},
    'simulation.tasks.*': {'queue': 'simulation'},
}

rabbit.conf.task_default_queue = 'default'
rabbit.conf.task_queues = (
    Queue('user', routing_key='user.tasks.#'),
    Queue('simulation', routing_key='simulation.tasks.#'),
    Queue('analysis', routing_key='analysis.tasks.#'),
)

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=8080)


@app.route('/<user_id>/teleportation/<measurements>', methods=['GET'])
def teleportation(user_id, measurements):
    
    results = []
    for i in range(measurements):
        results.append(rabbit.send_task('simulation.tasks.teleportation', args=[user_id]).wait())
    
    return json.dumps(results)


@app.route('/auth', methods=['POST', 'PUT'])
def auth():
    if request.method == 'POST':

        data = json.loads(request.data)[0]

        username = data['name']
        password = data['password']
        user = rabbit.send_task('user.tasks.login_user', args=[username, password], queue='user').wait()
        if user is not None:
            return json.dumps(AuthGuard.auth_response(user))
        else:
            abort(403)

    elif request.method == 'PUT':

        data = json.loads(request.data)[0]
        expired_auth_token = get_auth_token(request)

        try:

            if REFRESH_TOKEN_KEY in data:
                refresh_token = data[REFRESH_TOKEN_KEY]
            else:
                raise InvalidTokenError

            decoded_auth_token = AuthGuard.decode_token(expired_auth_token)
            decoded_refresh_token = AuthGuard.decode_token(refresh_token)

            user_id = str(decoded_auth_token['id'])
            user = rabbit.send_task('user.tasks.get_user', args=[user_id], queue='user').wait()

            if user is not None:
                return json.dumps(AuthGuard.auth_response(user))
            else:
                abort(403)

        except (InvalidTokenError, ExpiredSignatureError) as ex:
            abort(401)


@app.route('/user', methods=['GET', 'POST', 'PUT'])
def users():

    if request.method == 'GET':
        return rabbit.send_task('tasks.list_users', args=[request.args]).wait()

    elif request.method == 'POST':
        return rabbit.send_task('tasks.create_users', args=[request.data]).wait()

    elif request.method == 'PUT':
        return rabbit.send_task('tasks.update_users', args=[request.data]).wait()


@app.route('/user/<id>', methods=['GET'])
def get_user(id):

    if request.method == 'GET':
        return rabbit.send_task('tasks.get_user', args=[id]).wait()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, _signal_handler)
    http_server = WSGIServer(('localhost', 5000), app.wsgi_app)
    http_server.serve_forever()
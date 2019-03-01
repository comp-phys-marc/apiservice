import json
import signal
from flask import Flask, request, abort
from flask_cors import CORS
from kombu import Queue
from auth import AuthGuard, REFRESH_TOKEN_KEY, TOKEN_KEY
from gevent import monkey
from gevent.pywsgi import WSGIServer
from settings import Settings
from emulatorcommon.message_bus import MessageBus

monkey.patch_all()

app = Flask(__name__)
CORS(app)

settings = Settings()

bus = MessageBus(settings)
rabbit = bus.connection


rabbit.conf.task_routes = {
    'user.tasks.*': {'queue': 'user'},
    'simulation.tasks.*': {'queue': 'simulation'},
    'analysis.tasks.*': {'queue': 'analysis'},
}

rabbit.conf.task_default_queue = 'default'
rabbit.conf.task_queues = (
    Queue('user', routing_key='user.tasks.#'),
    Queue('simulation', routing_key='simulation.tasks.#'),
    Queue('analysis', routing_key='analysis.tasks.#'),
)


@app.route('/auth', methods=['POST', 'PUT'])
def auth():
    if request.method == 'POST':

        print(str(request.data))

        data = json.loads(str(request.data))

        username = data['name']
        password = data['password']
        response = rabbit.send_task('user.tasks.login_user', args=[username, password], queue='user').wait()

        if 'data' in response.keys():
            user = response['data']
            return json.dumps(AuthGuard.auth_response(user))
        else:
            return json.dumps(response)

    elif request.method == 'PUT':

        data = json.loads(str(request.data))
        expired_auth_token = data[TOKEN_KEY]

        try:

            if REFRESH_TOKEN_KEY in data:
                refresh_token = data[REFRESH_TOKEN_KEY]
            else:
                raise Exception

            decoded_auth_token = AuthGuard.decode_token(expired_auth_token)
            decoded_refresh_token = AuthGuard.decode_token(refresh_token)

            user_id = str(decoded_auth_token['id'])
            user = rabbit.send_task('user.tasks.get_user', args=[user_id], queue='user').wait()

            if user is not None:
                return json.dumps(AuthGuard.auth_response(user))
            else:
                abort(403)

        except Exception as ex:
            abort(401)


@app.route('/user', methods=['GET', 'POST', 'PUT'])
def user():

    data = json.loads(request.data)
    response = None

    if request.method == 'GET':
        response = rabbit.send_task('user.tasks.list_users', args=[data]).wait()

    elif request.method == 'POST':
        response = rabbit.send_task('user.tasks.create_user', args=[data]).wait()

    elif request.method == 'PUT':
        response = rabbit.send_task('user.tasks.update_user', args=[data]).wait()

    return json.dumps(response)


@app.route('/simulate', methods=['POST'])
def simulate():

    data = json.loads(request.data)

    if 'code' not in data or 'name' not in data:
        abort(400)

    try:
        user_id = AuthGuard.authenticate(data)

    except Exception as ex:
        abort(401)

    response = rabbit.send_task('simulation.tasks.execute',
                                args=[user_id, data['code'], data['name']],
                                queue='simulation').wait()

    if response is not None:
        return json.dumps(response)
    else:
        abort(403)


@app.route('/user/<id>', methods=['GET'])
def get_user(id):

    if request.method == 'GET':
        return rabbit.send_task('tasks.get_user', args=[id]).wait()


def _signal_handler(param1, param2):
    exit()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, _signal_handler)
    http_server = WSGIServer(('0.0.0.0', 5000), app.wsgi_app)
    http_server.serve_forever()

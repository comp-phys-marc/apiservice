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

    data = json.loads(request.data.decode("utf-8"))

    if request.method == 'POST':

        response, status = new_auth_response(data)
        return response, status

    elif request.method == 'PUT':

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
                return json.dumps(AuthGuard.auth_response(user)), 200
            else:
                abort(403)

        except Exception as ex:
            abort(401)


@app.route('/user', methods=['GET', 'POST', 'PUT'])
def user():

    data = json.loads(request.data.decode("utf-8"))
    user = None

    if request.method == 'GET':
        response = rabbit.send_task('user.tasks.list_users', args=[data]).wait()

    elif request.method == 'POST':
        user_response = rabbit.send_task('user.tasks.create_user', args=[data]).wait()

        if user_response['status'] == 200:
            response, status = new_auth_response(data)
            return response, status

        else:
            return json.dumps(user_response), user_response['status']

    elif request.method == 'PUT':
        response = rabbit.send_task('user.tasks.update_user', args=[data]).wait()

    return json.dumps(response), response['status']


@app.route('/simulate', methods=['POST'])
def simulate():

    data = json.loads(request.data.decode("utf-8"))

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
        return json.dumps(response), response['status']
    else:
        abort(403)


@app.route('/user/<id>', methods=['GET'])
def get_user(id):

    if request.method == 'GET':
        return rabbit.send_task('user.tasks.get_user', args=[id]).wait()


def new_auth_response(user_data):
    username = user_data['name']
    password = user_data['password']
    response = rabbit.send_task('user.tasks.login_user', args=[username, password], queue='user').wait()

    if 'data' in response.keys():
        user = response['data']
        return json.dumps(AuthGuard.auth_response(user)), response['status']
    else:
        return json.dumps(response), response['status']


def _signal_handler(param1, param2):
    exit()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, _signal_handler)
    http_server = WSGIServer(('0.0.0.0', 5000), app.wsgi_app)
    http_server.serve_forever()

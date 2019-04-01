import json
import signal
import sys
from flask import Flask, request, abort
from flask_cors import CORS
from kombu import Queue
from auth import AuthGuard, REFRESH_TOKEN_KEY, TOKEN_KEY, ExpiredSignatureError
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

        old_auth_token = data[TOKEN_KEY]

        try:

            if REFRESH_TOKEN_KEY in data:
                refresh_token = data[REFRESH_TOKEN_KEY]
            else:
                raise Exception

            decoded_auth_token = AuthGuard.decode_token(old_auth_token)

            try:
                AuthGuard.check_token_expired(old_auth_token)

            except ExpiredSignatureError:

                decoded_refresh_token = AuthGuard.decode_token(refresh_token)

                if not decoded_refresh_token[TOKEN_KEY] == old_auth_token \
                        or AuthGuard.check_token_expired(refresh_token):
                    raise Exception

            user_id = str(decoded_auth_token['id'])
            user = rabbit.send_task('user.tasks.get_user', args=[user_id], queue='user').wait()

            if user is not None:
                return json.dumps(AuthGuard.auth_response(user['data'])), 200
            else:
                abort(403)

        except Exception as ex:
            print(str(ex))
            abort(401)


@app.route('/user', methods=['POST', 'PUT'])
def user():

    data = json.loads(request.data.decode("utf-8"))
    response = None

    if request.method == 'POST':
        user_response = rabbit.send_task('user.tasks.create_user', args=[data]).wait()

        if user_response['status'] == 200:
            response, status = new_auth_response(data)
            return response, status

        else:
            return json.dumps(user_response), user_response['status']

    elif request.method == 'PUT':
        response = rabbit.send_task('user.tasks.update_user', args=[data]).wait()

    return json.dumps(response), response['status']


@app.route('/experiments', methods=['POST'])
def list_experiments():

    data = json.loads(request.data.decode("utf-8"))
    user_id = None

    if 'user_id' not in data:
        abort(400)

    try:
        user_id = AuthGuard.authenticate(data)

    except Exception as ex:
        abort(401)

    response = retry_if_necessary('simulation.tasks.list_experiments',
                                args=[{"user_id": user_id}],
                                queue='simulation')

    if response is not None:
        return json.dumps(response), response['status']
    else:
        abort(403)


@app.route('/executions', methods=['POST'])
def list_executions():

    data = json.loads(request.data.decode("utf-8"))
    user_id = None

    if 'user_id' not in data or 'experiment_id' not in data:
        abort(400)

    try:
        user_id = AuthGuard.authenticate(data)

    except Exception as ex:
        abort(401)

    execution_id = data['execution_id']

    response = retry_if_necessary('simulation.tasks.list_executions',
                                args=[{"user_id": user_id, "execution_id": execution_id}],
                                queue='simulation')

    if response is not None:
        return json.dumps(response), response['status']
    else:
        abort(403)


@app.route('/experiments/create', methods=['POST'])
def create_experiment():

    data = json.loads(request.data.decode("utf-8"))
    user_id = None

    if 'user_id' not in data:
        abort(400)

    try:
        user_id = AuthGuard.authenticate(data)

    except Exception as ex:
        abort(401)

    response = retry_if_necessary('simulation.tasks.create_experiment',
                                args=[user_id, data['name'], data['type'], data['qubits'], data['emulatorId']],
                                queue='simulation')

    if response is not None:
        return json.dumps(response), response['status']
    else:
        abort(403)


@app.route('/experiments/update', methods=['POST'])
def update_experiment():

    data = json.loads(request.data.decode("utf-8"))

    if 'id' not in data or 'code' not in data:
        abort(400)

    try:
        AuthGuard.authenticate(data)

    except Exception as ex:
        abort(401)

    response = retry_if_necessary('simulation.tasks.update_experiment_code',
                                args=[data['id'], data['code']],
                                queue='simulation')

    if response is not None:
        return json.dumps(response), response['status']
    else:
        abort(403)


@app.route('/simulate', methods=['POST'])
def simulate():

    data = json.loads(request.data.decode("utf-8"))
    user_id = None

    if 'code' not in data or 'name' not in data:
        abort(400)

    try:
        user_id = AuthGuard.authenticate(data)

    except Exception as ex:
        abort(401)

    response = retry_if_necessary('simulation.tasks.execute',
                                args=[user_id, data['code'], data['name'], data['experiment_id'], data['execution_type']],
                                queue='simulation')

    if response is not None:
        return json.dumps(response), response['status']
    else:
        abort(403)


def retry_if_necessary(task, args, queue, retries=1):
    attempts = 0
    response = rabbit.send_task(task, args=args, queue=queue).wait()

    if response['status'] == 500:
        print('Error occurred: {}'.format(response['message']), sys.stderr)
        print('Attempting retry {} of {}'.format(attempts, retries), sys.stderr)
        while attempts < retries:
            response = rabbit.send_task(task, args=args, queue=queue).wait()
            attempts += 1

    return response


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

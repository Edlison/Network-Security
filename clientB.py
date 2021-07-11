# @Author  : Edlison
# @Date    : 7/5/21 11:07
from flask import Flask, request, render_template, send_from_directory
from flask_socketio import SocketIO, emit
from Crypto.Cipher import AES
import json
import base64
import rsa
import os
import requests

app = Flask(__name__)
socketio = SocketIO(app)
AES_key = b'abcdefghabcdefgh'
ClientA_url = 'http://0.0.0.0:5001'


@app.route('/')
def index():
    return render_template('ClientB/index.html')


@app.route('/ftp', methods=['GET'])
def ftp():
    return render_template('ClientB/Login.html')


@app.route('/ftp/login', methods=['POST'])
def login():
    data = request.get_data()
    data = json.loads(data)
    username = data['username']
    password = data['password']
    print('usr ', username)
    print('pwd ', password)
    if username == 'admin' and password == '123123':
        return {'code': 0, 'desc': 'success'}
    return {'code': 1, 'desc': 'fail'}


@app.route('/ftp/download')
def download():
    path_cur = os.getcwd()
    path_ftp = os.getcwd() + '/ftp'
    os.chdir(path_ftp)
    file_list = os.listdir()
    os.chdir(path_cur)
    return render_template('ClientB/Download.html', file_list=file_list)


@app.route('/ftp/download/<filename>')
def download_file(filename):
    return send_from_directory('ftp', filename)


@app.route('/chat')
def chat():
    return render_template('ClientB/chat.html')


@socketio.on('connect', namespace='/chatroom')
def connect_chatroom(message):
    print('connect ', message)
    emit('show event', 'server connected.')


@app.route('/send', methods=['POST'])
def send():
    data = request.get_data()
    data = json.loads(data)
    resp = {
        'data': data['msg']
    }
    socketio.emit('show event', resp, namespace='/chatroom')
    clientA = ClientB(AES_key=AES_key, gen_rsa=False)
    data = clientA.encrypt_msg(data['msg'])
    resp = requests.post(ClientA_url + '/receive', json=data)
    print(resp)
    return 'success'


@app.route('/receive', methods=['POST'])
def receive():
    data = request.get_data()
    data = json.loads(data)
    print(data)
    clientA = ClientB(AES_key=AES_key, gen_rsa=False)
    de_msg = clientA.decrypt_msg(data['msg'], data['sign'])
    resp = {
        'data': de_msg
    }
    socketio.emit('show event', resp, namespace='/chatroom')
    return 'success'


@app.route('/file_send', methods=['POST'])
def upload():
    file = request.files.get('send_file')
    file_byte = file.read()
    file = file_byte.decode('utf-8').strip()
    print('file ', file)
    resp = {
        'data': file
    }
    socketio.emit('file event', resp, namespace='/chatroom')
    clientA = ClientB(AES_key=AES_key, gen_rsa=False)
    data = clientA.encrypt_msg(file)
    print(data)
    resp = requests.post(ClientA_url + '/file_receive', json=data)
    print(resp)
    return 'success'


@app.route('/file_receive', methods=['POST'])
def file_receive():
    data = request.get_data()
    data = json.loads(data)
    clientA = ClientB(AES_key=AES_key, gen_rsa=False)
    de_msg = clientA.decrypt_msg(data['msg'], data['sign'])
    resp = {
        'data': de_msg
    }
    socketio.emit('file event', resp, namespace='/chatroom')
    return 'success'


class ClientB:
    def __init__(self, AES_key, gen_rsa=False):
        self.aes = AES.new(AES_key)
        if gen_rsa:
            publicKey, privateKey = rsa.newkeys(nbits=512)
            self.publicKey = publicKey
            self.privateKey = privateKey
            self._store_key()
        else:
            self.publicKey, self.privateKey = self._load_key()

    def _store_key(self):
        with open('./key/public_key', 'wb') as f:
            f.write(self.publicKey.save_pkcs1())
        with open('./key/private_key', 'wb') as f:
            f.write(self.privateKey.save_pkcs1())

    def _load_key(self):
        with open('./key/public_key', 'rb') as f:
            publicKey = f.read()
        publicKey = rsa.PublicKey.load_pkcs1(publicKey)
        with open('./key/private_key', 'rb') as f:
            privateKey = f.read()
        privateKey = rsa.PrivateKey.load_pkcs1(privateKey)
        return publicKey, privateKey

    def encrypt_msg(self, msg: str):
        # 签名
        sign = rsa.sign(msg.encode('utf-8'), self.privateKey, hash_method='MD5')

        # 加密
        msg = msg.encode('utf-8')
        en_msg = self.aes.encrypt(self._to_16_bytes(msg))
        en_sign = self.aes.encrypt(self._to_16_bytes(sign))

        data = {
            'msg': str(base64.b64encode(en_msg), encoding='utf-8'),
            'sign': str(base64.b64encode(en_sign), encoding='utf-8')
        }

        return data

    def decrypt_msg(self, msg: str, sign: str):
        msg = base64.b64decode(msg)
        sign = base64.b64decode(sign)
        de_msg = self.aes.decrypt(msg)
        de_sign = self.aes.decrypt(sign)
        de_msg = de_msg.decode('utf-8').strip()
        hash_val = self._validate(de_msg, de_sign)

        print('de_msg ', de_msg)
        print('de_sign ', de_sign)
        print('is_val ', hash_val)
        return de_msg

    def _validate(self, msg: str, sign: bytes):
        hash_val = rsa.verify(msg.encode('utf-8'), sign, self.publicKey)
        return hash_val

    def _to_16_bytes(self, data):
        while len(data) % 16 != 0:
            data += b' '
        return data


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5002)
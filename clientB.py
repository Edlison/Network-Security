# @Author  : Edlison
# @Date    : 7/5/21 11:07
from flask import Flask, request, render_template, send_from_directory
from hashlib import md5
import json
import base64
import rsa
import os

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('ClientB.html')


@app.route('/ftp', methods=['GET'])
def ftp():
    return render_template('Login.html')


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
    return render_template('Download.html', file_list=file_list)


@app.route('/ftp/download/<filename>')
def download_file(filename):
    return send_from_directory('ftp', filename)


@app.route('/message/receive', methods=['POST'])
def receive():
    client_B = ClientB()
    data = request.get_data()
    data = json.loads(data)
    en_msg = data['msg']
    sign = data['sign']
    de_msg = client_B.decode(en_msg)
    is_val = client_B.validate(de_msg, sign)
    print('receive successfully msg: {}, validation: {}'.format(de_msg, is_val))
    return {
        'code': 0,
        'data': {
            'en_msg': en_msg,
            'de_msg': de_msg,
            'is_val': is_val
        }
    }


class ClientB:
    def __init__(self):
        self.privateKey = self._load_privateKey()

    def _load_privateKey(self):
        with open('./key/private_key', 'rb') as f:
            privateKey = f.read()
        privateKey = rsa.PrivateKey.load_pkcs1(privateKey)
        return privateKey

    def decode(self, en_msg: str):
        en_msg = base64.b64decode(en_msg)
        de_msg = rsa.decrypt(en_msg, self.privateKey)
        return de_msg.decode()

    def validate(self, de_msg: str, sign: str):
        sign_val = md5(de_msg.encode('utf-8')).hexdigest()
        return sign == sign_val


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)
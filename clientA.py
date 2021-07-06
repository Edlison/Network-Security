# @Author  : Edlison
# @Date    : 7/5/21 10:58
# -*- coding:utf-8 -*-
from flask import Flask, request, render_template
from hashlib import md5
import json
import base64
import requests
import rsa

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('ClientA.html')


@app.route('/send', methods=['POST'])
def send():
    client_B_url = 'http://127.0.0.1:5002/message/receive'
    data = request.get_data()
    data = json.loads(data)
    msg = data['msg']
    # msg = 'This is a msg sent by client A.'  # TODO 可以输入
    client_A = ClientA()
    resp = client_A.send_msg(client_B_url, msg)
    resp_content = json.loads(resp.content)
    print(resp_content)
    en_msg = resp_content['data']['en_msg']
    de_msg = resp_content['data']['de_msg']
    is_val = resp_content['data']['is_val']
    return {
        'code': 0,
        'data': {
            'en_msg': en_msg,
            'de_msg': de_msg,
            'is_val': is_val
        }
    }


class ClientA:
    def __init__(self):
        publicKey, privateKey = rsa.newkeys(nbits=512)
        self.publicKey = publicKey
        self.privateKey = privateKey
        self._store_privateKey()

    def _store_privateKey(self):
        with open('./key/private_key', 'wb') as f:
            f.write(self.privateKey.save_pkcs1())

    def send_msg(self, other_url: str, msg: str):
        signature = md5(msg.encode('utf-8')).hexdigest()
        en_msg = rsa.encrypt(msg.encode('utf-8'), self.publicKey)
        en_msg = str(base64.b64encode(en_msg), encoding='utf-8')
        data = {
            'msg': en_msg,
            'sign': signature
        }
        header = {'Content-Type': 'json'}
        resp = requests.post(other_url, json=data, headers=header)
        return resp


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
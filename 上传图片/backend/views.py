import ast
import json
import time
import hmac
import base64
import datetime
import urllib.request
from hashlib import sha1 as sha
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny

assess_key = 'LTAIiJXQPs1jekEE'
secret_key = 'YJNqIZSyPnfk2za3HbuSJSRsDFFlit'

callback_url = "http://60.205.179.20/upload/"
host = 'http://zzm-oss2.oss-cn-beijing.aliyuncs.com'

upload_dir = 'user-dir-prefix/'
expire_time = 30


def get_iso_8601(expire):
    gmt = datetime.datetime.utcfromtimestamp(expire).isoformat()
    gmt += 'Z'
    return gmt


def get_token():
    now = int(time.time())
    expire_syncpoint = now + expire_time
    # expire_syncpoint = 1612345678
    expire = get_iso_8601(expire_syncpoint)

    policy_dict = {}
    policy_dict['expiration'] = expire
    condition_array = []
    array_item = []
    array_item.append('starts-with');
    array_item.append('$key');
    array_item.append(upload_dir);
    condition_array.append(array_item)
    policy_dict['conditions'] = condition_array
    policy = json.dumps(policy_dict).strip()
    policy_encode = base64.b64encode(policy.encode())
    h = hmac.new(secret_key.encode(), policy_encode, sha)
    sign_result = base64.encodebytes(h.digest()).strip()

    callback_dict = {}
    callback_dict['callbackUrl'] = callback_url;
    callback_dict['callbackBody'] = 'filename=${object}&size=${size}&mimeType=${mimeType}' \
                                    '&height=${imageInfo.height}&width=${imageInfo.width}';
    callback_dict['callbackBodyType'] = 'application/x-www-form-urlencoded';
    callback_param = json.dumps(callback_dict).strip()
    base64_callback_body = base64.b64encode(callback_param.encode());

    token_dict = {}
    token_dict['accessid'] = assess_key
    token_dict['host'] = host
    token_dict['policy'] = policy_encode.decode()
    token_dict['signature'] = sign_result.decode()
    token_dict['expire'] = expire_syncpoint
    token_dict['dir'] = upload_dir
    token_dict['callback'] = base64_callback_body.decode()
    result = json.dumps(token_dict)
    return result


def verrify(auth_str, authorization_base64, pub_key):
    """
    校验签名是否正确（MD5 + RAS）
    :param auth_str: 文本信息
    :param authorization_base64: 签名信息
    :param pub_key: 公钥
    :return: 若签名验证正确返回 True 否则返回 False
    """
    pub_key_load = RSA.importKey(pub_key)
    auth_md5 = MD5.new(auth_str.encode())
    try:
        result = PKCS1_v1_5.new(pub_key_load).verify(auth_md5, base64.b64decode(authorization_base64.encode()))
    except Exception as e:
        print(e)
        result = False
    return result


def get_pub_key(pub_key_url_base64):
    """ 抽取出 public key 公钥 """
    pub_key_url = base64.b64decode(pub_key_url_base64.encode())
    url_reader = urllib.request.urlopen(pub_key_url.decode())
    pub_key = url_reader.read()
    return pub_key


def parse_post(request):
    headers = request.META

    try:
        pub_key_url_base64 = headers['HTTP_X_OSS_PUB_KEY_URL']
        pub_key = get_pub_key(pub_key_url_base64)
    except Exception as e:
        print(str(e))
        return

    # get authorization
    authorization_base64 = headers['HTTP_AUTHORIZATION']
    print(authorization_base64)

    # get callback body
    callback_body = request.body.decode('utf-8')
    print(callback_body)

    # compose authorization string
    path = request.path
    auth_str = path + '\n' + callback_body

    result = verrify(auth_str, authorization_base64, pub_key)

    if not result:
        return False
    return True


class AliyunUploadView(APIView):
    """阿里云上传文件"""
    permission_classes = (AllowAny,)

    def get(self, request):
        res = get_token()
        headers = {
            'Access-Control-Allow-Methods': 'POST',
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'text/html; charset=UTF-8'
        }
        return Response(ast.literal_eval(res), status=status.HTTP_200_OK, headers=headers)

    def post(self, request):
        r = parse_post(request)
        print(r)
        return Response({'Status': 'OK'}, status=status.HTTP_200_OK)

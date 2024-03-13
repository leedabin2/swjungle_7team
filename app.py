import datetime
from flask import Flask, render_template, request, redirect, jsonify, session
from settings import ca_path
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from pymongo import MongoClient
import xml.etree.ElementTree as elemTree
import certifi,hashlib
import requests

app = Flask(__name__)
jwt = JWTManager(app)

tree = elemTree.parse('keys.xml')
secretkey = tree.find('string[@name="secret_key"]').text

app.config['SECRET_KEY'] = secretkey

ca = certifi.where()
client = MongoClient(ca_path, tlsCAFile=ca)
db = client.dbsparta
# 사용자 로그인 상태 확인을 위한 함수
def is_user_authenticated():
    return 'access_token' in session
@app.route('/')
def home():
   print(is_user_authenticated())
   return render_template('index.html', authenticated=is_user_authenticated())

# 회원가입
@app.route('/signup', methods=['GET','POST'])
def register():
    if request.method == 'POST':
      # 회원가입
      username_receive = request.form['username_give']
      password_receive = request.form['password_give']
      
      # 비밀번화 암호화
      password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
      
      # 회원 정보 
      userinfo = {'username': username_receive, 'password': password_hash}
      
      # db에 저장
      db.users.insert_one(userinfo)
      return jsonify({'result':'success'})
    else:
      return render_template('signup.html') 
      
# 로그인
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
      username_receive = request.json.get('username_input')
      password_receive = request.json.get('password_input')
   
      password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
      
      # 유효한 데이터 찾기 (db에 없을시에 클라이언트에 에러 반환)
      find_user_data = db.users.find_one({'username' : username_receive, 'password' : password_hash})
      
      if find_user_data is None:
         return jsonify({'result':'error','msg': '인증 실패'}),401
      # jwt 토큰 발급 (유효기간 30분)
      expires_delta = datetime.timedelta(minutes=30)
      access_token = create_access_token(identity=username_receive, expires_delta=expires_delta)
      # 클라이언트에 200과 함께 토큰 전송
      return jsonify({'result': 'success', 'access_token': access_token}), 200
    else:
        # GET 요청을 처리하기 위한 로직 추가
      return render_template('login.html') 
    
client_id = 'qwYeDHfb22N5SlsoHEvL'
client_secret = '1IhM71SEUT'

@app.route('/v1/search/local', methods=['GET'])
def search_local():
    # 요청 헤더에서 클라이언트 아이디와 클라이언트 시크릿을 가져옵니다.
    client_id = request.headers.get('X-Naver-Client-Id')
    client_secret = request.headers.get('X-Naver-Client-Secret')

    # 요청 헤더에서 가져온 클라이언트 아이디와 클라이언트 시크릿을 이용하여 네이버 API에 요청을 보냅니다.
    if client_id and client_secret:
        api_url = 'https://openapi.naver.com/v1/search/local'
        headers = {
            'X-Naver-Client-Id': client_id,
            'X-Naver-Client-Secret': client_secret
        }
        # 네이버 API에 요청을 보냅니다.
        response = requests.get(api_url, headers=headers, params=request.args)

        # 네이버 API로부터 받은 응답을 클라이언트에게 반환합니다.
        return jsonify(response.json()), response.status_code
    else:
        return jsonify({'error': '클라이언트 아이디와 클라이언트 시크릿이 요청 헤더에 포함되어야 합니다.'}), 400

# 보호된 엔드포인트
@app.route('/protected', methods=['GET'])
@jwt_required()  # JWT 필요
def protected():
    current_user = get_jwt_identity()  # 현재 사용자 식별자
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':  
   app.run('0.0.0.0',port=5000,debug=True)
import datetime
from flask import Flask, render_template, request, redirect, jsonify
from settings import ca_path, naver_client_id, naver_secret_key
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from pymongo import MongoClient
import xml.etree.ElementTree as elemTree
import certifi,hashlib
import os
import sys
import urllib.request
import ssl

ssl._create_default_https_context = ssl._create_unverified_context

app = Flask(__name__)
jwt = JWTManager(app)

# 파싱
tree = elemTree.parse('keys.xml')
secretkey = tree.find('string[@name="secret_key"]').text

# 네이버 api 
client_id = naver_client_id
client_secret = naver_secret_key 

app.config['SECRET_KEY'] = secretkey
app.config['JWT_TOKEN_LOCATION'] = ['cookies']

ca = certifi.where()
client = MongoClient(ca_path, tlsCAFile=ca)
db = client.dbsparta

@app.route('/')
def home():
   return render_template('index.html')


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
      username_receive = request.form['username_input']
      password_receive = request.form['password_input']
   
      password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
      
      # 유효한 데이터 찾기 (db에 없을시에 클라이언트에 에러 반환)
      find_user_data = db.users.find_one({'username' : username_receive, 'password' : password_hash})
      
      if find_user_data is None:
         return jsonify({'result':'error','msg': '인증 실패'}),401
      # jwt 토큰 발급 (유효기간 30분)
      expires_delta = datetime.timedelta(minutes=30)
      access_token = create_access_token(identity=username_receive, expires_delta=expires_delta)
      # 클라이언트에 200과 함께 토큰 전송
      return jsonify({'result': 'success', 'token': access_token}), 200
    else:
        # GET 요청을 처리하기 위한 로직 추가
      return render_template('login.html') 
  

# 토큰의 유효성 검사
@app.route('/api/example', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    # 토큰 만료시 에러 처리 추후 추가
    return jsonify({'response': 'from {}'.format(username)}), 200
  
  
# 네이버 검색 API 
@app.route('/write', methods=['POST'])
# @jwt_required
def search_restaurant():
    search_receive = "대전맛집"
    encText = urllib.parse.quote(search_receive)
    
    url = "https://openapi.naver.com/v1/search/local?query=" + encText # JSON 결과
    req = urllib.request.Request(url)
    req.add_header("X-Naver-Client-Id",client_id)
    req.add_header("X-Naver-Client-Secret",client_secret)
    response = urllib.request.urlopen(req)
    rescode = response.getcode()
    if(rescode==200):
        response_body = response.read()
        print(response_body.decode('utf-8'))
        return jsonify({'resp' : response_body.decode('utf-8')})
    else:
        print("Error Code:" + rescode)

   
# 로그아웃
@app.route('/logout', methods=['POST'])
def logout():
    response = jsonify({'logout': True})
    return response, 200
  
if __name__ == '__main__':  
   app.run('0.0.0.0',port=5000,debug=True)
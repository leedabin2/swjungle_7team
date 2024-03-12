from flask import Flask, render_template, request, redirect, jsonify
from settings import ca_path
from flask_jwt_extended import JWTManager, create_access_token
from pymongo import MongoClient  
import certifi,hashlib

app = Flask(__name__)

ca = certifi.where()
client = MongoClient(ca_path, tlsCAFile=ca)
db = client.dbsparta

@app.route('/')
def home():
   return render_template('index.html')

# 회원가입
@app.route('/signup', methods=['POST'])
def register():
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
      
# 로그인
@app.route('/login', methods=['POST'])
def login():
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

if __name__ == '__main__':  
   app.run('0.0.0.0',port=5000,debug=True)
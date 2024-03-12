from flask import Flask, render_template, request, redirect, jsonify
from settings import ca_path
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
@app.route('/signup', methods=['GET','POST'])
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
   username = request.form['username_input']
   password = request.form['password_input']
   
   # 유효한 데이터 찾기 (db에 없을시에 클라이언트에 에러 반환)
  
   # jwt 토큰 발급
   
   # json형태로 로그인 저장
  
   # 클라이언트에 200과 함께 토큰 전송
  
   return render_template('login.html')

if __name__ == '__main__':  
   app.run('0.0.0.0',port=5000,debug=True)
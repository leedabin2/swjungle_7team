import datetime
from flask import Flask, render_template, request, redirect, jsonify
from settings import ca_path, naver_client_id, naver_secret_key
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, set_access_cookies,unset_jwt_cookies
from pymongo import MongoClient
import xml.etree.ElementTree as elemTree
import certifi,hashlib
import urllib.request
import ssl
import json

ssl._create_default_https_context = ssl._create_unverified_context

app = Flask(__name__,template_folder="templates")
jwt = JWTManager(app)

# 추후 수정
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

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
collection = db.restaurantlist

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


      if not username_receive:
        return jsonify({'result':'error', 'message':'사용자 이름은 필수 입력 사항입니다.'})
      elif len(username_receive) < 3 or len(username_receive) > 8:
        return jsonify({'result':'error', 'message':'사용자 이름은 3자에서 8자 이하로 입력해야 합니다.'})

      if not password_receive:
        return jsonify({'result':'error', 'message':'비밀번호 입력은 필수입니다.'})
      elif len(password_receive) < 8:
        return jsonify({'result':'error', 'message':'비밀번호의 길이는 8자 이상이어야 합니다.'})
      elif not any(char.isdigit() for char in password_receive) or not any(char.isalpha() for char in password_receive):
        return jsonify({'result':'error', 'message':'비밀번호는 영문자와 숫자를 모두 포함해야 합니다.'})

      is_existed = db.users.find_one({'username': username_receive})

      if is_existed:
        return jsonify({'result':'error','message':"중복된 이름입니다."})        

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

      if not username_receive:
        return jsonify({'result':'error', 'message':'사용자 이름은 필수 입력 사항입니다.'})

      if not password_receive:
        return jsonify({'result':'error', 'message':'비밀번호 입력은 필수입니다.'})

      password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
      # 유효한 데이터 찾기 (db에 없을시에 클라이언트에 에러 반환)
      find_user_data = db.users.find_one({'username' : username_receive, 'password' : password_hash})
      if find_user_data is None:
         return jsonify({'result':'error','message': '로그인 실패!'})
      # jwt 토큰 발급 (유효기간 30분)
      expires_delta = datetime.timedelta(minutes=30)
      access_token = create_access_token(identity=username_receive, expires_delta=expires_delta)
      resp = jsonify({'result':'success','login': True, 'token': access_token})
  
      set_access_cookies(resp, access_token)
      # 클라이언트에 200과 함께 토큰 전송
      return resp
    else:
        # GET 요청을 처리하기 위한 로직 추가
      return render_template('login.html')
    

# 네이버 검사 API
@app.route('/write', methods=['POST'])
def search_restaurant():
    search_receive = request.form['search_give']
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
        resp_data = response_body.decode('utf-8')
        resp_data = json.loads(response_body.decode('utf-8'))
        for item in resp_data['items']:
            title = item['title']
            link = item['link']
            address = item['address']
        restaurant_doc = {'title' : title, 'link' : link, 'address' : address}
     
        return jsonify(restaurant_doc)
    else:
        print("Error Code:" + rescode)
        return jsonify({'msg' : "에러가 발생하였습니다"})

 # 등록 버튼 클릭시 db에 정보 저장
@app.route('/complete/write', methods=["POST"])
@jwt_required()
def food_info():
    title_receive = request.form['title_give']
    address_receive = request.form['address_give']
    content_receive = request.form['content_give']
    username = get_jwt_identity()

    count = db.registerlist.count_documents({})

    key = 0
    if count != 0:
       key = db.registerlist.find_one(sort=[("key", -1)])["key"] + 1

    food_doc = { 'key': key,  "number": 0, 'title' : title_receive , 'address': address_receive, 'username' : username, 'content': content_receive}
    
    db.registerlist.insert_one(food_doc)
    return jsonify({"message":"success"}), 200
  
  
# 클라이언트 모든 것을  응답
@app.route('/complete/write', methods=["GET"])
def get_recent_register_info():
    cards =  list(db.registerlist.find({}, {'_id': 0}).sort([('number', -1), ('key', -1)]))
    return jsonify({"cards": cards})

  
# 로그아웃
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    resp = jsonify({'logout': True}) # 응답 객체 생성
    unset_jwt_cookies(resp) # JWT 쿠키 제거
    return resp, 200

# 추천수
@app.route('/up', methods=["POST"])
@jwt_required()
def post_up_button_count():
  key_receive = request.form['key']
  db.registerlist.update_one({"key": int(key_receive)}, {"$inc": {"number": 1}})
  return jsonify(), 200

# 보호된 엔드포인트
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user)

if __name__ == '__main__':
  app.run('0.0.0.0',port=5000,debug=True)
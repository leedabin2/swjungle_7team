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
      resp = jsonify({'login': True, 'token': access_token})
  
      set_access_cookies(resp, access_token)
      # 클라이언트에 200과 함께 토큰 전송
      return resp, 200
    else:
        # GET 요청을 처리하기 위한 로직 추가
      return render_template('login.html')
    
# 보호된 엔드포인트
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
  
# 토큰의 유효성 검사
@app.route('/api/example', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    # 토큰 만료시 에러 처리 추후 추가
    return jsonify({'response': 'from {}'.format(username)}), 200
  
# 토큰 만료시 클라이언트한테 401던지고, 클라이언트 로그인 리다이렉트처리

# 네이버 검사 API
@app.route('/write', methods=['POST'])
# @jwt_required
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
        # db.restaurantlist.insert_one(restaurant_doc)
        # 중복 제거 후 삽입
        # collection.insert_one(restaurant_doc,ordered=False)
        # res = list(db.restaurantlist.find({},{'_id':0}))
        # resp_data_to_json = json.dumps(restaurant_doc)
        return jsonify(restaurant_doc)
    else:
        print("Error Code:" + rescode)
        return jsonify({'msg' : "에러가 발생하였습니다"})

 # 등록 버튼 클릭시 db에 정보 저장
@app.route('/complete/write', methods=["POST"])
@jwt_required()
def register_info():
    title_receive = request.form['title_give']
    link_receive = request.form['link_give']
    address_receive = request.form['address_give']
    content_receive = request.form['content_give']
    username = get_jwt_identity()
    
    register_doc = { 'title' : title_receive , 'link' : link_receive, 'address': address_receive, 'username' : username}

    db.registerlist.insert_one(register_doc)
    return jsonify({"message":"success"}), 200
  
# 클라이언트 모든 것을  응답
@app.route('/complete/write', methods=["GET"])
def get_recent_register_info():
    cards =  list(db.registerlist.find({}, {'_id': 0}))
    return jsonify({"cards": cards})

# 클라이언트에서 받은 up버튼을 db에 저
@app.route('/up', methods=["POST"])
@jwt_required()
def post_up_button():
  id_receive = request.form['id_give']
  upvote_count = request.json['upvote_count']
  username_receive = get_jwt_identity() 
  #user_receive = request.form['username_receive']
  
  # 업데이트된 숫자를 새로운 데이터베이스에 저장
  upvote_data = {
      'upvote_count': upvote_count,
      'username': username_receive
  }
  
  # 해당 카드에 대해 up 버튼을 이미 눌렀는지 확인
  existing_vote = db.registerlist.find_one({'_id': id_receive, 'up_voters': username_receive})
  
  # 여기에 새로운 데이터베이스에 저장하는 코드
  upvote = db.upvote.insert_one(upvote_data)

  return jsonify(upvote), 200

  
# 로그아웃
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    resp = jsonify({'logout': True}) # 응답 객체 생성
    unset_jwt_cookies(resp) # JWT 쿠키 제거
    return resp, 200

if __name__ == '__main__':
  app.run('0.0.0.0',port=5000,debug=True)
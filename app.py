import datetime
from flask import Flask, render_template, request, redirect, jsonify
from settings import ca_path, naver_client_id, naver_secret_key
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, set_access_cookies
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
      resp = jsonify({'login': True})
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
    

# db에서 검사 후 전
# @app.route('/search/click', methods=["POST"])
# def check_db_and_post_info():
#    username = get_jwt_identity()
#    print(username)
#    address_receive = request.form['address_give']
#   # 유효한 데이터 찾기 (db에 없을시에 에러 반환)
#    find_address_data = db.restaurant.find_one({'address' : address_receive})
#    if find_address_data is None:
#      return jsonify({'msg': "유효한 데이터가 없습니다."})
#    # title/address/link,username json으로 보냄 찾는 address랑 똑같은 데이터만 (GET으로 처리해야하는가)
#    res = list(db.restaurantlist.find({},{'_id':0}),username)
#    return jsonify({'all_info': res}), 200
    

 # 등록 버튼 클릭시 db에 정보 저장
@app.route('/complete/write', methods=["POST"])
@jwt_required()
def register_info():
    title_receive = request.form['title_give']
    link_receive = request.form['link_give']
    address_receive = request.form['address_give']
    username = get_jwt_identity()
    print(username)
    register_doc = { 'title' : title_receive , 'link' : link_receive, 'address': address_receive, 'username' : username}
    db.registerlist.insert_one(register_doc)
    
    return render_template("index.html", title=title_receive, link=link_receive, address=address_receive, username=username), 200
  
# 클라이언트 card등록되게 보내줌
@app.route('/complete/write', methods=["GET"])
def get_register_info():
  all_register_list = list(db.registerlist.find({},{'_id':0}))
  all_register_list_to_json = json.dumps(all_register_list)
  return render_template("index.html",items=all_register_list_to_json)

<<<<<<< HEAD
=======
# @app.route('/detail', methods=['GET'])
# def index() :
#     post_list = Post.query.order_by(Post.id.desc()).all()

#     return render_template('post.html', result=post_list)

>>>>>>> bb0aa821ef25e6960ea7a343c873591d3e4d60bf
if __name__ == '__main__':
  app.run('0.0.0.0',port=5000,debug=True)
from flask import Flask, render_template
from settings import ca_path
from pymongo import MongoClient  
import certifi
app = Flask(__name__)

ca = certifi.where()
client = MongoClient(ca_path, tlsCAFile=ca)
db = client.dbsparta

@app.route('/')
def home():
   return 'This is Home!'

@app.route('/login')
def login():
   return render_template('login.html')

if __name__ == '__main__':  
   app.run('0.0.0.0',port=5000,debug=True)
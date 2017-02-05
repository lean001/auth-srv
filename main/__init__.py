#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
#from flask_debugtoolbar import DebugToolbarExtension

app = Flask(__name__, instance_relative_config=True)
# load config
app.config.from_object('config')
app.config.from_pyfile('config.py')

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)

# record log
handler = RotatingFileHandler(app.config["LOG"], maxBytes=10000, backupCount=1)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s '
    '[in %(pathname)s:%(lineno)d]'
))

from flask_mail import Mail
mail = Mail(app)

if not app.debug:
    handler.setLevel(logging.ERROR)
else:
    handler.setLevel(logging.DEBUG)

app.logger.addHandler(handler)

#toolbar = DebugToolbarExtension(app)


from main.models import User
def db_setup():
    db.drop_all()
    db.create_all()
    admin = User("lean", "admin", "lean@test.com", admin=True)
    #free = User("test", "testtest", "test@test.cn", quota=5)
    db.session.add(admin)
    #db.session.add(free)
    db.session.commit()

#db_setup()

from main.models import Media
from wechatpy import WeChatClient 
def upload_image(path_to_image, title):
    if path_to_image is None or title is None:
        return None
    client = WeChatClient(app.config["APPID"], app.config["APP_SECRET"])
    ret = client.material.add("image", path_to_image, title=title)
    if ret is not None:
        print(ret, " ", type(ret))
        m = Media(ret['media_id'], title)
        db.session.add(m)
        db.session.commit()
        return ret['media_id']
    return None

def get_mediaId(title):
    if title is None:
        return None
    m = Media.query.filter_by(title=title).first()
    if m is not None:
        return m.media_id
    return None

#from main.parse_opt import WECHATPAY, ALIPAY
#ret = upload_image("static/pic/ali.jpg", ALIPAY)
#print("alipay : ", ret)

#ret = upload_image("static/pic/wechat.jpg", WECHATPAY)
#print("wechatpay : ", ret)

from main.views import *

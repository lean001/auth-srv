from __future__ import absolute_import, unicode_literals

DEBUG = True
#log
LOG = "/var/log/wificonnect.log"

# wechat config
APPID = ""
APP_SECRET = ""
TOKEN = ""
ENCODINGAESKEY = ""
# From user name
ADMIN= ""

# app host
HOST = "0.0.0.0"
#HOST_URL = "http://domain.com"
# Web baidu counter
BAIDU_ANALYTICS = ""

#management
MAIL_SERVER = ""
MAIL_PORT = "25"
MAIL_USE_TLS = True
MAIL_USER = ""
MAIL_PASSWD = ""


# database
SECRET_KEY = "KEYKEY"
SQLALCHEMY_DATABASE_URI = "mysql+pymysql://user:password@127.0.0.1/database?charset=utf8mb4"
SQLALCHEMY_COMMIT_ON_TEARDOWN = True
SQLALCHEMY_TRACK_MODIFICATIONS = False
BOOTSTRAP_SERVE_LOCAL = True

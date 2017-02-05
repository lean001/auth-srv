#!/usr/bin/python3
# -*- coding: utf-8 -*-


import logging
import datetime

from flask import render_template, g, request, abort, redirect, session, url_for, flash, json, jsonify
from flask_login import login_user, logout_user, login_required, current_user

from wechatpy.crypto import WeChatCrypto
from wechatpy import parse_message, create_reply
from wechatpy.utils import check_signature
from wechatpy.exceptions import InvalidSignatureException
from wechatpy.exceptions import InvalidAppIdException

from main.forms import LoginForm, RegisterForm, ChangePasswordForm
from main.utils import check_passport
from main.models import User, Log
from main import db, app, get_mediaId
from main.parse_opt import handle_admin_opt, WECHATPAY, ALIPAY, user_help

IMAGE_URL = {
    WECHATPAY : "点击链接-》识别二维码充值流量5元/\n http://23.106.137.94/static/pic/wechat.jpg ",
    ALIPAY : "点击链接并保存二维码-》打开支付宝-》扫描二维码-》从相册中选择二维码充值5元/G\n http://23.106.137.94/static/pic/ali.jpg"
}

@app.route('/')
def index():
#    host = request.url_root
    abort(403)
#    return render_template('index.html', host=host)


@app.route('/wechat', methods=['GET', 'POST'])
def wechat():
    signature = request.args.get('signature', '')
    timestamp = request.args.get('timestamp', '')
    nonce = request.args.get('nonce', '')
    echo_str = request.args.get('echostr', '')
    encrypt_type = request.args.get('encrypt_type', '')
    msg_signature = request.args.get('msg_signature', '')

    app.logger.debug('signature: %s\ntimestamp: %s\nnonce: %s\necho_str: %s\nencrypt_type: %s\nmsg_signature: %s\n' % (signature, timestamp, nonce, echo_str, encrypt_type, msg_signature))

    try:
        check_signature(app.config["TOKEN"], signature, timestamp, nonce)
    except InvalidSignatureException:
        abort(403)
    if request.method == 'GET':
        return echo_str
    else:
        app.logger.debug('Raw message: \n%s' % request.data)
        crypto = WeChatCrypto(app.config["TOKEN"], app.config["ENCODINGAESKEY"], app.config["APPID"])
        try:
            msg = crypto.decrypt_message(
                request.data,
                msg_signature,
                timestamp,
                nonce
            )
            msg = msg.encode('UTF-8')
            app.logger.debug('Descypted message: \n%s' % msg)
        except (InvalidSignatureException, InvalidAppIdException):
            abort(403)
        msg = parse_message(msg)
        if msg.type == 'text':
            if msg.source == app.config["ADMIN"]:
                msg.content = handle_admin_opt(msg.content, admin=True)  # exec option and return result
            else:
                msg.content = handle_admin_opt(msg.content, wechatUser=msg.source, admin=False)  # exec option and return result

            if msg.content is ALIPAY or msg.content is WECHATPAY:
                msg.content = IMAGE_URL[msg.content]

            reply = create_reply(msg.content, message=msg)

        elif msg.type == 'event' and msg.event == "subscribe":
            msg.content = user_help
            reply = create_reply(msg.content, msg)
        else:
            reply = create_reply('Sorry, I can not handle this for now', msg)
        return crypto.encrypt_message(
            reply.render(),
            nonce,
            timestamp
        )


@app.route("/register/", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        studentid = form.studentid.data.strip()
        password = form.password.data.strip()
        valid = check_passport(studentid, password)
        if not valid:
            flash("您的用户名不合法，请重试.", "danger")
        else:
            exist_user = User.query.filter_by(username=studentid).first()
            if exist_user:
                flash("用户 {} 已经存在，请更换另一个用户名， 重新注册.".format(studentid), "danger")
                return redirect(url_for("login"))
            try:
                app.logger.debug("Validating {} against zuinfo".format(studentid))
                #valid = check_passport(studentid, password)
            except IOError as e:
                flash(str(e), "danger")
                return abort(500)
            if valid:
                new_user = User(studentid, password, studentid+"@test.com")
                db.session.add(new_user)
                db.session.commit()
                flash("注册成功. 现在可以登录网络.", "info")
                return redirect(url_for("login"))
            else:
                flash("您的用户名不合法，请重试.", "danger")
    return render_template("register.html", form=form)


@app.route("/auth/")
def auth():

    def make_reply(code):
        return "Auth: {}".format(code)

    AUTH_DENIED = 0
    AUTH_ALLOWED = 1
    AUTH_VALIDATION = 5
    AUTH_ERROR = -1

    ua = request.headers.get('User-Agent')
    if ua and 'wifidog' not in ua.lower():
        return abort(404)

    stage = request.args.get('stage').lower()
    ipaddr = request.args.get('ip').lower()
    mac = request.args.get('mac').lower()
    token = request.args.get('token').lower()
    incoming = int(request.args.get('incoming'))
    outgoing = int(request.args.get('outgoing'))

    token = Log.query.filter_by(token=token, mac=mac, ipaddr=ipaddr, valid=True).first()
    if token:
        token.update_counters(incoming, outgoing)
        if token.user.quota_exceeded or not token.user.enabled:
            return make_reply(AUTH_DENIED)
        return make_reply(AUTH_ALLOWED)
    else:
        app.logger.debug("none token: AUTH_DENIED")

    return make_reply(AUTH_DENIED)


@app.route("/prelogin/")
def prelogin():
    # session.clear()
    session['gw_address'] = request.args.get("gw_address")
    session['gw_port'] = request.args.get("gw_port")
    session['url'] = request.args.get("url")
    session['gw_id'] = request.args.get("gw_id")
    session['ip'] = request.args.get('ip')
    session['mac'] = request.args.get('mac')
    return redirect("login")


@app.route("/login/", methods=["GET", "POST"])
def login():
    prelogin()
    form = LoginForm()
    if form.validate_on_submit() and check_passport(form.username.data, None):
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            if user.enabled:
                user.ping()
                login_user(user)
                if user.quota_exceeded:
                    flash("您已经使用了{} MBytes 流量，可用流量已用完. 请用微信扫描下方二维码联系管理员充值.".format(user.quota), "warning")
                    return redirect(url_for('dashboard'))
                if session.get("gw_id") is None:
                    #If the user is not redirected by router, go to the dashboard, do not assign wifi token
                    return redirect(url_for('dashboard'))
                else:
                    # add by lean for limit reReg
                    user.mac = session.get('mac')
                    invalid_users = User.query.filter_by(mac_t=session.get('mac'), enabled=True).all()
                    if len(invalid_users) > 1:
                        user.user_enable = False
                    db.session.add(user)
                    db.session.commit()
                    # end by lean
                    #Only assign token if login via wifidog
                    new_token = user.assign_token(session.get('ip'), session.get('mac'))
                    gateway_auth_url = "http://{}:{}/wifidog/auth?token={}".format(session['gw_address'], session['gw_port'], new_token)
                    del session['gw_id']
                    session['wifitoken'] = new_token
                    return redirect(gateway_auth_url)
            else:
                flash("您的账户已经被禁用.", "warning")
        else:
            flash('用户名与密码不匹配.', "warning")
    else:
        flash('用户名不合法.', "warning")
    return render_template('login.html', form=form)


@app.route("/cpw", methods=['GET', 'POST'])
@login_required
def changepw():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        oldpw = form.old_password.data
        newpw = form.password.data
        if not current_user.verify_password(oldpw):
            flash("旧密码不正确", "danger")
        elif oldpw == newpw:
            flash("新密码和旧密码一致，修改无效", "warning")
        else:
            current_user.password = newpw
            flash("修改成功.", "success")
            return redirect(url_for('dashboard'))
    return render_template("changepw.html", form=form, user=current_user)


@app.route('/portal/')
@login_required
def portal():
    return redirect(url_for('dashboard'))


@app.route('/dashboard/')
@login_required
def dashboard():
    now = datetime.datetime.now()
    day_list = range(1, now.day+1)
    download = {}
    upload = {}
    for l in current_user.logs:
        if l.create_timestamp.month == now.month:
            download[l.create_timestamp.day] = download.get(l.create_timestamp.day, 0) + l.incoming
            upload[l.create_timestamp.day] = upload.get(l.create_timestamp.day, 0) + l.outgoing
    dlist = []
    ulist = []
    for day in day_list:
        dlist.append(download.get(day, 0))
        ulist.append(upload.get(day, 0))
    return render_template("dashboard.html", user=current_user, logs=current_user.logs[:10], xaxis=list(day_list), ulist=ulist, dlist=dlist)


@app.route("/admin")
@login_required
def admin():
    if current_user.is_admin:
        return render_template("admin.html", users=User.query.all(), user=current_user)
    return abort(401)

@app.route("/profile/<int:uid>")
@login_required
def profile(uid):
    if current_user.is_admin or current_user.uid == uid:
        return render_template("profile.html", user=User.query.get(uid))
    return abort(401)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    if 'wifitoken' in session:
        t = Log.query.filter_by(token=session['wifitoken']).first()
        t.make_invalid()
        session.clear()
        flash("您已退出登录，即将断开网络.", 'warning')
    else:
        flash("退出.", "info")
    return redirect(url_for("login"))

@app.route("/disconnect/<int:uid>")
@login_required
def disconnect(uid):
    if current_user.is_admin or current_user.uid == uid:
        user = User.query.get(uid)
        if not user:
            return 'No such user'
        if user.online:
            user.disconnect()
            flash("{} 成功断开.".format(user.username), "success")
        else:
            flash("{} do not have active connections.".format(user.username), "info")
        return redirect(url_for("dashboard"))
    return abort(401)


@app.route('/ping/')
def ping():
    INACTIVE_THRESHOLD = 100
    active_logs = Log.query.filter_by(valid=True).all()
    cut = datetime.datetime.now() - datetime.timedelta(seconds=INACTIVE_THRESHOLD)
    #If wifidog did not report a token in INACTIVE_THRESHOLD seconds, the token will be marked invalid
    for l in active_logs:
        if l.update_timestamp < cut:
            l.make_invalid()
    return 'Pong'


@app.route("/message/")
def message():
    return render_template("message.html")


@app.route("/exceed/")
def exceed():
    flash("您的流量使用已经超额. 请尽快充值.", "warning")
    return render_template("message.html")


@app.route("/lottery/")
def lottery():
    return "TODO"


@app.route("/api/stat")
@login_required
def api_stat():
    return json.dumps({"data_usage":current_user.data_usage, "quota":current_user.quota})


@app.route("/api/logs/<int:logid>")
@login_required
def api_logs(logid):
    l = Log.query.get(logid)
    if l:
        return jsonify(logid=l.logid, day=l.create_timestamp.day, download=l.incoming, upload=l.outgoing)
    return abort(404)


@app.route("/api/chart")
@login_required
def api_chart():
    now = datetime.datetime.now()
    t = [(l.logid, l.create_timestamp.day, l.incoming, l.outgoing) for l in current_user.logs if l.create_timestamp.month == now.month]
    return json.dumps(t)

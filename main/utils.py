#!/usr/bin/python3
# -*- coding: utf-8 -*-

from flask_mail import Message
from threading import Thread
from main import app, mail


def send_async_email(handle, msg):
    with handle.app_context():
        mail.send(msg)


def send_mail_func(theme, content):
    msg = Message(theme, sender=app.config['MAIL_USER'], recipients=[app.config['SEND_USER']])
    msg.body = '文本 body'
    msg.html = '<b>%s</b>' % content

    thread = Thread(target=send_async_email, args=[app, msg])
    thread.start()


def check_validname(w):
    return (w >= '0' and w <= '9') or (w >= 'A' and w <= 'Z') or (w >= 'a' and w <= 'z')

def check_passport(id, passwd):
    # check id and passwd is valid
    for s in id:
        if not check_validname(s):
            return False
    return True

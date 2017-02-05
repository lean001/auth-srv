# -*- coding: utf-8 -*-

import re
from main.models import User
from main.utils import check_passport, send_mail_func
from main import db, app, mail

ALIPAY="ALIPAY"
WECHATPAY="WECHATPAY"
admin_help = "Usage: cmd=command;key=value\ncommand list:\nusers -- get all user info\n" \
                "userinfo -- get the user info\n" \
                "useradd -- create a new user\n" \
                "disable -- disable the user\n" \
                "enable -- enable the user\n" \
                "cpw -- update user password, default[123456]\n" \
                "pay -- add cost for the user"

user_help = "使用方法: \n发送 0+用户名 绑定WIFI用户至微信\n" \
            "发送 1 查询流量使用情况\n" \
            "发送 2 使用微信支付(推荐)充值流量 5元/G 10元/3G\n" \
            "发送 3 使用支付宝充值流量"

def exec_show_help(self, admin, **kwargs):
    app.logger.debug("exec_show_help")
    if admin:
        return admin_help
    else:
        return user_help

class OptHandle(object):
    '''
    parse the option command from wechat message
    '''

    def __init__(self, data):
        self.data = data
        self.userdata = {}
        self.command = None
        self.opt_func = None
        self.username = None
        self.password = None
        self.money = None
        self.mac = None

    def _init_datas(self):
        for k in self.userdata:
            if k == "opt" or k == "cmd" or k == "command":
                self.command = self.userdata[k]
                continue
            if k == "username" or k == "usr":
                self.username = self.userdata[k]
                continue
            if k == "password" or k == "passwd":
                self.password = self.userdata[k]
                continue
            if k == "money" or k == "cost":
                self.money = int(self.userdata[k])
                continue
            if k == "mac" or k == "MAC":
                self.mac = self.userdata[k]
                continue

    def parse_data(self, admin):
        app.logger.debug("data : %s" % self.data.encode('UTF8'))
        if admin:
            datas = self.data.split(';')
            for s in datas:
                tmp = s.strip()
                row = tmp.split('=')
                try:
                    self.userdata[row[0]] = row[1]
                except IndexError:
                    continue
        else:
            datas = self.data.split('+')
            if len(datas) == 1:
                self.userdata["cmd"] = datas[0].strip()
            elif len(datas) == 2:
                # bind usr name
                self.userdata["cmd"] = datas[0].strip()
                self.userdata["usr"] = datas[1].strip()
        self._init_datas()

    def print_userdata(self):
        for k in self.userdata:
            app.logger.debug("%s = %s" % (k.encode('UTF8'), self.userdata[k].encode('UTF8')))

    def exec_alluser(self, admin):
        app.logger.debug("exec_alluser")
        users = User.query.filter_by(online=True).all()
        return "online: %d" % len(users)

    def exec_userinfo(self, admin):
        app.logger.debug("exec_userinfo")
        if self.username is not None:
            u = User.query.filter_by(username=self.username).first()
            if u is not None:
                return "name: %s\nonline: %d\ndata_usage: %d\nquota: %d\nenabled: %d\nmac: %s" % \
                       (u.username, u.online, u.data_usage, u.quota, u.enabled, u.mac_t if u.mac_t is not None else "NULL")
            else:
                return "[Warn] user not existed!"
        elif self.mac is not None:
            users = User.query.filter_by(mac_t=self.mac).all()
            if len(users) > 0 :
                res = ""
                for u in users:
                    res += "name: %s\nonline: %d\ndata_usage: %d\nquota: %d\nenabled: %d\n" % \
                       (u.username, u.online, u.data_usage, u.quota, u.enabled)
                return res
            else:
                return "[Warn] user not existed!"
        return "[Error] please provide username or mac for search"

    def exec_user_cpw(self, admin):
        app.logger.debug("exec_user_cpw")
        if admin is False:
            return "this command not for user"
        if self.username is not None:
            exist_user = User.query.filter_by(username=self.username).first()
            if exist_user is not None:
                if self.password is not None:
                    exist_user.password = self.password
                else:
                    exist_user.password = "123456"
                db.session.add(exist_user)
                db.session.commit()
                return "[Success] update user: %s " % exist_user.username
            else:
                return "[Warn] user not existed!"
        else:
            return "[Error] please provide username for search"

    def exec_user_add(self, admin):
        app.logger.debug("exec_user_add")
        if admin is False:
            return "this command not for user"
        if self.username is not None and self.password is not None:
            exist_user = User.query.filter_by(username=self.username).first()
            if exist_user is not None:
                return "[Error] user: %s is existed, please try another name" % self.username
            elif check_passport(self.username, self.password):
                new = User(self.username, self.password, self.username + "@test.com")
                db.session.add(new)
                db.session.commit()
                return "[Success] add user: %s " % new.username
        return "[Error] Invalid parameters for add user"

    def exec_user_disable(self, admin):
        app.logger.debug("exec_user_disable")
        if admin is False:
            return "this command not for user"
        if self.username is not None:
            disable_users = User.query.filter_by(username=self.username, enabled=True).first()
            if disable_users is not None:
                disable_users.user_enable = False
                db.session.add(disable_users)
                db.session.commit()
                return "[Success] disable user: %s " % disable_users.username
            else:
                return "[Warn] user not existed!"
        elif self.mac is not None:
            disable_users = User.query.filter_by(mac_t=self.mac, enabled=True).all()
            if disable_users is not None:
                for u in disable_users:
                    u.user_enable = False
                    db.session.add(u)
                db.session.commit()
                return "[Success] disable mac:%s " % self.mac
            else:
                return "[Warn] user not existed!"
        return "[Error] please provide username or mac for search"

    def exec_user_enable(self, admin):
        app.logger.debug("exec_user_enable")
        if admin is False:
            return "this command not for user"
        if self.username is not None:
            disable_users = User.query.filter_by(username=self.username, enabled=False).first()
            if disable_users is not None:
                disable_users.user_enable = True 
                db.session.add(disable_users)
                db.session.commit()
                return "[Success] enable user: %s " % disable_users.username
            else:
                return "[Warn] user not existed!"
        return "[Error] please provide username for search"

    def exec_user_pay(self, admin):
        app.logger.debug("exec_user_pay")
        if not admin:
            return "this command not for user"
        if self.username is not None and self.money is not None:
            u = User.query.filter_by(username=self.username).first()
            if u is not None:
                u.quota += self.money
                db.session.add(u)
                db.session.commit()
                return "[success] %s account balance : %d" % (u.username, u.quota)
            else:
                return "[Warn] user not existed!"
        return "[Error] please provide username and cost for update quota"

    # return qrcode
    def exec_pay_wechat(self, admin, **kwargs):
        #send_mail_func(WECHATPAY, "somebody pay with wechat")
        return WECHATPAY

    def exec_pay_ali(self, admin, **kwargs):
        #send_mail_func(ALIPAY, "somebody pay with alipay")
        return ALIPAY

    def exec_bind_wechat(self, admin, **kwargs):
        if self.username is not None and 'wechat'in kwargs and kwargs['wechat'] is not None:
            u = User.query.filter_by(wechat=kwargs['wechat']).first()
            if u is None:
                utobind = User.query.filter_by(username=self.username).first()
                if utobind is not None:
                    utobind.wechat = kwargs['wechat'] 
                    db.session.add(utobind)
                    db.session.commit()
                    return "绑定成功，回复 1 查询用户信息"
                else:
                    return "用户不存在"
            else:
                return "[Warn]: 微信账户已经被绑定到 %s" % u.username
        return "[Error] 请发送 0+用户名 绑定微信"

    def exec_userinfo_wechat(self, admin, **kwargs):
        if 'wechat'in kwargs and kwargs['wechat'] is not None:
            u = User.query.filter_by(wechat=kwargs['wechat']).first()
            if u is not None:
                return "用户名: %s\n在线: %d\n已用流量: %d\n总流量: %d\n状态: %d\n硬件信息: %s" % \
                       (u.username, u.online, u.data_usage, u.quota, u.enabled,
                        u.mac_t if u.mac_t is not None else "NULL")
            else:
                return "[Error] 您的微信还没绑定任何WIFI用户，请先绑定后再试！"
        app.logger.error("Error: wechat is None!!!")
        return "[System Error] please contact to admin"

#    def exec_show_help(self, admin, **kwargs):
#        print("exec_show_help")
#        admin_help = "Usage: cmd=command;key=value\ncommand list:\nusers -- get all user info\n" \
#                     "userinfo -- get the user info\n" \
#                     "useradd -- create a new user\n" \
#                     "disable -- disable the user\n" \
#                     "enable -- enable the user\n" \
#                     "pay -- add cost for the user"
#        user_help = "Usage: \n0+username bind the wifiuser to wechat\n1 get user info\n2 pay wifi cost\n"
#        if admin:
#            return admin_help
#        else:
#            return user_help

    COMMANDS = {
        "users": exec_alluser,
        "userinfo": exec_userinfo,
        "useradd": exec_user_add,
        "cpw": exec_user_cpw,
        "disable": exec_user_disable,
        "enable": exec_user_enable,
        "pay": exec_user_pay,
        "0": exec_bind_wechat,
        "1": exec_userinfo_wechat,
        "2": exec_pay_wechat,
        "3": exec_pay_ali,
    }

    def _get_command_func(self):
        try:
            opt = self.userdata["cmd"]
        except KeyError:
            # log here
            self.opt_func = exec_show_help
            return 
        for keyword in self.COMMANDS:
            if re.match(keyword, opt):
                    self.opt_func = self.COMMANDS.get(keyword, exec_show_help)
                    return

        self.opt_func = exec_show_help


    def exec_command(self, admin, **kwargs):
        self._get_command_func()
        if admin:
            result = self.opt_func(self, admin)
        elif 'wechat' in kwargs:
            result = self.opt_func(self, admin, wechat=kwargs['wechat'])
        return result


def handle_admin_opt(data, wechatUser=None, admin=False):
    opt_handle = OptHandle(data)
    opt_handle.parse_data(admin)
    opt_handle.print_userdata()  # just for debug
    return opt_handle.exec_command(admin, wechat=wechatUser)

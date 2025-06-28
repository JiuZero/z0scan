#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/11

rules = {
    "discuz": { # CMS名称
        "keywords": "admin_questionid",  # CMS后台登陆页关键字
        "success_flag": "admin.php?action=logout",  # 登录成功关键字
        "die_flag": "密码错误次数过多",  # 若填写此项，遇到其中的关键字就会退出爆破
    },
    "dedecms": {
        "keywords": "newdedecms",
        "success_flag": "",
        "die_flag": "",
    },
    "phpweb": {
        "keywords": "width:100%;height:100%;background:#ffffff;padding:160px",
        "success_flag": "admin.php?action=logout",
        "die_flag": "",
    },
    "ecshop": {
        "keywords": "validator.required('username', user_name_empty);",
        "success_flag": "ECSCP[admin_pass]",
        "die_flag": "",
    },
    "phpmyadmin": {
        "keywords": "pma_username",
        "success_flag": "db_structure.php",
        "die_flag": "",
    }
}

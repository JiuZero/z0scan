#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero/z0scan

import ldap3
from api import generateResponse, random_num, conf, PLACE, VulType, POST_HINT, Type, _PluginBase, KB

class Z0SCAN(_PluginBase):
    name = "unauth-ldaps"
    version = "2025.11.25"
    desc = "Ldaps Unauthorized Access"
    risk = 2
    ports = [389]
    fingers = []
    
    def audit(self):
        ip, port = self.host.split(":")
        try:
            server = ldap3.Server(host=ip, port=port, allowed_referral_hosts=[('*', False)], get_info=ldap3.ALL, connect_timeout=30)
            conn = ldap3.Connection(server, auto_bind=True)
            if len(server.info.naming_contexts) > 0:
                for _ in server.info.naming_contexts:
                    if conn.search(_, '(objectClass=inetOrgPerson)'):
                        result = self.generate_result()
                        result.main({
                            "type": Type.REQUEST, 
                            "url": self.host, 
                            "vultype": VulType.UNAUTH, 
                            })
                        result.step("Ldaps-Request", {
                            "position": None,
                            "request": "None", 
                            "response": str(_.decode('utf-8', 'ignore')), 
                            "desc": ""
                            })
                        self.success(result)
                        return
        except Exception as e:
            pass

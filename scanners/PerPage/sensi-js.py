#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/6
# JiuZero/z0scan

import re
import json
from api import VulType, Type, PluginBase, conf, KB, logger, chat

"""
Reference:
https://xz.aliyun.com/spa/#/news/13091
https://github.com/shuanx/BurpAPIFinder
https://github.com/gh0stkey/HaE
https://github.com/API-Security/APIKit
https://github.com/z2p/sweetPotato
"""
rules = {
    ## Fingerprint
    'shiro': r'(=deleteMe|rememberMe=)',
    'ueditor': r'(ueditor\.(config|all)\.js)',
    'swagger_ui': r'((swagger-ui.html)|(\"swagger\":)|(Swagger UI)|(swaggerUi)|(swaggerVersion))',
    'json_web_token': r'​(eyJ[A-Za-z0-9_-]{10,}​\\​.[A-Za-z0-9._-]{10,}|eyJ[A-Za-z0-9_​\\​/+-]{10,}​\\​.[A-Za-z0-9._​\\​/+-]{10,})',

    ## Maybe Vulnerability
    # 'dos_paramters': r'((size=)|(page=)|(num=)|(limit=)|(start=)|(end=)|(count=))', 
    # 'debug_rogic_parameters': r'((access=)|(adm=)|(admin=)|(alter=)|(cfg=)|(clone=)|(config=)|(create=)|(dbg=)|(debug=)|(delete=)|(disable=)|(edit=)|(enable=)|(exec=)|(execute=)|(grant=)|(load=)|(make=)|(modify=)|(rename=)|(reset=)|(root=)|(shell=)|(test=)|(toggl=))',

    ## Basic Infomation
    # "url": r'(\b|\'|")(?:http:|https:)(?:[\w/\.]+)?(?:[a-zA-Z0-9_\-\.]{1,})\.(?:php|asp|ashx|jspx|aspx|jsp|json|action|html|txt|xml|do)(\b|\'|")',
    # "email": r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+',
    # "ip": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',

    ## Sensitive Infomation
    "wechat_appid": r'(?i)(?:app(?:[\-_]?)(?:id|secret)).?[=:].*?(wx[a-fA-F0-9]{16,18})',
    "cloudfront_cloud": r'[\w]+\.cloudfront\.net',
    "appspot_cloud": r'[\w\-.]+\.appspot\.com',
    "digitalocean_cloud": r'([\w\-.]*\.?digitaloceanspaces\.com\/?[\w\-.]*)',
    "google_cloud": r'(storage\.cloud\.google\.com\/[\w\-.]+)',
    'wecom_key': r'((corp)(id|secret))',
    "google_storage_api": r'([\w\-.]*\.?storage.googleapis.com\/?[\w\-.]*)',
    # "phone_number": '[^​\\​w]((?:(?:​\\​+|00)86)?1(?:(?:3[​\\​d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[​\\​d])|(?:9[189]))​\\​d{8})[^​\\​w]​',
    # "host": r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:biz|cc|club|cn|com|co|edu|fun|group|info|ink|kim|link|live|ltd|mobi|net|online|org|pro|pub|red|ren|shop|site|store|tech|top|tv|vip|wang|wiki|work|xin|xyz|me))',
    "access_key": r'access_key.*?["\'](.*?)["\']',
    "access_key_id": r'accesskeyid.*?["\'](.*?)["\']',
    "token_password": r'\b(?:wxappid|wxsecret|qqmapkey|secret_key|token|secret_token|auth_token|access_token|aws_access_key_id|aws_secret_access_key|secretkey|authtoken|accesstoken|access-token|authkey|client_secret|bucket|email|HEROKU_API_KEY|SF_USERNAME|PT_TOKEN|id_dsa|clientsecret|client-secret|encryption-key|encryption_key|encryptionkey|secretkey|secret-key|JEKYLL_GITHUB_TOKEN|HOMEBREW_GITHUB_API_TOKEN|api_key|api_secret_key|api-key|private_key|client_key|client_id|sshkey|ssh_key|ssh-key|privatekey|DB_USERNAME|oauth_token|irc_pass|dbpasswd|xoxa-2|xoxrprivate-key|private_key|consumer_key|consumer_secret|access_token_secret|SLACK_BOT_TOKEN|slack_api_token|api_token|ConsumerKey|ConsumerSecret|SESSION_TOKEN|session_key|session_secret|slack_token|slack_secret_token|bot_access_token|passwd|api|eid|sid|api_key|apikey|userid|user_id|user-id)["\s]*(?::|=|=:|=>)["\s]*[a-z0-9A-Z]{8,64}"?',
    "sensitive_all_in_one": r'(((access_key|appsecret|app_secret|access_token|password|secretkey|accesskey|accesskeyid|accesskeysecret|secret_key|pwd|test_user|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_.]{0,25})(=|>|:=|:|<=|=>|:).{0,5}[\'\"\ ]([0-9a-zA-Z-_=]{12,64})[\'\"\ ])',
    "cloud_access_key": r'([\'\"\ ](GOOG[\w\W]{10,30})[\'\"\ ]|([\'\"\ ]AZ[A-Za-z0-9]{34,40}[\'\"\ ])|([\'\"\ ]AKID[A-Za-z0-9]{13,20}[\'\"\ ])|([\'\"\ ]AKIA[A-Za-z0-9]{16}[\'\"\ ])|([\'\"\ ][a-zA-Z0-9]{8}(-[a-zA-Z0-9]{4}){3}-[a-zA-Z0-9]{12}[\'\"\ ])|([\'\"\ ]OCID[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]LTAI[A-Za-z0-9]{12,20}[\'\"\ ])|([\'\"\ ][A-Z0-9]{20}$[\'\"\ ])|([\'\"\ ]JDC_[A-Z0-9]{28,32}[\'\"\ ])|([\'\"\ ]AK[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]UC[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]QY[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]AKLT[a-zA-Z0-9-_]{16,28}[\'\"\ ])|([\'\"\ ]LTC[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]YD[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]CTC[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]YYT[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]YY[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]CI[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]gcore[A-Za-z0-9]{10,30}[\'\"\ ]))',
    "jwt": r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    # "author": '@author[: ]+(.*?) ',
    'google_api': r'AIza[0-9A-Za-z-_]{35}',
    'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url1': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2': r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    "amazon_aws_url3": r'[\w\-.]*s3[\w\-.]*\.?amazonaws\.com\/?[\w\-.]*', 
    'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    # 'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    # 'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
    # 'twilio_api_key': r'SK[0-9a-fA-F]{32}',
    # 'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
    # 'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
    # 'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    # 'square_oauth_secret': r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    # 'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    # 'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
    # 'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'windows_filedir_path': r'[^\w](([a-zA-Z]:\\(?:\w+\\?)*)|([a-zA-Z]:\\(?:\w+\\)*\w+\.\w+))',
    'slack_token': r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'ssh_privkey': r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    # 'heroku_api_key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_creds': r"(" \
        r"password\s*[`=:\"]+\s*[^\s]+|" \
        r"password is\s*[`=:\"]*\s*[^\s]+|" \
        r"pwd\s*[`=:\"]*\s*[^\s]+|" \
        r"passwd\s*[`=:\"]+\s*[^\s]+)",
    'java_deserialization​': r"​(javax​\\​.faces​\\​.ViewState)​", 
    'jdbc-sql': r"jdbc:(mysql|h2|oracle|sqlserver|jtds:sqlserver):|System\.Data\.SqlClient|Data\.PassportContext|mysql\.username|mysql\.password|mysql\.url|jdbc\.username|jdbc\.password|mssql\.jdbc|mssql\.user|com\.microsoft\.sqlserver\.jdbc\.SQLServerDriver",
    'jdbc-connection': r'(jdbc:[a-z:]+://[a-z0-9\.\-_:;=/@?,&]+)',
    'authorization_header': r'((basic [a-z0-9=:_\+\/-]{5,100})|(bearer [a-z0-9_.=:_\+\/-]{5,100}))',
    'iis_path_leak': r"<th>\xe7\x89\xa9\xe7\x90\x86\xe8\xb7\xaf\xe5\xbe\x84</th><td>(&nbsp;)*?[A-Z]",
    "thinkphp_path_leak": r"#\d?\s.*?\.php\(\d?\).*?<br />",
    'init_password': r"​(initPassword​\\​s*[:=]​\\​s*​\"​?|​\"​initPassword​\"\\​s*:​\\​s*​\"​?|​\"​初始密码​\"\\​s*:​\\​s*​\"​?)[​\"​]?[^​\"\\​s]+[​\"​]?|​\\​b初始密码是​\\​s+[^​\"\\​s]+​",
}

class Z0SCAN(PluginBase):
    name = "sensi-js"
    desc = 'JS Sensitive Information Leak (with AI Context Validation)'
    version = "2025.3.4"
    risk = 0
        
    def audit(self):
        if not self.requests.suffix == ".js":
            return
            
        js_content = self.response.text
        for name, pattern in rules.items():
            matches = re.finditer(pattern, js_content, re.M | re.I)
            found_valid = False
            
            for match in matches:
                text = match.group()
                # 基础过滤
                ignores = ['function', 'encodeURIComponent', 'XMLHttpRequest']
                if any(ignore_word in text for ignore_word in ignores):
                    continue

                start_pos = max(0, match.start() - 100)
                end_pos = min(len(js_content), match.end() + 100)
                context = js_content[start_pos:end_pos]

                marked_context = (
                    context[:match.start()-start_pos] + 
                    "【SENSITIVE_START】" + 
                    context[match.start()-start_pos:match.end()-start_pos] + 
                    "【SENSITIVE_END】" + 
                    context[match.end()-start_pos:]
                )

                if conf.smartscan["enable"]:
                    valid, type, reason = self._ai_validate_with_context(marked_context, name, pattern)
                    if not valid:
                        continue

                result = self.generate_result()
                result.main({
                    "type": Type.ANALYZE,
                    "url": self.requests.url, 
                    "vultype": VulType.SENSITIVE, 
                    "show": {
                        "Match": f"{text}",
                        "Type": str(name) if not conf.smartscan["enable"] else type
                        }
                    })
                description = f"Found valid sensitive information using pattern {pattern}: {text}"
                if conf.smartscan["enable"]:
                    description += f", Analysis given by AI: {reason}"
                result.step("Request Details", {
                    "request": self.requests.raw, 
                    "response": self.response.raw, 
                    "description": description
                    })
                self.success(result)
                found_valid = True
                break
                
            if found_valid:
                break
                
    def _ai_validate_with_context(self, context, name, pattern):
        prompt = f"""
            Please analyze whether the marked sensitive information in the following JavaScript code is genuine:

            {context}


            Rule Name: {name}
            Matching mode: {pattern}

            Key points to consider:
            1. The context in which the information appears
            2. Whether it's in comments or test data
            3. Whether it matches common patterns for this type of sensitive information

            Respond strictly in the following JSON format:
            {{
                "valid": boolean,    // Whether it's valid sensitive info
                "confidence": float, // Confidence level (0.0~1.0)
                "type": string,     // Type of sensitive info (e.g., API key, password)
                "reason": string    // Detailed analysis rationale
            }}
        """
        
        try:
            response = chat(prompt)
            if not response:
                return False
                
            try:
                analysis = json.loads(response.content)
                # 置信度阈值到0.8
                if analysis.get('valid', False) and analysis.get('confidence', 0) > 0.8:
                    return True, analysis.get('type', ''), analysis.get('reason', '')
            except json.JSONDecodeError:
                logger.error(f"AI response format error, raw response: {response.content}")
                return False, None, None
                
        except Exception as e:
            logger.error(f"Error during AI validation: {e}")
            return False, None, None
            
        return False, None, None
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/6
# JiuZero 2025/3/4
# Referer: https://github.com/al0ne/Vxscan/blob/master/lib/jsparse.py
import re

from api import VulType, PLACE, Type, ResultObject, PluginBase, conf


class Z0SCAN(PluginBase):
    name = "JsSensitiveContent"
    desc = 'Js Sensitive Finder'

    def condition(self):
        if self.requests.suffix == ".js" and 0 in conf.level:
            return True
        return False
        
    def audit(self):
        if not self.condition():
            return
        regx = {
            # "url": r'(\b|\'|")(?:http:|https:)(?:[\w/\.]+)?(?:[a-zA-Z0-9_\-\.]{1,})\.(?:php|asp|ashx|jspx|aspx|jsp|json|action|html|txt|xml|do)(\b|\'|")',
            # "email": r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+',
            "token_password": r'\b(?:secret|secret_key|token|secret_token|auth_token|access_token|username|password|aws_access_key_id|aws_secret_access_key|secretkey|authtoken|accesstoken|access-token|authkey|client_secret|bucket|email|HEROKU_API_KEY|SF_USERNAME|PT_TOKEN|id_dsa|clientsecret|client-secret|encryption-key|pass|encryption_key|encryptionkey|secretkey|secret-key|bearer|JEKYLL_GITHUB_TOKEN|HOMEBREW_GITHUB_API_TOKEN|api_key|api_secret_key|api-key|private_key|client_key|client_id|sshkey|ssh_key|ssh-key|privatekey|DB_USERNAME|oauth_token|irc_pass|dbpasswd|xoxa-2|xoxrprivate-key|private_key|consumer_key|consumer_secret|access_token_secret|SLACK_BOT_TOKEN|slack_api_token|api_token|ConsumerKey|ConsumerSecret|SESSION_TOKEN|session_key|session_secret|slack_token|slack_secret_token|bot_access_token|passwd|api|eid|sid|api_key|apikey|userid|user_id|user-id)["\s]*(?::|=|=:|=>)["\s]*[a-z0-9A-Z]{8,64}"?',
            "ip": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            "cloudfront_cloud": r'[\w]+\.cloudfront\.net',
            "appspot_cloud": r'[\w\-.]+\.appspot\.com',
            "digitalocean_cloud": r'([\w\-.]*\.?digitaloceanspaces\.com\/?[\w\-.]*)',
            "google_cloud": r'(storage\.cloud\.google\.com\/[\w\-.]+)',
            "google_storage_api": r'([\w\-.]*\.?storage.googleapis.com\/?[\w\-.]*)',
            # "phone_number": r'(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|199|170|171)[0-9]{8}',
            # "host": r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:biz|cc|club|cn|com|co|edu|fun|group|info|ink|kim|link|live|ltd|mobi|net|online|org|pro|pub|red|ren|shop|site|store|tech|top|tv|vip|wang|wiki|work|xin|xyz|me))',
            "access Key": r'access_key.*?["\'](.*?)["\']',
            "access_key_id": r'accesskeyid.*?["\'](.*?)["\']',
            "sensitive_all_in_one": r'((?i)((access_key|appsecret|app_secret|access_token|password|secretkey|accesskey|accesskeyid|accesskeysecret|secret_key|pwd|test_user|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_.]{0,25})(=|>|:=|:|<=|=>|:).{0,5}[\'\"\ ]([0-9a-zA-Z-_=]{12,64})[\'\"\ ])',
            "cloud_access_key": r'([\'\"\ ](GOOG[\w\W]{10,30})[\'\"\ ]|([\'\"\ ]AZ[A-Za-z0-9]{34,40}[\'\"\ ])|([\'\"\ ]AKID[A-Za-z0-9]{13,20}[\'\"\ ])|([\'\"\ ]AKIA[A-Za-z0-9]{16}[\'\"\ ])|([\'\"\ ][a-zA-Z0-9]{8}(-[a-zA-Z0-9]{4}){3}-[a-zA-Z0-9]{12}[\'\"\ ])|([\'\"\ ]OCID[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]LTAI[A-Za-z0-9]{12,20}[\'\"\ ])|([\'\"\ ][A-Z0-9]{20}$[\'\"\ ])|([\'\"\ ]JDC_[A-Z0-9]{28,32}[\'\"\ ])|([\'\"\ ]AK[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]UC[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]QY[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]AKLT[a-zA-Z0-9-_]{16,28}[\'\"\ ])|([\'\"\ ]LTC[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]YD[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]CTC[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]YYT[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]YY[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]CI[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]gcore[A-Za-z0-9]{10,30}[\'\"\ ]))',
            "jwt": r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
            # "author": '@author[: ]+(.*?) ',
            'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
            'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
            'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
            'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
            'amazon_aws_url2' : r"(" \
                   r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
                   r"|s3://[a-zA-Z0-9-\.\_]+" \
                   r"|s3-[a-zA-Z0-9-\.\_\/]+" \
                   r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
                   r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
            "amazon_aws_url3": r'[\w\-.]*s3[\w\-.]*\.?amazonaws\.com\/?[\w\-.]*',
            'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
            'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
            'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
            # 'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
            # 'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
            # 'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
            # 'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
            # 'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
            # 'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            # 'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
            # 'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
            # 'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
            # 'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
            'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
            'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
            'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
            'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
            'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
            'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
            'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
            'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'possible_Creds' : r"(?i)(" \
                            r"password\s*[`=:\"]+\s*[^\s]+|" \
                            r"password is\s*[`=:\"]*\s*[^\s]+|" \
                            r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                            r"passwd\s*[`=:\"]+\s*[^\s]+)"
        }
        for name, _ in regx.items():
            texts = re.findall(_, self.response.text, re.M | re.I)
            issuc = False
            if texts:
                for text in set(texts):
                    ignores = ['function', 'encodeURIComponent', 'XMLHttpRequest']
                    is_continue = True

                    for i in ignores:
                        if i in text:
                            is_continue = False
                            break
                    if not is_continue:
                        continue

                    result = ResultObject(self)
                    result.init_info(Type.ANALYZE, self.requests.hostname, self.requests.url, VulType.SENSITIVE, PLACE.URL, msg="From Regx {} Find Sensitive Info {}".format(_, text))
                    result.add_detail("Request", self.requests.raw, self.response.raw, "From Regx {} Find Sensitive Info {}".format(_, text))
                    self.success(result)
                    issuc = True
                    break
            if issuc:
                break

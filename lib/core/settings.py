#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.core.enums import WEB_SERVER
from lib.core.data import logger

VERSION = '2025.3.22'
SITE = 'https://github.com/JiuZero/z0scan'
DEFAULT_USER_AGENT = "z0scan/#v%s (%s)" % (VERSION, SITE)

banner = """
{cy}__  _     __   _   _  _ _     
{cy} / (.\   (_ ` / ` /_) )\ )       {m}~ Z0SCAN : {b}v{v} ~
{cy}/_  \_) .__) (_. / / (  (.   {g}{s}{e}

""".format(s=SITE, v=VERSION, m=logger.m, cy=logger.cy, g=logger.g, b=logger.b, e=logger.e)

acceptedExt = [
    '.php', '.php3', '.php4', '.php5', '.php7', '.phtml',
    '.asp', '.aspx', '.ascx', '.asmx',
    '.chm', '.cfc', '.cfmx', '.cfml',
    '.py',
    '.rb',
    '.pl',
    '.cgi',
    '.jsp', '.jhtml', '.jhtm', '.jws',
    '.htm', '.html',
    '.do', '.action', ''
]

ignoreParams = ['submit', '_', '_t', 'rand', 'hash']

logoutParams = [
    'logout',
    'log_out',
    'loginesc',
    'loginout',
    'delete',
    'signout',
    'logoff',
    'signoff',
    'exit',
    'quit',
    'byebye',
    'bye-bye',
    'clearuser',
    'invalidate',
    'reboot',
    'shutdown',
]

GITHUB_REPORT_OAUTH_TOKEN = ""

# Default delimiter in cookie values
DEFAULT_COOKIE_DELIMITER = ';'

# Default delimiter in GET/POST values
DEFAULT_GET_POST_DELIMITER = '&'

# Regular expression used for detecting Array-like POST data
ARRAY_LIKE_RECOGNITION_REGEX = r"(\A|%s)(\w+)\[\]=.+%s\2\[\]=" % (
    DEFAULT_GET_POST_DELIMITER, DEFAULT_GET_POST_DELIMITER)

# Regular expression for XML POST data
XML_RECOGNITION_REGEX = r"(?s)\A\s*<[^>]+>(.+>)?\s*\Z"

# Regular expression used for detecting JSON POST data
JSON_RECOGNITION_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'

# Regular expression used for detecting JSON-like POST data
JSON_LIKE_RECOGNITION_REGEX = r"(?s)\A(\s*\[)*\s*\{.*'[^']+'\s*:\s*('[^']+'|\d+).*\}\s*(\]\s*)*\Z"

# Regular expression used for detecting multipart POST data
MULTIPART_RECOGNITION_REGEX = r"(?i)Content-Disposition:[^;]+;\s*name="

notAcceptedExt = [
    ".css",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".wmv",
    ".a3c",
    ".ace",
    ".aif",
    ".aifc",
    ".aiff",
    ".arj",
    ".asf",
    ".asx",
    ".attach",
    ".au",
    ".avi",
    ".bin",
    ".bmp",
    ".cab",
    ".cache",
    ".class",
    ".djv",
    ".djvu",
    ".dwg",
    ".es",
    ".esl",
    ".exe",
    ".fif",
    ".fvi",
    ".gz",
    ".hqx",
    ".ice",
    ".ico",
    ".ief",
    ".ifs",
    ".iso",
    ".jar",
    ".jpe",
    ".kar",
    ".mdb",
    ".mid",
    ".midi",
    ".mov",
    ".movie",
    ".mp",
    ".mp2",
    ".mp3",
    ".mp4",
    ".mpeg",
    ".mpeg2",
    ".mpg",
    ".mpg2",
    ".mpga",
    ".msi",
    ".pac",
    ".pdf",
    ".ppt",
    ".psd",
    ".qt",
    ".ra",
    ".ram",
    ".rar",
    ".rm",
    ".rpm",
    ".snd",
    ".svf",
    ".tar",
    ".tgz",
    ".tif",
    ".tiff",
    ".tpl",
    ".ttf",
    ".uff",
    ".wav",
    ".wma",
    ".zip",
    ".woff2"
]

XSS_EVAL_ATTITUDES = ['onbeforeonload', 'onsubmit', 'ondragdrop', 'oncommand', 'onbeforeeditfocus', 'onkeypress',
                      'onoverflow', 'ontimeupdate', 'onreset', 'ondragstart', 'onpagehide', 'onunhandledrejection',
                      'oncopy',
                      'onwaiting', 'onselectstart', 'onplay', 'onpageshow', 'ontoggle', 'oncontextmenu', 'oncanplay',
                      'onbeforepaste', 'ongesturestart', 'onafterupdate', 'onsearch', 'onseeking',
                      'onanimationiteration',
                      'onbroadcast', 'oncellchange', 'onoffline', 'ondraggesture', 'onbeforeprint', 'onactivate',
                      'onbeforedeactivate', 'onhelp', 'ondrop', 'onrowenter', 'onpointercancel', 'onabort',
                      'onmouseup',
                      'onbeforeupdate', 'onchange', 'ondatasetcomplete', 'onanimationend', 'onpointerdown',
                      'onlostpointercapture', 'onanimationcancel', 'onreadystatechange', 'ontouchleave',
                      'onloadstart',
                      'ondrag', 'ontransitioncancel', 'ondragleave', 'onbeforecut', 'onpopuphiding', 'onprogress',
                      'ongotpointercapture', 'onfocusout', 'ontouchend', 'onresize', 'ononline', 'onclick',
                      'ondataavailable', 'onformchange', 'onredo', 'ondragend', 'onfocusin', 'onundo', 'onrowexit',
                      'onstalled', 'oninput', 'onmousewheel', 'onforminput', 'onselect', 'onpointerleave', 'onstop',
                      'ontouchenter', 'onsuspend', 'onoverflowchanged', 'onunload', 'onmouseleave',
                      'onanimationstart',
                      'onstorage', 'onpopstate', 'onmouseout', 'ontransitionrun', 'onauxclick', 'onpointerenter',
                      'onkeydown', 'onseeked', 'onemptied', 'onpointerup', 'onpaste', 'ongestureend', 'oninvalid',
                      'ondragenter', 'onfinish', 'oncut', 'onhashchange', 'ontouchcancel', 'onbeforeactivate',
                      'onafterprint', 'oncanplaythrough', 'onhaschange', 'onscroll', 'onended', 'onloadedmetadata',
                      'ontouchmove', 'onmouseover', 'onbeforeunload', 'onloadend', 'ondragover', 'onkeyup',
                      'onmessage',
                      'onpopuphidden', 'onbeforecopy', 'onclose', 'onvolumechange', 'onpropertychange', 'ondblclick',
                      'onmousedown', 'onrowinserted', 'onpopupshowing', 'oncommandupdate', 'onerrorupdate',
                      'onpopupshown',
                      'ondurationchange', 'onbounce', 'onerror', 'onend', 'onblur', 'onfilterchange', 'onload',
                      'onstart',
                      'onunderflow', 'ondragexit', 'ontransitionend', 'ondeactivate', 'ontouchstart', 'onpointerout',
                      'onpointermove', 'onwheel', 'onpointerover', 'onloadeddata', 'onpause', 'onrepeat',
                      'onmouseenter',
                      'ondatasetchanged', 'onbegin', 'onmousemove', 'onratechange', 'ongesturechange',
                      'onlosecapture',
                      'onplaying', 'onfocus', 'onrowsdelete']

TOP_RISK_GET_PARAMS = {"id", 'action', 'type', 'm', 'callback', 'cb'}
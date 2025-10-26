#!/usr/bin/env python3
# @Time    : 2020-04-21
# @Author  : caicai
# @File    : importssti.py


from helper.ssti.engines.jinja2 import Jinja2
from helper.ssti.engines.dot import Dot
from helper.ssti.engines.twig import Twig
from helper.ssti.engines.ejs import Ejs
from helper.ssti.engines.erb import Erb
from helper.ssti.engines.mako import Mako
from helper.ssti.engines.marko import Marko
from helper.ssti.engines.nunjucks import Nunjucks
from helper.ssti.engines.pug import Pug
from helper.ssti.engines.slim import Slim
from helper.ssti.engines.smarty import Smarty
from helper.ssti.engines.tornado import Tornado
from helper.ssti.engines.velocity import Velocity
from helper.ssti.engines.freemarker import Freemarker
from helper.ssti.engines.dust import Dust
from helper.ssti.languages.javascript import Javascript
from helper.ssti.languages.php import Php
from helper.ssti.languages.python import Python
from helper.ssti.languages.ruby import Ruby
from lib.core.log import logger

plugins = [
    Smarty,
    Mako,
    Python,
    Tornado,
    Jinja2,
    Twig,
    Freemarker,
    Velocity,
    Slim,
    Erb,
    Pug,
    Nunjucks,
    Dot,
    Dust,
    Marko,
    Javascript,
    Php,
    Ruby,
    Ejs
]

def importssti():
    try:
        test_payloads=[]
        for plugin in plugins:
            current_plugin = plugin()
            test_payloads+=current_plugin.generate_payloads()
        return test_payloads
    except Exception as ex:
        logger.warning("import ssti payloads error:{}".format(ex))


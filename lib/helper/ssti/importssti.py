#!/usr/bin/env python3
# @Time    : 2020-04-21
# @Author  : caicai
# @File    : importssti.py


from lib.helper.ssti.engines.jinja2 import Jinja2
from lib.helper.ssti.engines.dot import Dot
from lib.helper.ssti.engines.twig import Twig
from lib.helper.ssti.engines.ejs import Ejs
from lib.helper.ssti.engines.erb import Erb
from lib.helper.ssti.engines.mako import Mako
from lib.helper.ssti.engines.marko import Marko
from lib.helper.ssti.engines.nunjucks import Nunjucks
from lib.helper.ssti.engines.pug import Pug
from lib.helper.ssti.engines.slim import Slim
from lib.helper.ssti.engines.smarty import Smarty
from lib.helper.ssti.engines.tornado import Tornado
from lib.helper.ssti.engines.velocity import Velocity
from lib.helper.ssti.engines.freemarker import Freemarker
from lib.helper.ssti.engines.dust import Dust
from lib.helper.ssti.languages.javascript import Javascript
from lib.helper.ssti.languages.php import Php
from lib.helper.ssti.languages.python import Python
from lib.helper.ssti.languages.ruby import Ruby
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


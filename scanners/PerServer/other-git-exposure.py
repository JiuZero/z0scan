#!/usr/bin/env python3
from lib.core.plugins import PluginBase
from lib.core.output import ResultObject
from lib.core.enums import VulType, Type

class GitExposurePlugin(PluginBase):
    name = "git_exposure"
    desc = "Detects exposed .git directories and files, like gitleaks"
    version = "2025.6.24"
    risk = 3

    def __init__(self):
        super().__init__()

    def audit(self):
        if self.name in self.KB.disable:
            return
            
        # Only scan if URL path is not empty
        if not self.requests.path or self.requests.path == "/":
            # Check for exposed .git directory
            url = self.requests.url.rstrip("/") + "/.git/"
            resp = self.req("URL", url)
            if resp and resp.status_code == 200 and "index" in resp.text.lower():
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST,
                    "url": url,
                    "vultype": VulType.GIT_EXPOSURE,
                    "show": {
                        "Description": "Exposed .git directory detected",
                        "URL": url
                    }
                })
                self.success(result)

        # Optionally, check for .git/config file exposure
        git_config_url = self.requests.url.rstrip("/") + "/.git/config"
        resp = self.req("URL", git_config_url)


        if resp and resp.status_code == 200 and "[core]" in resp.text:
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST,
                "url": git_config_url,
                "vultype": VulType.GIT_EXPOSURE,
                "show": {
                    "Description": "Exposed .git/config file detected",
                    "URL": git_config_url
                }
            })

            self.success(result)
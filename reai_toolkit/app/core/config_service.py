import configparser
import os

import idaapi

_CFG = ".reai.cfg"
_SECTION = "auth"
_DEFAULT_API_URL = "https://api.reveng.ai"
_DEFAULT_PORTAL_URL = "https://portal.reveng.ai"


class ConfigService:
    """INI-backed config: [auth] api_url, portal_url, api_key."""

    def __init__(self):
        self._path = os.path.join(idaapi.get_user_idadir(), _CFG)
        self._data = {
            "api_url": _DEFAULT_API_URL,
            "portal_url": _DEFAULT_PORTAL_URL,
            "api_key": "",
        }
        self.load()

    def load(self):
        cp = configparser.ConfigParser()
        if os.path.exists(self._path):
            try:
                cp.read(self._path, encoding="utf-8")
                s = cp[_SECTION] if _SECTION in cp else {}
                self._data["api_url"] = s.get("api_url", _DEFAULT_API_URL).rstrip("/")
                self._data["portal_url"] = s.get(
                    "portal_url", _DEFAULT_PORTAL_URL
                ).rstrip("/")
                self._data["api_key"] = s.get("api_key", "")
            except Exception:
                pass
        else:
            self.save()

    def save(self):
        cp = configparser.ConfigParser()
        cp[_SECTION] = self._data
        with open(self._path, "w", encoding="utf-8") as f:
            cp.write(f)

    def valid(self) -> bool:
        return (self.api_key != "") and (self.api_url != "") and (self.portal_url != "")

    @property
    def api_url(self):
        return self._data["api_url"]

    @api_url.setter
    def api_url(self, v):
        self._data["api_url"] = (v or _DEFAULT_API_URL).strip().rstrip("/")

    @property
    def portal_url(self):
        return self._data["portal_url"]

    @portal_url.setter
    def portal_url(self, v):
        self._data["portal_url"] = (v or _DEFAULT_PORTAL_URL).strip().rstrip("/")

    @property
    def api_key(self):
        return self._data["api_key"]

    @api_key.setter
    def api_key(self, v):
        self._data["api_key"] = (v or "").strip()

    def as_dict(self):
        return dict(self._data)

from enum import StrEnum


class HostKind(StrEnum):
    WEB_APP = "web_app"
    API = "api"
    MAIL = "mail"
    LOGIN_PANEL = "login_panel"
    DOCS = "docs"
    BLOG = "blog"
    REDIRECT = "redirect"
    NO_SERVICE = "no_service"

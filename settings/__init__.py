from os import environ


DEBUG = False
SECRET_KEY = None
SQLALCHEMY_DATABASE_URI = 'sqlite:///trello-mailgun.db'
TRELLO_API_KEY = None
TRELLO_API_SECRET = None


# Settings from ENV

_locals = locals()


for key in _locals.keys():
    if key.isupper():
        value = environ.get(key)
        if value:
            _locals[key] = value


# Settings from python file

try:
    from production import *
except ImportError:
    pass

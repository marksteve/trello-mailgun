import json

from os import environ


DEBUG = False
SECRET_KEY = None
SQLALCHEMY_DATABASE_URI = 'sqlite:///trello-mailgun.db'
TRELLO_API_KEY = None
TRELLO_API_SECRET = None
MAILGUN_API_KEY = None


# Settings from ENV

_locals = locals()


for key in _locals.keys():
    if key.isupper():
        value = environ.get(key)
        if value:
            _locals[key] = value


# Settings from AppFog

services = json.loads(environ.get('VCAP_SERVICES', '{}'))
service = services.get('mysql-5.1')
if service:
    credentials = service.pop()['credentials']
    SQLALCHEMY_DATABASE_URI = 'mysql://%s:%s@%s:%s/%s' % (
        credentials['username'],
        credentials['password'],
        credentials['hostname'],
        credentials['port'],
        credentials['name'])

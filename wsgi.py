import settings

import json
import requests
import urllib
import urlparse

from flask import (Flask, url_for, redirect, request, session, render_template,
                   flash)
from flask_sqlalchemy import SQLAlchemy
from oauth_hook import OAuthHook
from sqlalchemy.dialects.mysql import VARCHAR

TRELLO_REQUEST_TOKEN_URL = 'https://trello.com/1/OAuthGetRequestToken'
TRELLO_AUTHORIZE_URL = 'https://trello.com/1/OAuthAuthorizeToken'
TRELLO_ACCESS_TOKEN_URL = 'https://trello.com/1/OAuthGetAccessToken'
TRELLO_SCOPES = 'read,write'


app = application = Flask(__name__)
app.config.update(
    DEBUG=settings.DEBUG,
    SECRET_KEY=settings.SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=settings.SQLALCHEMY_DATABASE_URI,
)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(VARCHAR(255), primary_key=True)
    email = db.Column(VARCHAR(255))
    oauth_token = db.Column(VARCHAR(255))
    oauth_token_secret = db.Column(VARCHAR(255))


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    oauth_verifier = request.args.get('oauth_verifier')
    consumer = {
        'consumer_key': settings.TRELLO_API_KEY,
        'consumer_secret': settings.TRELLO_API_SECRET,
    }
    if not oauth_verifier:
        # Get request token
        oauth_hook = OAuthHook(**consumer)
        trello_client = requests.session(hooks={'pre_request': oauth_hook})
        response = trello_client.post(TRELLO_REQUEST_TOKEN_URL)
        request_token = dict(urlparse.parse_qsl(response.content))
        session['request_token'] = request_token
        # Authorize
        params = {
            'oauth_token': request_token['oauth_token'],
            'scope': TRELLO_SCOPES,
            'return_url': url_for('setup', _external=True),
            'name': 'Trello-Mailgun',
            'expiration': 'never',
        }
        return redirect(TRELLO_AUTHORIZE_URL + '?' + urllib.urlencode(params))
    else:
        # Get access token
        request_token = session.get('request_token')
        oauth_hook = OAuthHook(
            access_token=request_token['oauth_token'],
            access_token_secret=request_token['oauth_token_secret'],
            **consumer)
        trello_client = requests.session(hooks={'pre_request': oauth_hook})
        response = trello_client.post(TRELLO_ACCESS_TOKEN_URL,
                                      data={'oauth_verifier': oauth_verifier})
        access_token = dict(urlparse.parse_qsl(response.content))
        # Get user details
        oauth_hook = OAuthHook(
            access_token=access_token['oauth_token'],
            access_token_secret=access_token['oauth_token_secret'],
            **consumer)
        trello_client = requests.session(hooks={'pre_request': oauth_hook})
        response = trello_client.get('https://trello.com/1/members/me')
        trello_user = json.loads(response.content)
        # Store user info
        is_stored = False
        if request.method == 'POST':
            if not request.form.get('email'):
                flash("We need your email")
            else:
                # Store user details
                db.session.add(User(
                    id=trello_user['id'],
                    email=request.form['email'],
                    oauth_token=access_token['oauth_token'],
                    oauth_token_secret=access_token['oauth_token_secret']))
                db.session.commit()
                flash("You're done!")
                is_stored = True
        return render_template('setup.html', trello_user=trello_user,
                               is_stored=is_stored)


if __name__ == '__main__':
    app.run()

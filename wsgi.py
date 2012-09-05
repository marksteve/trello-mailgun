import settings

import re
import requests
import urllib
import urlparse

from flask import (Flask, url_for, redirect, request, session, render_template,
                   flash, abort, Response)
from flask_sqlalchemy import SQLAlchemy
from oauth_hook import OAuthHook
from requests.auth import HTTPBasicAuth
from sqlalchemy.dialects.mysql import VARCHAR

TRELLO_API_ENDPOINT = 'https://trello.com/1/%s'
MAILGUN_API_ENDPOINT = 'https://api.mailgun.net/v2/%s'
TRELLO_SCOPES = 'read,write'
EMAIL_PAT = re.compile('<?(\w+@[^@>]+)>?$')


app = application = Flask(__name__)
app.config.update(
    DEBUG=settings.DEBUG,
    SECRET_KEY=settings.SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=settings.SQLALCHEMY_DATABASE_URI,
)
db = SQLAlchemy(app)
consumer = {
    'consumer_key': settings.TRELLO_API_KEY,
    'consumer_secret': settings.TRELLO_API_SECRET,
}


class User(db.Model):
    id = db.Column(VARCHAR(255), primary_key=True)
    email = db.Column(VARCHAR(255))
    oauth_token = db.Column(VARCHAR(255))
    oauth_token_secret = db.Column(VARCHAR(255))
    route_id = db.Column(VARCHAR(255))


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    oauth_verifier = request.args.get('oauth_verifier')
    if not oauth_verifier:
        # Get request token
        oauth_hook = OAuthHook(**consumer)
        trello_client = requests.session(hooks={'pre_request': oauth_hook})
        response = trello_client.post(TRELLO_API_ENDPOINT %
                                      'OAuthGetRequestToken')
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
        return redirect(TRELLO_API_ENDPOINT % 'OAuthAuthorizeToken' + '?' +
                        urllib.urlencode(params))
    else:
        # Get access token
        request_token = session['request_token']
        oauth_hook = OAuthHook(
            access_token=request_token['oauth_token'],
            access_token_secret=request_token['oauth_token_secret'],
            **consumer)
        trello_client = requests.session(hooks={'pre_request': oauth_hook})
        response = trello_client.post(
            TRELLO_API_ENDPOINT % 'OAuthGetAccessToken',
            data={'oauth_verifier': oauth_verifier})
        access_token = dict(urlparse.parse_qsl(response.content))
        # Get user details
        oauth_hook = OAuthHook(
            access_token=access_token['oauth_token'],
            access_token_secret=access_token['oauth_token_secret'],
            **consumer)
        trello_client = requests.session(hooks={'pre_request': oauth_hook})
        trello_user = (trello_client.get(TRELLO_API_ENDPOINT % 'members/me')
                       .json)
        # Get lists
        trello_boards = trello_client.get(TRELLO_API_ENDPOINT %
            'members/me/boards?filter=open&organization=true&lists=open').json
        # Store user info
        is_stored = False
        if request.method == 'POST':
            email = request.form.get('email')
            list_id = request.form.get('list_id')
            if not email:
                flash("We need your email")
            elif not list_id:
                flash("Select a list to add your cards to")
            else:
                data = {
                    'expression': 'match_header("From", ".*%s")' % email,
                    'action': 'forward("%s")' % url_for('create_card',
                                                        list_id=list_id,
                                                        _external=True),
                }
                route = (requests.post(MAILGUN_API_ENDPOINT % 'routes',
                         data=data,
                         auth=HTTPBasicAuth('api', settings.MAILGUN_API_KEY))
                         .json['route'])
                # Store user details
                db.session.add(User(
                    id=trello_user['id'],
                    email=email,
                    oauth_token=access_token['oauth_token'],
                    oauth_token_secret=access_token['oauth_token_secret'],
                    route_id=route['id']))
                db.session.commit()
                session.pop('request_token')
                flash("You're done!")
                is_stored = True
        return render_template('setup.html', trello_user=trello_user,
                               trello_boards=trello_boards,
                               is_stored=is_stored)


def _get_email(s):
    match = EMAIL_PAT.search(s)
    if match:
        return match.group(1)
    else:
        return


@app.route('/create_card/<list_id>', methods=['POST'])
def create_card(list_id):
    # Get user
    email = _get_email(request.form['From'])
    if not email:
        abort(400)
    user = User.query.filter_by(email=email).first_or_404()
    # Set trello client
    oauth_hook = OAuthHook(
        access_token=user.oauth_token,
        access_token_secret=user.oauth_token_secret,
        **consumer)
    trello_client = requests.session(hooks={'pre_request': oauth_hook})
    # Create card
    data = {
        'name': request.form['Subject'],
        'desc': request.form['body-plain'],
        'idList': list_id,
    }
    card = trello_client.post(TRELLO_API_ENDPOINT % 'cards', data=data).json
    # Add members from cc addresses
    for cc in request.form['Cc'].split(','):
        email = _get_email(cc)
        if not email:
            continue
        cc_user = User.query.filter_by(email=email).first()
        if not cc_user:
            continue
        data = {
            'value': cc_user.id,
        }
        trello_client.post(
            TRELLO_API_ENDPOINT % 'cards/%s/members' % card['id'],
            data)
    return Response()


if __name__ == '__main__':
    app.run()

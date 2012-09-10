import settings

import json
import re
import requests
import urllib
import urlparse

from flask import (Flask, url_for, redirect, request, session, render_template,
                   abort, jsonify)
from flask_sqlalchemy import SQLAlchemy
from oauth_hook import OAuthHook
from requests.auth import HTTPBasicAuth
from sqlalchemy.dialects.mysql import VARCHAR, TEXT

TRELLO_API_ENDPOINT = 'https://trello.com/1/%s'
MAILGUN_API_ENDPOINT = 'https://api.mailgun.net/v2/%s'
TRELLO_SCOPES = 'read,write'
EMAIL_PAT = re.compile('<?(\w+@[^@>]+)>?$')


app = application = Flask(__name__)
app.config.update(
    DEBUG=settings.DEBUG,
    SECRET_KEY=settings.SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=settings.SQLALCHEMY_DATABASE_URI)
db = SQLAlchemy(app)
consumer = {
    'consumer_key': settings.TRELLO_API_KEY,
    'consumer_secret': settings.TRELLO_API_SECRET,
}


class User(db.Model):
    email = db.Column(VARCHAR(255), primary_key=True)
    trello_id = db.Column(VARCHAR(255), primary_key=True)
    trello_lists = db.Column(TEXT)
    trello_oauth_token = db.Column(VARCHAR(255))
    trello_oauth_token_secret = db.Column(VARCHAR(255))
    mailgun_route_id = db.Column(VARCHAR(255))

    def to_dict(self):
        kv_pairs = []
        for key in 'email', 'trello_id', 'trello_lists':
            kv_pairs.append((key, getattr(self, key)))
        return dict(kv_pairs)


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    # Get request token
    request_token = session.get('request_token')
    if not request_token:
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

    # Get access token
    access_token = session.get('access_token')
    if not access_token:
        oauth_verifier = request.args.get('oauth_verifier')
        request_token = session['request_token']
        oauth_hook = OAuthHook(
            access_token=request_token['oauth_token'],
            access_token_secret=request_token['oauth_token_secret'],
            **consumer)
        trello_client = requests.session(hooks={'pre_request': oauth_hook})
        response = trello_client.post(
            TRELLO_API_ENDPOINT % 'OAuthGetAccessToken',
            data={'oauth_verifier': oauth_verifier})
        session['access_token'] = dict(urlparse.parse_qsl(response.content))
        return redirect(url_for('setup'))

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
    if request.method == 'POST':
        email = request.json.get('email')
        trello_lists = request.json.get('lists')
        if not email:
            return jsonify({'error': "We need your mail"}), 400
        elif not trello_lists:
            return jsonify({'error': "You need to add at least one list"}), 400
        else:
            # Add route
            # FIXME: Handle exceptions
            auth = HTTPBasicAuth('api', settings.MAILGUN_API_KEY)
            data = {
                'expression': 'match_header("From", ".*%s")' % email,
                'action': 'forward("%s")' % url_for('create_card',
                    trello_user_id=trello_user['id'], _external=True),
            }
            route = (requests.post(MAILGUN_API_ENDPOINT % 'routes',
                     data=data, auth=auth).json['route'])
            # Store user details
            user = User(
                email=email,
                trello_id=trello_user['id'],
                trello_lists=json.dumps(trello_lists),
                trello_oauth_token=access_token['oauth_token'],
                trello_oauth_token_secret=access_token['oauth_token_secret'],
                mailgun_route_id=route['id'])
            db.session.add(user)
            # Save
            db.session.commit()
            # Clear session
            session.pop('request_token')
            session.pop('access_token')
            return jsonify(user.to_dict())
    return render_template('setup.html', trello_user=trello_user,
                           trello_boards=trello_boards)


def _get_email(s):
    match = EMAIL_PAT.search(s)
    if match:
        return match.group(1)
    else:
        return


@app.route('/create_card/<trello_user_id>', methods=['POST'])
def create_card(trello_user_id):
    # Get user
    user = User.query.get((_get_email(request.form['From']), trello_user_id))
    if not user:
        abort(404)
    # Get lists
    subject = request.form['Subject']
    trello_lists = json.loads(user.trello_lists)
    matched_lists = []
    for trello_list in trello_lists:
        if trello_list['keyword'] in subject:
            matched_lists.append(trello_list)
    if not matched_lists:
        abort(404)
    # Set trello client
    oauth_hook = OAuthHook(
        access_token=user.trello_oauth_token,
        access_token_secret=user.trello_oauth_token_secret,
        **consumer)
    trello_client = requests.session(hooks={'pre_request': oauth_hook})
    # Create cards
    cards = []
    for trello_list in matched_lists:
        data = {
            'name': subject,
            'desc': request.form['body-plain'],
            'idList': trello_list['list_id'],
        }
        card = (trello_client.post(TRELLO_API_ENDPOINT % 'cards', data=data)
                .json)
        cards.append(card)
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
    return jsonify({'cards': cards})


if __name__ == '__main__':
    app.run()

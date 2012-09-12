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


@app.route('/')
def index():
    return render_template('index.html')


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

    # Get Trello user details
    oauth_hook = OAuthHook(
        access_token=access_token['oauth_token'],
        access_token_secret=access_token['oauth_token_secret'],
        **consumer)
    trello_client = requests.session(hooks={'pre_request': oauth_hook})
    trello_user = (trello_client.get(TRELLO_API_ENDPOINT % 'members/me')
                   .json)
    # Get boards
    trello_boards = trello_client.get(TRELLO_API_ENDPOINT %
        'members/me/boards?filter=open&organization=true&lists=open').json
    # Get user if exists
    user = User.query.filter_by(trello_id=trello_user['id']).first()
    email = user.email if user else ''
    trello_lists = []
    if user:
        curr_trello_lists = json.loads(user.trello_lists)
        for trello_board in trello_boards:
            board_name = trello_board['name']
            organization = trello_board.get('organization')
            if organization:
                board_name = organization['name'] + '/' + board_name
            for trello_list in trello_board.get('lists', []):
                if trello_list['id'] in curr_trello_lists:
                    trello_lists.append({
                        'list_id': trello_list['id'],
                        'keyword': curr_trello_lists[trello_list['id']],
                        'list_name': board_name + '/' + trello_list['name'],
                    })
    # Store user info
    if request.method == 'POST':
        email = request.json.get('email')
        trello_lists = request.json.get('lists')
        if not email:
            return jsonify({'error': "We need your mail"}), 400
        elif not trello_lists:
            return jsonify({'error': "You need to add at least one list"}), 400
        else:
            if user:
                user.email = email
                user.trello_id = trello_user['id']
                user.trello_lists = json.dumps(trello_lists)
                user.trello_oauth_token = access_token['oauth_token']
                user.trello_oauth_token_secret = (
                    access_token['oauth_token_secret']
                )
            else:
                # Add route
                # FIXME: Handle exceptions
                auth = HTTPBasicAuth('api', settings.MAILGUN_API_KEY)
                data = {
                    'expression': 'match_header("From", ".*%s")' % email,
                    'action': 'forward("%s")' % url_for('create_card',
                        trello_id=trello_user['id'], _external=True),
                }
                route = (requests.post(MAILGUN_API_ENDPOINT % 'routes',
                         data=data, auth=auth).json['route'])
                # Store user details
                user = User(
                    email=email,
                    trello_id=trello_user['id'],
                    trello_lists=json.dumps(trello_lists),
                    trello_oauth_token=access_token['oauth_token'],
                    trello_oauth_token_secret=(
                        access_token['oauth_token_secret']
                    ),
                    mailgun_route_id=route['id'])
            db.session.add(user)
            # Save
            db.session.commit()
            return jsonify(user.to_dict())
    return render_template('setup.html', trello_user=trello_user,
                           trello_boards=trello_boards, user=user, email=email,
                           trello_lists=trello_lists)


def _get_email(s):
    match = EMAIL_PAT.search(s)
    if match:
        return match.group(1)
    else:
        return


@app.route('/create_card/<trello_id>', methods=['POST'])
def create_card(trello_id):
    # Get user
    user = User.query.get((_get_email(request.form['From']), trello_id))
    if not user:
        abort(404)
    # Get lists
    subject = request.form['Subject']
    trello_lists = json.loads(user.trello_lists)
    trello_list_ids = []
    for list_id, keyword in trello_lists.items():
        if keyword in subject:
           trello_list_ids.append(list_id)
    if not trello_list_ids:
        abort(404)
    # Set trello client
    oauth_hook = OAuthHook(
        access_token=user.trello_oauth_token,
        access_token_secret=user.trello_oauth_token_secret,
        **consumer)
    trello_client = requests.session(hooks={'pre_request': oauth_hook})
    # Create cards
    cards = []
    for list_id in trello_list_ids:
        data = {
            'name': subject,
            'desc': request.form['body-plain'],
            'idList': list_id,
        }
        card = (trello_client.post(TRELLO_API_ENDPOINT % 'cards', data=data)
                .json)
        cards.append(card)
        # Add members from cc addresses
        for cc in request.form.get('Cc', '').split(','):
            email = _get_email(cc)
            if not email:
                continue
            cc_user = User.query.filter_by(email=email).first()
            if not cc_user:
                continue
            data = {
                'value': cc_user.trello_id,
            }
            trello_client.post(
                TRELLO_API_ENDPOINT % 'cards/%s/members' % card['id'],
                data)
    return jsonify({'cards': cards})


if __name__ == '__main__':
    app.run()

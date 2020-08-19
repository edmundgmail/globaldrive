import os
import flask
import requests
import base64

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from google.oauth2 import id_token
from google.auth.transport import requests

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
from flask import Blueprint

CLIENT_SECRETS_FILE = "client_secrets.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'

gdrive = Blueprint('gdrive', __name__)

@gdrive.route('/<accountname>')
def bucketinfo(accountname):
  accountname = base64.b64decode(accountname).decode('ascii')
  if 'credentials.'+accountname not in flask.session:
    return flask.redirect(flask.url_for('gdrive.authorize', accountname=base64.b64encode(accountname.encode('ascii')).decode('ascii')))

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials.'+accountname])

  drive = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)

  files = drive.files().list().execute()

  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  flask.session['credentials.'+accountname] = credentials_to_dict(credentials)

  return flask.jsonify(**files)


@gdrive.route('/authorize/<accountname>')
def authorize(accountname):
  accountname = base64.b64decode(accountname).decode('ascii')
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('gdrive.oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      #access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state
  flask.session['accountname']=accountname
  return flask.redirect(authorization_url)


@gdrive.route('/callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']
  accountname=flask.session['accountname']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('gdrive.oauth2callback',  _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  idinfo = id_token.verify_oauth2_token(credentials.id_token, requests.Request(), credentials.client_id)
  accountname1 = idinfo['email']
  if(accountname!=accountname1):
      raise TypeError("The account authorized is not equal to the account asked for")

  flask.session['credentials.'+accountname] = credentials_to_dict(credentials)

  return flask.redirect(flask.url_for('gdrive.bucketinfo', accountname=base64.b64encode(accountname.encode('ascii')).decode('ascii')))


@gdrive.route('/revoke/<accountname>')
def revoke(accountname):
  accountname = base64.b64decode(accountname).decode('ascii')
  if 'credentials.'+accountname not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials.'+accountname])

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.')
  else:
    return('An error occurred.')


@gdrive.route('/clear/<accountname>')
def clear_credentials(accountname):
  accountname = base64.b64decode(accountname).decode('ascii')
  if 'credentials.'+accountname in flask.session:
    del flask.session['credentials.'+accountname]
  return ('Credentials have been cleared.')


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

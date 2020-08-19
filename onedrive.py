import flask, os, base64
from flask import Blueprint
from requests_oauthlib import OAuth2Session

from auth_helper import get_sign_in_url, store_token, store_user, get_user, get_token_from_code, \
  remove_user_and_token

onedrive = Blueprint('onedrive', __name__, template_folder='templates')
graph_url = 'https://graph.microsoft.com/v1.0'

@onedrive.route('/onedrive/<accountname>')
def test_api_request(accountname):
  accountname = base64.b64decode(accountname).decode('ascii')
  if 'onedrive.token.'+accountname not in flask.session:
    return flask.redirect(flask.url_for('onedrive.authorize', accountname=base64.b64encode(accountname.encode('ascii')).decode('ascii')))

  # Load credentials from the session.
  token = flask.session['onedrive.token.'+accountname]

  graph_client = OAuth2Session(token=token)
  drive = graph_client.get('{0}/me/drive'.format(graph_url))
  return drive

  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.

@onedrive.route('/onedrive/authorize/<accountname>')
def authorize(accountname):
  accountname = base64.b64decode(accountname).decode('ascii')

  flask.session['accountname']=accountname
  sign_in_url, state = get_sign_in_url()
  # Redirect to the Azure sign-in page
  return flask.redirect(sign_in_url)


@onedrive.route('/onedrive/callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  accountname=flask.session['accountname']
  # Get the state saved in session
  expected_state = ''
  # Make the token request
  token = get_token_from_code(flask.request.full_path, expected_state)

  # Get the user's profile
  user = get_user(token)

  if accountname != user['userPrincipalName']:
    raise TypeError("The authorized account name is not the same as we asked for")
  # Save token and user
  flask.session['onedrive.token.'+accountname] = token
  flask.session.pop('accountname', '')

  return flask.redirect(flask.url_for('onedrive.test_api_request', accountname=base64.b64encode(accountname.encode('ascii')).decode('ascii')))


@onedrive.route('/onedrive/revoke/<accountname>')
def revoke(accountname):
  pass

@onedrive.route('/onedrive/clear/<accountname>')
def clear_credentials(accountname):
  pass

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

def print_index_table():
  return ('<table>' +
          '<tr><td><a href="/test">Test an API request</a></td>' +
          '<td>Submit an API request and see a formatted JSON response. ' +
          '    Go through the authorization flow if there are no stored ' +
          '    credentials for the user.</td></tr>' +
          '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
          '<td>Go directly to the authorization flow. If there are stored ' +
          '    credentials, you still might not be prompted to reauthorize ' +
          '    the application.</td></tr>' +
          '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
          '<td>Revoke the access token associated with the current user ' +
          '    session. After revoking credentials, if you go to the test ' +
          '    page, you should see an <code>invalid_grant</code> error.' +
          '</td></tr>' +
          '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
          '<td>Clear the access token currently stored in the user session. ' +
          '    After clearing the token, if you <a href="/test">test the ' +
          '    API request</a> again, you should go back to the auth flow.' +
          '</td></tr></table>')




# Copyright (c) Microsoft Corporation.
# <HomeViewSnippet>

# <SignInViewSnippet>
def sign_in(request):
  # Get the sign-in URL
  sign_in_url, state = get_sign_in_url()
  # Save the expected state so we can validate in the callback
  request.session['auth_state'] = state
  # Redirect to the Azure sign-in page
  return flask.redirect(sign_in_url)
# </SignInViewSnippet>

def mydrive(accountname):
  pass

# <SignOutViewSnippet>
def sign_out(request):
  # Clear out the user and token
  remove_user_and_token(request)

  return 'singed out'
# </SignOutViewSnippet>

# <CallbackViewSnippet>
def callback(request):
  # Get the state saved in session
  expected_state = request.session.pop('auth_state', '')
  # Make the token request
  token = get_token_from_code(request.get_full_path(), expected_state)

  # Get the user's profile
  user = get_user(token)

  # Save token and user
  store_token(request, token)
  store_user(request, user)
  accountname = user.email #todo
  return flask.redirect(flask.url_for('onedrive.mydrive', accountname=base64.b64encode(accountname.encode('ascii')).decode('ascii')))
# </CallbackViewSnippet>

if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
  os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'


  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  onedrive.run('localhost', 8080, debug=True, ssl_context="adhoc")
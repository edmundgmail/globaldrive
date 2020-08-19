import flask, os, base64
from flask import Blueprint
from requests_oauthlib import OAuth2Session
from models import FileStructure
from flask.json import jsonify

from auth_helper import get_sign_in_url, store_token, store_user, get_user, get_token_from_code, \
  remove_user_and_token

onedrive = Blueprint('onedrive', __name__)
graph_url = 'https://graph.microsoft.com/v1.0'

@onedrive.route('/<accountname>')
@onedrive.route('/<accountname>/<path:varargs>')
def bucketinfo(accountname, varargs=None):
  accountname = base64.b64decode(accountname).decode('ascii')
  if 'onedrive.token.'+accountname not in flask.session:
    return flask.redirect(flask.url_for('onedrive.authorize', accountname=base64.b64encode(accountname.encode('ascii')).decode('ascii')))

  # Load credentials from the session.
  token = flask.session['onedrive.token.'+accountname]

  graph_client = OAuth2Session(token=token)
  if varargs == None:
    url = '{0}/me/drive'.format(graph_url)
  else:
    varargs = varargs.split("/")
    if len(varargs) <= 1:
       url = '{0}/me/drive/root/children'.format(graph_url)
    else:
      driveid = varargs[0]
      paths = "/".join(varargs[1:])
      url = '{0}/drives/{1}/root:/{2}:/children'.format(graph_url, driveid, paths)

  drive = graph_client.get(url)
  return drive.text

  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.

@onedrive.route('/authorize/<accountname>')
def authorize(accountname):
  accountname = base64.b64decode(accountname).decode('ascii')

  flask.session['accountname']=accountname
  sign_in_url, state = get_sign_in_url()
  # Redirect to the Azure sign-in page
  return flask.redirect(sign_in_url)


@onedrive.route('/callback')
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

  return flask.redirect(flask.url_for('onedrive.bucketinfo', accountname=base64.b64encode(accountname.encode('ascii')).decode('ascii')))

@onedrive.route('/revoke/<accountname>')
def revoke(accountname):
  pass

@onedrive.route('/clear/<accountname>')
def clear_credentials(accountname):
  pass


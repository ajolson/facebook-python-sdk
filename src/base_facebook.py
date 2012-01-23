from abc import ABCMeta, abstractmethod
from base64 import urlsafe_b64decode
import json
import hashlib
import urllib
from uuid import uuid4
from urlparse import parse_qs

from facebook_exception import FacebookApiError

class BaseFacebook(object):
	"""
	Provides access to the Facebook Platform.  This class provides
 	a majority of the functionality needed, but the class is abstract
 	because it is designed to be sub-classed.  The subclass must
	implement the four abstract methods listed at the bottom of
 	the file.
	"""

	__metaclass__ = ABCMeta # "i never meta class i didn't like..."

	VERSION = "3.1.1" # follows the official php version mirrored

	# List of query parameters that get automatically dropped when rebuilding
	# the current URL.
	DROP_QUERY_PARAMS = [
		'code',
		'state',
		'signed_request'
	]

	# Maps aliases to Facebook domains.
	DOMAIN_MAP = {
		'api'       : 'https://api.facebook.com/',
		'api_video' : 'https://api-video.facebook.com/',
		'api_read'  : 'https://api-read.facebook.com/',
		'graph'     : 'https://graph.facebook.com/',
		'www'       : 'https://www.facebook.com/',
	}

	# FB credentials
	app_id = None
	app_secret = None

	# Indicates if the CURL based @ syntax for file uploads is enabled.
	file_upload_support = None
	# The OAuth access token received in exchange for a valid authorization
	# code.  None means the access token has yet to be determined.
	access_token = None

	# ID of the Facebook user, or 0 if the user is logged out.
	user = None
	# Data from the signed_request token.
	signed_request = None
	# A CSRF state variable to assist in the defense against CSRF attacks.
	state = None

	# internal storage of cookies and requests
	request = None
	cookies = None


	def set_app_id(self, app_id):
		self.app_id = app_id
		return self
	def get_app_id(self):
		return self.app_id

	def set_app_secret(self, app_secret):
		self.app_secret = app_secret
		return self
	def get_app_secret(self):
		return self.app_secret

	def set_file_upload_support(self, file_upload):
		self.file_upload_support = file_upload
		return self
	def get_file_upload_support(self):
		return self.file_upload_support

	# Determines the access token that should be used for API calls.
	# The first time this is called, $this->accessToken is set equal
	# to either a valid user access token, or it's set to the application
	# access token if a valid user access token wasn't available.  Subsequent
	# calls return whatever the first call returned.
	# @return string The access token
	def get_access_token(self):
		return self.access_token

	# Sets the access token for api calls.  Use this if you get
	# your access token by other means and just want the SDK
	# to use it.
	#
	# @param string $access_token an access token.
	# @return BaseFacebook
	def set_access_token(self, access_token):
		self.access_token = access_token
		return self



	# Initialize a Facebook Application.
	# The configuration:
	# - app_id: the application ID
	# - secret: the application secret
	# - file_upload: (optional) boolean indicating if file uploads are enabled
	# @param dictionary config The application configuration
	def __init__(self, config):
		self.set_app_id(config['app_id'])
		self.set_app_secret(config['secret'])
		if 'file_upload' in config:
			self.set_file_upload_support(config['file_upload'])

		state = self.get_persistent_data('state')
		if state is not None:
			self.state = state




	# Determines and returns the user access token, first using
	# the signed request if present, and then falling back on
	# the authorization code if present.  The intent is to
	# return a valid user access token, or false if one is determined
	# to not be available.
	#
	# @return string A valid user access token, or false if one
	#                could not be determined.
	#
	def get_user_access_token(self):
		# first, consider a signed request if it's supplied.
		# if there is a signed request, then it alone determines
		# the access token.
		signed_request = self.get_signed_request()
		if signed_request:
			# apps.facebook.com hands the access_token in the signed_request
			if 'oauth_token' in signed_request:
				access_token = signed_request['oauth_token']
				self.set_persistent_data('access_token', access_token)
				return access_token
			# the JS SDK puts a code in with the redirect_uri of ''
			if 'code' in signed_request:
				code = signed_request['code']
				access_token = self.get_access_token_from_code(code, '')
				if access_token:
					self.set_persistent_data('code', code)
					self.set_persistent_data('access_token', access_token)
					return access_token

			# signed request states there's no access token, so anything
			# stored should be cleared.
			self.clear_all_persistent_data()
			# respect the signed request's data, even
			#// if there's an authorization code or something else
			return False

		code = self.get_code()
		if code and code != self.get_persistent_data('code'):
			access_token = self.get_access_token_from_code(code)
			if access_token:
				self.set_persistent_data('code', code)
				self.set_persistent_data('access_token', access_token)
				return access_token
			# code was bogus, so everything based on it should be invalidated
			self.clear_all_persistent_data()
			return False

		# as a fallback, just return whatever is in the persistent
		# store, knowing nothing explicit (signed request, authorization
		# code, etc.) was present to shadow it (or we saw a code in $_REQUEST,
		# but it's the same as what's in the persistent store)
		return self.get_persistent_data('access_token')




	#* Retrieve the signed request, either from a request parameter or,
	#* if not present, from a cookie.
	#*
	#* @return string the signed request, if available, or null otherwise.
	def get_signed_request(self):
		# TODO: we're gonna have to get access to cookies and requests here
#		raise Exception('not yet implemented!')
		if not self.signed_request:
			if getattr(self.request, 'signed_request', None):
				self.signed_request = self.parse_signed_request(getattr(self.request, 'signed_request', None))
			elif getattr(self.cookies, self.get_signed_request_cookie_name(), None):
				self.signed_request = self.parse_signed_request(getattr(self.cookies, self.get_signed_request_cookie_name()))
		return self.signed_request



	# Get the UID of the connected user, or 0
	# if the Facebook user is not connected.
	#
	# @return string the UID if available.
	def get_user(self):
		if self.user is not None:
			# we've already determined this and cached the value
			return self.user
		self.user = self.get_user_from_available_data()
		return self.user


	# Determines the connected user by first examining any signed
	# requests, then considering an authorization code, and then
	# falling back to any persistent store storing the user.
	#
	# @return integer The id of the connected Facebook user,
	#                 or 0 if no such user exists.

	def get_user_from_available_data(self):
		# if a signed request is supplied, then it solely determines who the user is
		signed_request = self.get_signed_request()
		if signed_request:
			if 'user_id' in signed_request:
				user_id = signed_request['user']
				self.set_persistent_data('user_id', user_id)
				return user_id
			# if the signed request didn't present a user id, then invalidate
			# all entries in any persistent store.
			self.clear_all_persistent_data()
			return 0

		user = self.get_persistent_data('user_id', default=0)
		persisted_access_token = self.get_persistent_data('access_token')

		# use access_token to fetch user id if we have a user access_token, or if
		# the cached access token has changed.
		access_token = self.get_access_token()
		if access_token and access_token != self.get_application_access_token() and not (user and persisted_access_token == access_token):
			user = self.get_user_from_access_token()
			if user:
				self.set_persistent_data('user_id', user)
			else:
				self.clear_all_persistent_data()
		return user


	# Get a Login URL for use with redirects. By default, full page redirect is
	# assumed. If you are using the generated URL with a window.open() call in
	# JavaScript, you can pass in display=popup as part of the $params.
	#
	# The parameters:
	# - redirect_uri: the url to go to after a successful login
	# - scope: comma separated list of requested extended perms
	#
	# @param array $params Provide custom parameters
	# @return string The URL for the login flow
	def get_login_url(self, params=None):
		self.establish_csrf_token_state()
		current_url = self.get_current_url()

		# if 'scope' is passed as a list, convert to comma separated list
		scope_params = getattr(params, 'scope', None)
		if scope_params and isinstance(scope_params, list):
			params['scope'] = ','.join(scope_params)

		final_params = {
			'client_id' 	: self.get_app_id(),
			'redirect_url' 	: current_url, # possibly overwritten
			'state' 		: self.state
		}
		final_params.update(params)
		return self.get_url(
			'www',
			'dialog/oauth',
			final_params
		)

	# Get a Logout URL suitable for use with redirects.
	# The parameters:
	# - next: the url to go to after a successful logout
	# @param array $params Provide custom parameters
	# @return string The URL for the logout flow

	def get_logout_url(self, params=None):
		if params is None: params = {}
		final_params = {
			'next' 			: self.get_current_url(),
			'access_token' 	: self.get_access_token(),
		}
		final_params.update(params)
		return self.get_url(
			'www',
			'logout.php',
			final_params
		)



	# Get a login status URL to fetch the status from Facebook.
	#
	# The parameters:
	# - ok_session: the URL to go to if a session is found
	# - no_session: the URL to go to if the user is not connected
	# - no_user: the URL to go to if the user is not signed into facebook
	#
	# @param array $params Provide custom parameters
	# @return string The URL for the logout flow
	def get_login_status_url(self, params=None):
		if params is None: params = {}
		current_url = self.get_current_url()
		final_params = {
			'api_key' 			: self.get_app_id(),
			'no_session'		: current_url,
			'no_user'			: current_url,
			'ok_session'		: current_url,
			'session_version' 	: 3,
		}
		final_params.update(params)
		return self.get_url(
			'www',
			'extern/login_status.php',
			final_params
		)



	# Make an API call.
	# @return mixed The decoded response
	def api(self, *args):
		if isinstance(args[0], dict):
			return self._restserver(args[0])
		else:
			return self._graph(args)


	# Constructs and returns the name of the cookie that
	# potentially houses the signed request for the app user.
	# The cookie is not set by the BaseFacebook class, but
	# it may be set by the JavaScript SDK.
	# @return string the name of the cookie that would house
	#		the signed request value.
	def get_signed_request_cookie_name(self):
		return 'fbsr_'+self.get_app_id()



	# Get the authorization code from the query parameters, if it exists,
	# and otherwise return false to signal no authorization code was
	# discoverable.
	#
	# @return mixed The authorization code, or false if the authorization
	#               code could not be determined.
	def get_code(self):
		# TODO: get access to request here
		if 'code' in self.request:
			if self.state is not None and 'state' in self.request and self.state == self.request['state']:
				self.state = None
				self.clear_persistent_data('state')
				return self.request['code']
			else:
				#TODO: log error: CSRF state token does not match one provided.
				return False
		return False


	# Retrieves the UID with the understanding that
	# $this->accessToken has already been set and is
	# seemingly legitimate.  It relies on Facebook's Graph API
	# to retrieve user information and then extract
	# the user ID.
	#
	# @return integer Returns the UID of the Facebook user, or 0
	#                 if the Facebook user could not be determined.
	def get_user_from_access_token(self):
		try:
			user_info = self.api('/me')
			return user_info['id']
		except FacebookApiError:
			return 0

	# Returns the access token that should be used for logged out
	# users when no authorization code is available.
	#
	# @return string The application access token, useful for gathering
	#                public information about users and applications.
	def get_application_access_token(self):
		return "%s|%s" % (self.get_app_id(), self.get_app_secret())


	# Lays down a CSRF state token for this process.
	def establish_csrf_token_state(self):
		if self.state is None:
			self.state = hashlib.md5(uuid4())
			self.set_persistent_data('state', self.state)



	# Retrieves an access token for the given authorization code
	# (previously generated from www.facebook.com on behalf of
	# a specific user).  The authorization code is sent to graph.facebook.com
	# and a legitimate access token is generated provided the access token
	# and the user for which it was generated all match, and the user is
	# either logged in to Facebook or has granted an offline access permission.
	#
	# @param string $code An authorization code.
	# @return mixed An access token exchanged for the authorization code, or
	#               false if an access token could not be generated.
	def get_access_token_from_code(self, code, redirect_uri=None):
		if not code:
			return False
		if redirect_uri is None:
			redirect_uri = self.get_current_url()

		try:
			# need to circumvent json_decode by calling _oauthRequest
			# directly, since response isn't JSON format.
			access_token_response = self._oauth_request(
				self.get_url('graph', '/oauth/access_token'),
				params = {
					'client_id' 	: self.get_app_id(),
					'client_secret' : self.get_app_secret(),
					'redirect_uri'	: redirect_uri,
					'code' 			: code
				}
			)
		except FacebookApiError:
			# most likely that user very recently revoked authorization.
			# In any event, we don't have an access token, so say so.
			return False
		if access_token_response is None:
			return False

		response_params = parse_qs(access_token_response)
		if 'access_token' not in response_params:
			return False

		return response_params['access_token']



	# Invoke the old restserver.php endpoint.
	#
	# @param array $params Method call object
	#
	# @return mixed The decoded response object
	# @throws FacebookApiException
	def _restserver(self, params):
		params['api_key'] = self.get_app_id()
		params['format'] = 'json-strings'

		result = json.loads(self._oauth_request(
			self.get_api_url(params['method']),
			params
		))

		if isinstance(result, dict) and 'error_code' in result:
			self.raise_api_exception(result)

		if params['method'] == 'auth.expireSession' or params['method'] == 'auth.revokeAuthorization':
			self.destroy_session()

		return result


	# Invoke the Graph API.
	#
	# @param string $path The path (required)
	# @param string $method The http method (default 'GET')
	# @param array $params The query/post data
	#
	# @return mixed The decoded response object
	# @throws FacebookApiException

	def _graph(self, path, method='GET', params=None):
		if params is None: params = {}
		if isinstance(method, dict) and params is None:
			params = method
			method = 'GET'
		params['method'] = method # method override, as we always do a POST

		result = json.loads(self._oauth_request(
			self.get_url('graph', path),
			params
		))

		if isinstance(result, dict) and 'error_code' in result:
			self.raise_api_exception(result)

		return result


	# Make a OAuth Request.
	#
	# @param string $url The path (required)
	# @param array $params The query/post data
	#
	# @return string The decoded response object
	# @throws FacebookApiException

	def _oauth_request(self, url, params):
		if 'access_token' not in params:
			params['access_token'] = self.get_access_token()

		for key,value in params:
			if not isinstance(value, str):
				params[key] = json.dumps(value)

		return self.make_request(url, params)


	# Makes an HTTP request. This method can be overridden by subclasses if
	# developers want to do fancier things or use something other than curl to
	# make the request.
	#
	# @param string $url The URL to make the request to
	# @param array $params The parameters to use for the POST body
	# @param CurlHandler $ch Initialized curl handle
	#
	# @return string The response text

	# TODO: test test test this, and make sure we have parity with php curl
	def make_request(self, url, params):
		post_data = None if params is None else urllib.urlencode(params)
		file = urllib.urlopen(url, post_data)
		try:
			response = json.loads(file.read())
		finally:
			file.close()
		if response.get("error"):
			raise FacebookApiError(response)
		return response



	# Parses a signed_request and validates the signature.
	#
	# @param string $signed_request A signed token
	# @return array The payload inside it or null if the sig is wrong

	def parse_signed_request(self, signed_request):
		encoded_sig, payload = signed_request.split('.', 2)
		sig = urlsafe_b64decode(encoded_sig)
		data = json.loads(urlsafe_b64decode(payload))

		if data['algorithm'].upper() != "HMAC-SHA256":
			# TODO: log error
			return None

		hash = hashlib.sha256()
		hash.update(payload + self.get_app_secret())
		expected_sig = hash.digest()

		if sig != expected_sig:
			# TODO: log failure
			return None

		return data




	# Build the URL for api given parameters.
	#
	# @param $method String the method name.
	# @return string The URL for the given parameters
	def get_api_url(self, method):
		READ_ONLY_CALLS = [
				'admin.getallocation',
				'admin.getappproperties'
				'admin.getbannedusers',
				'admin.getlivestreamvialink',
				'admin.getmetrics',
				'admin.getrestrictioninfo',
				'application.getpublicinfo',
				'auth.getapppublickey',
				'auth.getsession',
				'auth.getsignedpublicsessiondata',
				'comments.get',
				'connect.getunconnectedfriendscount',
				'dashboard.getactivity',
				'dashboard.getcount',
				'dashboard.getglobalnews',
				'dashboard.getnews',
				'dashboard.multigetcount',
				'dashboard.multigetnews',
				'data.getcookies',
				'events.get',
				'events.getmembers',
				'fbml.getcustomtags',
				'feed.getappfriendstories',
				'feed.getregisteredtemplatebundlebyid',
				'feed.getregisteredtemplatebundles',
				'fql.multiquery',
				'fql.query',
				'friends.arefriends',
				'friends.get',
				'friends.getappusers',
				'friends.getlists',
				'friends.getmutualfriends',
				'gifts.get',
				'groups.get',
				'groups.getmembers',
				'intl.gettranslations',
				'links.get',
				'notes.get',
				'notifications.get',
				'pages.getinfo',
				'pages.isadmin',
				'pages.isappadded',
				'pages.isfan',
				'permissions.checkavailableapiaccess',
				'permissions.checkgrantedapiaccess',
				'photos.get',
				'photos.getalbums',
				'photos.gettags',
				'profile.getinfo',
				'profile.getinfooptions',
				'stream.get',
				'stream.getcomments',
				'stream.getfilters',
				'users.getinfo',
				'users.getloggedinuser',
				'users.getstandardinfo',
				'users.hasapppermission',
				'users.isappuser',
				'users.isverified',
				'video.getuploadlimits']
		name = 'api'
		if method.lower() in READ_ONLY_CALLS:
			name = 'api_read'
		elif method.lower() == 'video_upload':
			name = 'api_video'
		return self.get_url(name, 'restserver.php')



	# Build the URL for given domain alias, path and parameters.
	#
	# @param $name string The name of the domain
	# @param $path string Optional path (without a leading slash)
	# @param $params array Optional query parameters
	#
	# @return string The URL for the given parameters
	def get_url(self, name, path='', params=None):
		if not params: params = {}
		url = BaseFacebook.DOMAIN_MAP[name]
		if path:
			if path.find('/'): path = path.replace('/','',1)
			url += path

		if params:
			url = "%s?%s" % (url, urllib.urlencode(params))

		return url


	# Returns the Current URL, stripping it of known FB parameters that should
	# not persist.
	# This is now django-specific
	def get_current_url(self):
		protocol = 'http%s://' % ('s' if self.request.is_secure() else '')
		all_params = self.request.REQUEST
		retained_params = {}
		query = ''
		for key,value in all_params:
			if self.should_retain_param(key):
				retained_params[key] = value

		if retained_params:
			query = urllib.urlencode(retained_params)

		return "%s%s%s?%s" % (protocol, self.request.get_host(), self.request.path, query)


	def should_retain_param(self, param_name):
		return param_name not in BaseFacebook.DROP_QUERY_PARAMS


	# Analyzes the supplied result to see if it was thrown
	# because the access token is no longer valid.  If that is
	# the case, then the persistent store is cleared.
	#
	# @param $result array A record storing the error message returned
	#                      by a failed API call.
	def raise_api_exception(self, result):
		e = FacebookApiError(result)
		type = e.get_type()
		if type == 'OAuthException' or \
			type == 'invalid_token' or \
			type == 'Exception':
			message = e.get_message()
			if 'Error validating access token' in message or 'Invalid OAuth access token' in message:
				self.set_access_token(None)
				self.user = 0
				self.clear_all_persistent_data()
		raise e



	# Destroy the current session
	def destroy_session(self):
		self.access_token = None
		self.signed_request = None
		self.user = None
		self.clear_all_persistent_data()


	# Abstract methods to be implemented by subclasses

	@abstractmethod
	def set_persistent_data(self, key, value):
		return False

	@abstractmethod
	def get_persistent_data(self, key, default=None):
		return False

	@abstractmethod
	def clear_persistent_data(self, key):
		return False

	@abstractmethod
	def clear_all_persistent_data(self):
		return False
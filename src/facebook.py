from base_facebook import BaseFacebook

class Facebook(BaseFacebook):

	k_supported_keys = ['state', 'code', 'access_token', 'user_id']


	# our constructor here takes an optional member of request: session
	# which we will modify and save.  this makes it django-specific, but that's cool
	# @param dictionary request The request information associated with the current request
	# - request_params: a dict of the GET and POST parameters in the request
	# - cookie_params: a dict of the cookies available
	# - session: a django session object.

	def __init__(self, config, request=None):
		self.session = request.session
		super(Facebook, self).__init__(config, request)

	def is_supported_key(self, key):
		return key in self.k_supported_keys

	def set_persistent_data(self, key, value):
		if not self.is_supported_key(key):
			return False
		session_var_name = self.construct_session_variable_name(key)
		self.session[session_var_name] = value
		return True

	def get_persistent_data(self, key, default=None):
		if not self.is_supported_key(key):
			return default
		return self.session.get(key, default)

	def clear_persistent_data(self, key):
		if not self.is_supported_key(key):
			return False
		session_var_name = self.construct_session_variable_name(key)
		if session_var_name in self.session:
			self.session.remove(session_var_name)
		return True

	def clear_all_persistent_data(self):
		for key in self.k_supported_keys:
			self.clear_persistent_data(key)
		return True

	def construct_session_variable_name(self, key):
		return "%s_%s_%s" % ('fb', self.get_app_id(), key)



class FacebookApiError(Exception):
	"""Exception class to handle all errors related to Facebook Graph API"""
	# Make a new API Exception with the given result.
	#
	# @param array api_result The result from the API server
	def __init__(self, api_result):
		self.api_result = api_result
		self.error_code = getattr(api_result, 'error_code', 0)
		self.value = self.get_value()

		super(FacebookApiError, self).__init__()

	def get_value(self):
		msg = ''
		if 'error_description' in self.api_result:
			msg = getattr(self.api_result, 'error_description')
		elif 'error' in self.api_result:
			msg = getattr(getattr(self.api_result, 'error'), 'message')
		elif 'error_msg' in self.api_result:
			msg = getattr(self.api_result, 'error_msg')
		else:
			msg = 'Unknown Error. Check getResult()'
		return msg

	def __str__(self):
		if int(self.error_code):
			return "%d: %s", (self.error_code, repr(self.value))
		return repr(self.value)
# Copyright (C) 2015, Thomas Leonard
# See http://0install.net/0compile.html

# Perform a solve by calling out to the OCaml solver using its JSON API

#!/usr/bin/env python

# This is a simple demonstration client for the "0install slave" JSON API.
# This file is in the Public Domain.

import support, sys
from json_connection import JsonConnection

class Handler:
	# In GUI mode, 0install will show the dialog itself, so we only have to handle
	# console interaction here (which it can't do itself because we're using stdin).
	def handle_confirm_keys(feed, keys):
		print("Feed:", feed)
		print("The feed is correctly signed with the following keys:")
		for key, hints in keys.items():
			print("- " + key)
			for vote, msg in hints:
				print("   ", vote.upper(), msg)
		while True:
			r = input("Trust these keys? [YN]")
			if r in 'Yy': return list(keys)
			if r in 'Nn': return []

	def handle_update_key_info(*unused):
		return

class Solver:
	def __init__(self, gui, verbose = True):
		self.conn = JsonConnection(Handler(), gui, verbose)

	def solve(self, requirements, refresh = False):
		refresh = False
		reply = []
		def response(status, result, info = None):
			if status == "fail":
				raise Exception(result)
			else:
				assert status == "ok"
				reply.append({
					'result': result,
					'info': info
				})
		ticket = self.conn.invoke(response, "select", requirements, refresh)
		while not reply:
			self.conn.handle_next_chunk()
		assert len(reply) == 1
		return reply[0]

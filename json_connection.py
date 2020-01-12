# Copyright (C) 2015, Thomas Leonard
# See http://0install.net/0compile.html

# Perform a solve by calling out to the OCaml solver using its JSON API

import support
import subprocess, json
import logging, sys

class JsonConnection:
	def __init__(self, handler, gui, verbose = False, version = "2.10"):
		self.handler = handler
		slave_args = support.install_prog + ["slave", version]
		if gui: slave_args.append("--gui")
		else: slave_args.append("--console")
		if verbose: slave_args.append("-v")
		self.child = subprocess.Popen(slave_args, stdin = subprocess.PIPE, stdout = subprocess.PIPE)
		self.next_ticket = 1
		self.callbacks = {}
		api_notification = self.get_json_chunk()
		assert api_notification[0] == "invoke"
		assert api_notification[1] == None
		assert api_notification[2] == "set-api-version"
		api_version = api_notification[3]
		logging.info("Agreed on 0install slave API version '%s'", api_version)

	def get_chunk(self):
		len_line = self.child.stdout.readline()
		assert len_line.startswith(b"0x"), len_line
		assert len_line.endswith(b"\n")
		chunk_len = int(len_line[2:-1], 16)
		#print("chunk length = %d" % chunk_len)
		return self.child.stdout.read(chunk_len)

	def get_json_chunk(self):
		data = json.loads(self.get_chunk().decode('utf-8'))
		logging.info("From slave: %s", data)
		#print("got", data)
		return data

	def send_chunk(self, value):
		data = json.dumps(value)
		logging.info("To slave: %s", data)
		self.child.stdin.write((('0x%08x\n' % len(data)) + data).encode('utf-8'))
		self.child.stdin.flush()

	def invoke(self, on_success, op, *args):
		ticket = str(self.next_ticket)
		self.next_ticket += 1
		self.callbacks[ticket] = on_success
		self.send_chunk(["invoke", ticket, op, args])
		return ticket

	def reply_ok(self, ticket, response):
		self, send_chunk(["return", ticket, "ok", response])

	def reply_fail(self, ticket, response):
		self, send_chunk(["return", ticket, "fail", response])

	def handle_next_chunk(self):
		api_request = self.get_json_chunk()
		if api_request[0] == "invoke":
			ticket = api_request[1]
			op = api_request[2]
			args = api_request[3]
			try:
				response = getattr(self.handler, 'handle_' + op.replace('-', '_'))(*args)
				self.reply_ok(ticket, response)
			except Exception as ex:
				logging.warning("Operation %s(%s) failed", op, ', '.join(args), exc_info = True)
				self.reply_fail(ticket, str(ex))
		elif api_request[0] == "return":
			ticket = api_request[1]
			cb = self.callbacks.pop(ticket)
			if api_request[2] == 'ok':
				cb(*api_request[3])
			elif api_request[2] == 'ok+xml':
				xml = self.get_chunk()
				logging.info("With XML: %s", xml)
				cb(*(api_request[3] + [xml]))
			else:
				assert api_request[2] == 'fail', api_request
				raise Exception(api_request[3])
		else:
			assert 0, api_request

	def close(self):
		self.child.terminate()
		self.child = None

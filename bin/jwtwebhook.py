"""
This module implements a modular input consisting of a web-server that handles incoming Webhooks.
"""
try:
    # Python 2
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from urlparse import parse_qs

except:
    # Python 3
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs

    unicode = str

import sys
import ssl
import time
import re
import json
import errno
import traceback
from threading import Thread
import jwt
import os, logging
from splunk_helper import data_encryption
from modular_input import ModularInput, Field, IntegerField, FilePathField
from splunklib.modularinput.event_writer import EventWriter
from splunklib.modularinput.event import Event


class LogRequestsInSplunkHandler(BaseHTTPRequestHandler):

    def handle_request(self):
        try:
            # Make the resulting data
            post_body = ""
            # Get the content-body
            content_len = int(self.headers.get('content-length', 0))

            # If content was provided, then parse it
            if content_len > 0:

                encoded_post_body = self.rfile.read(content_len)
                
                if self.server.secret is not None:
                    # decode body using jwt
                    try:
                        post_body = jwt.decode(encoded_post_body, self.server.secret, algorithms=['HS256'])
                    except jwt.ExpiredSignatureError:
                        self.write_response(403, {"error": 'Signature expired. Please log in again.'})
                        return
                    except jwt.InvalidTokenError:
                        self.write_response(403, {"error": 'Invalid token. Please log in again.'})
                        return
                else:
                    post_body = encoded_post_body
                
            # Send Event to Splunk via event_writer
            self.server.output_results(json.loads(post_body), self.client_address[0])

            # Send a 200 request noting that this worked
            self.write_response(200, {"success": True})
        except Exception as ex:
            self.server.logger.error("JWT web hook handle_request error: %s", traceback.format_exc())

    def write_json(self, json_dict):
        content = json.dumps(json_dict)

        if isinstance(content, unicode):
            content = content.encode('utf-8')

        self.wfile.write(content)

    def do_GET(self):
        self.write_response(200, {"success": True})

    def do_HEAD(self):
        self.write_response(405, {"success": False})

    def read_file(self, length):
        return self.rfile.read(length)

    def do_POST(self):
        self.handle_request()

    def convert_list_entries(self, args_list):
        updated_list = []
        modified = False

        for entry in args_list:
            if sys.version_info.major >= 3 and isinstance(entry, bytes):
                updated_list.append(entry.decode('utf-8'))
                modified = True
            else:
                updated_list.append(entry)

        return updated_list, modified

    def write_response(self, status_code, json_body):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.write_json(json_body)


class WebServer:
    """
    This class implements an instance of a web-server that listens for incoming webhooks.
    """

    MAX_ATTEMPTS_TO_START_SERVER = 5

    def __init__(self, output_results, port, path, secret, password, cert_file=None, key_file=None, logger=None):

        # Make an instance of the server
        server = None
        attempts = 0

        while server is None and attempts < WebServer.MAX_ATTEMPTS_TO_START_SERVER:
            try:
                server = HTTPServer(('', port), LogRequestsInSplunkHandler)
            except IOError as exception:

                # Log a message noting that port is taken
                if logger is not None:
                    logger.info('The web-server could not yet be started, attempt %i of %i, reason="%s", pid="%r"',
                                attempts, WebServer.MAX_ATTEMPTS_TO_START_SERVER, str(exception), os.getpid())

                    time.sleep(3)

                server = None
                attempts = attempts + 1

        # Stop if the server could not be started
        if server is None:

            # Log that it couldn't be started
            if logger is not None:
                logger.info('The web-server could not be started, pid="%r"', os.getpid())

            # Stop, we weren't successful
            return

        # Save the parameters
        server.output_results = output_results
        server.path = path
        server.logger = logger
        server.secret = secret

        # SSL socket is required on this TA, throw exception if cert file is missing
        if cert_file is not None:
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file, password=password)
            server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        else:
            raise Exception('Server certificate is missing.')

        # Keep a server instance around
        self.server = server

    def start_serving(self):
        """
        Start the server.
        """

        try:
            self.server.serve_forever()
        except IOError as exception:
            if self.server.logger is not None:
                if exception.errno == errno.EPIPE:
                    # Broken pipe: happens when the input shuts down or when remote peer disconnects
                    pass
                else:
                    self.server.logger.warn("IO error when serving the web-server: %s", str(exception))

    def stop_serving(self):
        """
        Stop the server.
        """

        self.server.shutdown()

        # https://lukemurphey.net/issues/1908
        if hasattr(self.server, 'socket'):
            self.server.socket.close()


class JwtWebhooksInput(ModularInput, EventWriter):
    """
    The webhooks input modular input runs a web-server and pipes data from the requests to Splunk.
    """

    def __init__(self, timeout=30, **kwargs):

        scheme_args = {'title': "JWT Webhook",
                       'description': "Retrieve data from jwt webhook using SSL",
                       'use_single_instance': True}

        args = [
            IntegerField('port', 'Port', 'The port to run the web-server on', none_allowed=False, empty_allowed=False),
            Field('secret', 'Secret',
                  'The secret key to decode the JWT encoded payload, leave it empty if the payload is not JWT encoded.',
                  none_allowed=True, empty_allowed=True),
            Field('path', 'Path',
                  'A wildcard that the path of requests must match (paths generally begin with a "/" and can include a wildcard)',
                  none_allowed=True, empty_allowed=True),
            FilePathField('key_file', 'SSL Certificate Key File',
                          'The path to the SSL certificate key file (if the certificate requires a key); typically uses .KEY file extension',
                          none_allowed=True, empty_allowed=True, validate_file_existence=True),
            FilePathField('cert_file', 'SSL Certificate File',
                          'The path to the SSL certificate file (if you want to use encryption); typically uses .DER, .PEM, .CRT, .CER file extensions',
                          none_allowed=False, empty_allowed=False, validate_file_existence=True),
            Field('password', 'Password',
                  'The password to decrypt the private key, leave it empty if the private key is not encrypted.',
                  none_allowed=True, empty_allowed=True),
        ]

        ModularInput.__init__(self, scheme_args, args, logger_name="webhook_modular_input", sleep_interval=60)
        EventWriter.__init__(self, output = sys.stdout, error = sys.stderr)

        if timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 30

        self.http_daemons = {}

    @classmethod
    def wildcard_to_re(cls, wildcard):
        """
        Convert the given wildcard to a regular expression.

        Arguments:
        wildcard -- A string representing a wild-card (like "/some_path/*")
        """

        regex_escaped = re.escape(wildcard)
        return regex_escaped.replace('\*', ".*")

    def do_shutdown(self):

        for stanza, httpd in self.http_daemons.copy().items():
            httpd.stop_serving()
            del self.http_daemons[stanza]

            self.logger.info("Stopping server, stanza=%s, pid=%r", stanza, os.getpid())

    def run(self, stanza, cleaned_params, input_config):

        # Make the parameters
        port = cleaned_params.get("port", 8080)
        key_file = cleaned_params.get("key_file", None)
        cert_file = cleaned_params.get("cert_file", None)
        masked_secret = cleaned_params.get("secret", None)
        masked_password = cleaned_params.get("password", None)

        # self.logger.info(input_config)
        session_key = input_config.session_key

        # self.logger.info('session_key ' + session_key)
        # self.logger.info('stanza ' + stanza)
        client_id = stanza.split('://')[1]
        updated_item = {
            'port': port,
            'password': data_encryption.DataEncryption.masked_password
        }

        if key_file is not None:
            updated_item['key_file'] = key_file

        if cert_file is not None:
            updated_item['cert_file'] = cert_file

        # get secret from encrypted location
        encrypt = data_encryption.DataEncryption(session_key, stanza)
        if masked_secret:
            updated_item['secret'] = data_encryption.DataEncryption.masked_password
            secret = encrypt.encrypt_and_get_password(client_id, masked_secret, updated_item)
        else:
            secret = None
        password = encrypt.encrypt_and_get_password(client_id + '_password', masked_password, updated_item)

        sourcetype = cleaned_params.get("sourcetype", "jwtwebhook")
        host = cleaned_params.get("host", None)
        index = cleaned_params.get("index", "default")
        path = cleaned_params.get("path", None)
        source = stanza

        # Log the number of servers that are running
        if self.use_single_instance:
            if hasattr(os, 'getppid'):
                self.logger.info('Number of servers=%r, pid=%s, ppid=%r', len(self.http_daemons), os.getpid(),
                                 os.getppid())
            else:
                self.logger.info('Number of servers=%r, pid=%s', len(self.http_daemons), os.getpid())

        # See if the daemon is already started and start it if necessary
        if stanza not in self.http_daemons:

            # Convert the path to a regular expression
            if path is not None and path != "":
                path_re = self.wildcard_to_re(path)
            else:
                path_re = None

            # Construct Splunk Event and Write to Splunk
            def output_results(payload, clientip):
                event = Event(
                    data=json.dumps(payload),
                    time="%.3f" % time.time(),
                    index=index,
                    host=clientip,
                    source=host,
                    sourcetype=sourcetype,
                    done=True,
                    unbroken=True
                )
                self.write_event(event)

            # Start the web-server
            self.logger.info("Starting server on port=%r, path=%r, cert_file=%r, key_file=%r, stanza=%s, pid=%r", port,
                             path_re, cert_file, key_file, source, os.getpid())
            httpd = WebServer(output_results, port, path_re, secret, password, cert_file, key_file, logger=self.logger)

            if hasattr(httpd, 'server') and httpd.server is not None:
                self.http_daemons[stanza] = httpd

                # Use threads if this is using single instance mode
                if self.use_single_instance:
                    thread = Thread(target=httpd.start_serving)
                    thread.start()

                # Otherwise, just run the server and block on it until it is done
                else:
                    httpd.start_serving()

                self.logger.info(
                    "Successfully started server on port=%r, path=%r, cert_file=%r, key_file=%r, stanza=%s, pid=%r",
                    port, path_re, cert_file, key_file, source, os.getpid())


if __name__ == '__main__':
    jwtwebhooks_input = None

    try:
        jwtwebhooks_input = JwtWebhooksInput()
        jwtwebhooks_input.execute()
        sys.exit(0)
    except Exception:
        if jwtwebhooks_input is not None and jwtwebhooks_input.logger is not None:
            # This logs general exceptions that would have been unhandled otherwise (such as coding errors)
            jwtwebhooks_input.logger.exception("Unhandled exception was caught, this may be due to a defect in the script")
        raise

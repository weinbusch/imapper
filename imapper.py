
import logging
import socket
import ssl
import re
import collections

logger = logging.getLogger(__name__)

CRLF = b'\r\n'
STATUS_RESPONSE = (b'OK', b'NO', b'BAD', b'PREAUTH', b'BYE')

def force_bytes(value):
    if not isinstance(value, bytes):
        return bytes(str(value), 'utf8')
    return value

def abbreviate(string, cutoff = 45):
    if len(string) > cutoff+7:
        return string[:cutoff] + ' [' + str(len(string)-cutoff) + ' more]'
    return string

def escape(string):
    return (string
        .replace('\n', '\\n')
        .replace('\r', '\\r')
        .replace('\t', '\\t')
    )

token_res = [
    r'^(?P<tag>\*|[A-z0-9]+)',
    r'(?P<open_bracket>\[)',
    r'(?P<close_bracket>\])',
    r'(?P<open_paren>\()',
    r'(?P<close_paren>\))',
    r'\{(?P<octet_count>\d+)\}',
    r'(?P<number>\d+\.?\d*)',
    r'(?P<atom>[^{}]+)'.format(re.escape('()][ \r\n')),
    r'(?P<eol>\r\n)',
    r'(?P<whitespace>[ ]+)',
    r'(?P<data>.+)',
]
    
token_pattern = force_bytes('|'.join(token_res))

class Token(collections.namedtuple('Token', 'type value')):

    def __repr__(self):
        data = abbreviate(escape(self.value.decode('utf8')))
        return f'<{self.type.upper()} "{data}">' 


def lex(source):
    while True:
        line = source.readline()
        if not line:
            # raises StopIteration at end of file
            # https://docs.python.org/3/library/io.html#io.TextIOBase.readline
            break
        size = None
        for mo in re.finditer(token_pattern, line):
            key = mo.lastgroup
            value = mo.group(key)
            if key == 'octet_count':
                size = int(value)
                literal = source.read(size)
                yield Token('literal', literal)
                break
            else:
                yield Token(key, value)

def next_without_whitespace(token_stream):
    token = next(token_stream)
    if token.type == 'whitespace':
        return next_without_whitespace(token_stream)
    return token

def parse(tokens, token):
    
    if not token:
        token = next_without_whitespace(tokens)

    if token.type == 'tag':
        response = {}
        response['tag'] = token.value
        message = b''
        data = None

        token = next_without_whitespace(tokens)
            
        if token.type == 'number':
            response['number'] = token.value
            token = next_without_whitespace(tokens)
            
        response['type'] = token.value

        token = next_without_whitespace(tokens)

        if token.type == 'open_bracket':
            response['response_code'] = parse(tokens, token)
            token = next_without_whitespace(tokens)
        
        if token.type == 'open_paren':
            data = parse(tokens, token)
            token = next_without_whitespace(tokens)
        elif response['type'] == b'SEARCH':
            data = []
            while token.type != 'eol':
                data.append(token.value)
                token = next_without_whitespace(tokens)

        if response['type'] == b'FETCH':
            # convert list of format [key value key value ... ] into dict
            # https://stackoverflow.com/a/12739974
            # Decode key
            data = {key.decode('utf8'): value for key, value in zip(*[iter(data)]*2)}

        if data:
            response['data'] = data

        while token.type != 'eol':
            # Collect message tokens, include whitespace
            message += token.value
            token = next(tokens)

        if message:
            response['message'] = message

        return response
    
    elif token.type == 'open_bracket' or token.type == 'open_paren':
        expected_close = 'close_bracket' if token.type == 'open_bracket' else 'close_paren'
        output = []
        token = next_without_whitespace(tokens)
        while token.type != expected_close and token.type != 'eol':
            output.append(parse(tokens, token))
            token = next_without_whitespace(tokens)
        if token.type == 'eol':
            logger.warning(f'Encountered "eol" without "{expected_close}"')
            return output
        return output

    return token.value

class Client:
    
    def __init__(self, host, port=993, ssl=True, timeout=10, debug=True):
        self.host = host
        self.port = port

        self.ssl = ssl
        self.timeout = timeout
        self.debug = debug

        self.tag_num = 1

        self.socket = self.get_socket()
        self.file = self.socket.makefile('rb')
        self.get_response()

    def get_socket(self):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.ssl:
            context = ssl.create_default_context()
            return context.wrap_socket(s, server_hostname=self.host)
        return s

    def get_response(self, tag=None, name=None):

        responses = []
        tokens = lex(self.file)
        token = None
        try:
            while True:
                response = parse(tokens, token)
                responses.append(response)
                if self.debug:
                    logger.info(response)
                if not tag or (tag and response['tag'] == tag):
                    # If this check is not included, a failing login command leads to a timeout,
                    # it does not raise StopIteration (?!)
                    break
        except StopIteration:
            # React to StopIteration raised by lexer
            pass        
        return responses

    def _send_command(self, *args):
        args = [force_bytes(arg) for arg in args]
        data = b' '.join(args) + CRLF
        self.socket.sendall(data)

        if self.debug:
            if len(args) >= 2 and args[1] == b'LOGIN':
                # Do not log user credentials
                logger.debug('Sent command %r to server', args[0:2])
            else:
                logger.debug('Sent command %r to server', args)

    def _get_tag(self):
        tag = force_bytes(self.tag_num)
        self.tag_num += 1
        return tag

    def command(self, name, *args):
        tag = self._get_tag()
        self._send_command(tag, name, *args)
        response = self.get_response(tag, name)
        
        return response

    def close(self):
        self.file.close()
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()
        if self.debug:
            logger.info('Connection closed.')

    def login(self, username, password):
        name = b'LOGIN'
        return self.command(name, username, password)

    def logout(self):
        name = b'LOGOUT'
        return self.command(name)

    def capability(self):
        name = b'CAPABILITY'
        return self.command(name)

    def select(self, mailbox='INBOX'):
        name = b'SELECT'
        return self.command(name, mailbox)

    def search(self, *args):
        name = b'SEARCH'
        return self.command(name, *args)

    def fetch(self, message_set, data_item_names='RFC822', uid=False):
        name = b'FETCH'
        if uid:
            name = b'UID ' + name
        response = self.command(name, message_set, data_item_names)
        return response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

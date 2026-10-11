"""Smart Proxy UI: mitmproxy addon and local web rule editor."""
import copy
import fnmatch
import json
import logging
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import http, ctx

BASE = Path(__file__).resolve().parent
RULES_FILE = BASE / 'rules.json'
UI_HOST = os.environ.get('PROXY_UI_HOST', '127.0.0.1')
UI_PORT = int(os.environ.get('PROXY_UI_PORT', '8765'))
lock = threading.RLock()
rules = []


def save_rules():
    with lock:
        temp = RULES_FILE.with_suffix('.tmp')
        temp.write_text(json.dumps(rules, ensure_ascii=False, indent=2), encoding='utf-8')
        temp.replace(RULES_FILE)


def load_rules():
    global rules
    try:
        data = json.loads(RULES_FILE.read_text(encoding='utf-8'))
        if not isinstance(data, list):
            raise ValueError('Expected array of rules')
        with lock:
            rules = data
    except FileNotFoundError:
        rules = []
        save_rules()
    except Exception as e:
        logging.error('Failed to load rules: %s', e)


def matches(rule, url, method):
    if not rule.get('enabled', True):
        return False
    method_filter = str(rule.get('method', '*')).upper()
    if method_filter not in ('*', method.upper()):
        return False
    pattern = str(rule.get('url_pattern', ''))
    mode = rule.get('match_mode', 'contains')
    if not pattern:
        return False
    try:
        if mode == 'exact':
            return url == pattern
        if mode == 'contains':
            return pattern in url
        if mode == 'glob':
            return fnmatch.fnmatchcase(url, pattern)
        if mode == 'regex':
            return re.search(pattern, url) is not None
    except re.error:
        return False
    return False


def merge_json(a, b):
    if isinstance(a, dict) and isinstance(b, dict):
        result = copy.deepcopy(a)
        for k, v in b.items():
            result[k] = merge_json(result[k], v) if k in result else copy.deepcopy(v)
        return result
    return copy.deepcopy(b)


def modify_message(message, config):
    if not config or not config.get('enabled'):
        return
    mode = config.get('body_mode', 'none')
    if mode == 'replace':
        message.text = config.get('body', '')
    elif mode == 'json_merge':
        incoming = json.loads(message.get_text(strict=False) or '{}')
        patch = json.loads(config.get('body', '{}') or '{}')
        message.text = json.dumps(merge_json(incoming, patch), ensure_ascii=False)
    if mode != 'none' and config.get('content_type'):
        message.headers['Content-Type'] = str(config['content_type'])
    for name in config.get('remove_headers', []):
        if str(name).strip():
            message.headers.pop(str(name), None)
    for name, val in (config.get('set_headers') or {}).items():
        if str(name).strip():
            message.headers[str(name)] = str(val)
    # mitmproxy automatically maintains Content-Length when body content is assigned.


class SmartProxy:
    def __init__(self):
        self.server = None
        self.thread = None

    def load(self, loader):
        load_rules()
        handler = self.build_handler()
        try:
            self.server = ThreadingHTTPServer((UI_HOST, UI_PORT), handler)
        except OSError as exc:
            ctx.log.error(f'Cannot launch UI on {UI_HOST}:{UI_PORT}: {exc}')
            return
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        ctx.log.info(f'Smart Proxy UI: http://{UI_HOST}:{UI_PORT}')

    def done(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def request(self, flow: http.HTTPFlow):
        flow.metadata['smart_original_url'] = flow.request.pretty_url
        self.process(flow, 'request')

    def response(self, flow: http.HTTPFlow):
        self.process(flow, 'response')

    def process(self, flow, phase):
        url = flow.metadata.get('smart_original_url', flow.request.pretty_url)
        with lock:
            snapshot = copy.deepcopy(rules)
        for rule in snapshot:
            if not matches(rule, url, flow.request.method):
                continue
            config = rule.get(phase) or {}
            if not config.get('enabled'):
                continue
            try:
                msg = flow.request if phase == 'request' else flow.response
                if msg is None:
                    continue
                modify_message(msg, config)
                if phase == 'response' and config.get('status_code'):
                    msg.status_code = int(config['status_code'])
                ctx.log.info(f'[Smart Proxy] {phase}: {rule.get("name", "Unnamed")} → {flow.request.method} {url}')
            except Exception as exc:
                ctx.log.error(f'[Smart Proxy] Rule {rule.get("name")} failed: {exc}')

    @staticmethod
    def build_handler():
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                logging.debug(fmt, *args)

            def respond(self, status, data, content_type='application/json; charset=utf-8'):
                payload = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode('utf-8')
                self.send_response(status)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(payload)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                path = urlsplit(self.path).path
                if path == '/':
                    self.respond(200, (BASE/'index.html').read_bytes(), 'text/html; charset=utf-8')
                elif path == '/api/rules':
                    with lock:
                        self.respond(200, copy.deepcopy(rules))
                elif path == '/api/status':
                    self.respond(200, {'ok': True, 'rule_count': len(rules), 'proxy_port': os.environ.get('PROXY_PORT', '8080')})
                else:
                    self.respond(404, {'error': 'Not found'})

            def do_POST(self):
                if urlsplit(self.path).path != '/api/rules':
                    return self.respond(404, {'error': 'Not found'})
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if length > 2_000_000:
                        return self.respond(413, {'error': 'Request too large'})
                    content = self.rfile.read(length)
                    data = json.loads(content)
                    if not isinstance(data, list) or len(data) > 500:
                        raise ValueError('Rules must be a list (max 500)')
                    for rule in data:
                        if not isinstance(rule, dict):
                            raise ValueError('Invalid rule')
                        if rule.get('match_mode') == 'regex':
                            re.compile(rule.get('url_pattern', ''))
                        if rule.get('match_mode') not in ('exact', 'contains', 'glob', 'regex'):
                            raise ValueError('Unknown match mode')
                        for phase in ('request', 'response'):
                            cfg = rule.get(phase) or {}
                            if cfg.get('enabled') and cfg.get('body_mode') == 'json_merge':
                                if not isinstance(json.loads(cfg.get('body') or '{}'), dict):
                                    raise ValueError('JSON merge payload must be an object')
                    with lock:
                        rules[:] = data
                        save_rules()
                    self.respond(200, {'ok': True, 'count': len(rules)})
                except (ValueError, json.JSONDecodeError, re.error) as exc:
                    self.respond(400, {'error': str(exc)})
                except Exception as exc:
                    logging.exception('Failed to save rules')
                    self.respond(500, {'error': 'Server error'})
        return Handler


addons = [SmartProxy()]

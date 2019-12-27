#!/usr/bin/env python3

import requests
import json

class HttpRequester():
    def __init__(self, headers=None, response_hook=None, cert_keypair=None):
        self.session = requests.Session()

        if headers:
            self.headers = headers
        else:
            self.headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.9600',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Encoding': 'gzip, deflate',
                    'Accept-Language': 'en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7,fr-CA;q=0.6,fr;q=0.5,es-AR;q=0.4,es;q=0.3',
                    'X-Correlation-ID': 'rttest' }

        self.update_headers(self.headers)

        if response_hook:
            self.session.hooks['response'].append(response_hook)
        if cert_keypair:
            self.session.cert = cert_keypair

    def Session(self):
        return self.session

    def update_headers(self, header):
        self.headers.update(header)
        self.session.headers.update(header)

        return self.session.headers

    def get(self, url, params):
        "params is a dictionary"
        return self.session.get(url, params=params)

    def post(self, url, param_type, params):
        "params is a dictionary"
        if param == "json":
            return self.session.post(url, params=json.dumps(params))
        elif param == "form":
            return self.session.post(url, params=params)

    def put(self, url, params):
        "params is a dictionary"
        if param == "json":
            return self.session.post(url, params=json.dumps(params))
        elif param == "form":
            return self.session.post(url, params=params)

    def options(self, url):
        return self.session.options(url)

    def head(self, url):
        return self.session.head(url)

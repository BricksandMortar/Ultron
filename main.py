#!/usr/bin/env python
import io
import os
import re
import sys
import json
import subprocess
import logging
import urllib

from google.appengine.api import urlfetch
import requests
import ipaddress
import hmac
import yaml
from hashlib import sha1
from flask import Flask, request, abort

"""`main` is the top level module for the Flask application."""
app = Flask(__name__)
app.config.from_object('config')
app.debug = True
_basedir = os.path.abspath(os.path.dirname(__file__))

@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return 'OK'
    elif request.method == 'POST':
        # # Store the IP address of the requester
        # request_ip = ipaddress.ip_address(u'{0}'.format(request.remote_addr))
        #
        # # If GHE_ADDRESS is specified, use it as the hook_blocks.
        # if os.environ.get('GHE_ADDRESS', None):
        #     hook_blocks = [os.environ.get('GHE_ADDRESS')]
        # # Otherwise get the hook address blocks from the API.
        # else:
        #     hook_blocks = requests.get('https://api.github.com/meta').json()[
        #         'hooks']
        #
        # # Check if the POST request is from github.com or GHE
        # for block in hook_blocks:
        #     if ipaddress.ip_address(request_ip) in ipaddress.ip_network(block):
        #         break  # the remote_addr is within the network range of github.
        # else:
        #     abort(403)

        #Accept pings
        if request.headers.get('X-GitHub-Event') == "ping":
            return json.dumps({'msg': 'Hi!'})

        #Accept pushes
        elif request.headers.get('X-GitHub-Event') != "push":
            return json.dumps({'msg': "wrong event type"})

        payload = json.loads(request.data)
        repo_name = payload['repository']['name']
        repo_owner = payload['repository']['owner']['name']

        #Double check it's our precious template repo
        if repo_name != app.config['REPO'] or repo_owner != app.config['ORG']:
            return 'OK'

        #Verify the signature matches our webhook signature
        key = app.config['GITHUB_SECRET']
        if key:
            signature = request.headers.get('X-Hub-Signature').split(
                '=')[1]
            if type(key) == unicode:
                key = key.encode()
            mac = hmac.new(key, msg=request.data, digestmod=sha1)
            if not compare_digest(mac.hexdigest(), signature):
                abort(403)

        #Get the repos it should trigger builds from the YAML file
        stream = open(os.path.join(_basedir, "build_repos.yaml"))
        repos_to_build = yaml.load(stream)

        logging.info("Got YAML")

        #Specify the branch to build in the payload
        payload = json.dumps({'request': {'branch': app.config['BRANCH']}})
        logging.info('Payload' + payload)
        #Do the request
        for repo in repos_to_build:
            logging.debug("Looping" + repo)
            url = 'https://api.travis-ci.org/repo/'+app.config['ORG']+'%2F'+repo+'/requests'
            logging.debug("Url is " + url)
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Travis-API-Version': 3, 'Authorization': 'token ' + app.config['TRAVIS_SECRET']}
            result = urlfetch.fetch(url=url, payload=payload, method=urlfetch.POST, headers=headers, follow_redirects=False)
            # try:
            #     travis_request = requests.post(url, data=payload, headers=headers, allow_redirects=False)
            #     if travis_request.status_code != 200 or travis_request.status_code != 202:
            #         logging.error(travis_request)
            #         break
            # except requests.exceptions as e:
            #     logging.error(e)
            if result.status_code != 202 or result.status_code != 200:
                logging.error(str(result.status_code)+ result.content)
            else:
                logging.info(str(result.status_code) + result.content)
    return 'OK'

def compare_digest(a, b):
        """
        ** From Django source **
        Run a constant time comparison against two strings
        Returns true if a and b are equal.
        a and b must both be the same length, or False is
        returned immediately
        """
        if len(a) != len(b):
            return False

        result = 0
        for ch_a, ch_b in zip(a, b):
            result |= ord(ch_a) ^ ord(ch_b)
        return result == 0

# if __name__ == "__main__":
#     try:
#         port_number = int(sys.argv[1])
#     except:
#         port_number = 80
#     app.run(host='0.0.0.0', port=port_number)

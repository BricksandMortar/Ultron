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
import hmac
from hashlib import sha1
from flask import Flask, request, abort
from google.appengine.ext import ndb

"""`main` is the top level module for the Flask application."""
app = Flask(__name__)
app.config.from_pyfile('config.py')
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


        event_type = request.headers.get('X-GitHub-Event')
        logging.debug('Event Type: ' + event_type)

        # Accept pings
        if event_type == "ping":
            return json.dumps({'msg': 'Hi!'})

        # Accept pushes
        elif event_type != "push" or event_type != "create" or event_type != "delete":
            return json.dumps({'msg': "wrong event type"})

        payload = json.loads(request.data)
        logging.debug('Payload' + json.dumps(payload))
        repo_owner = payload['repository']['owner']['name']
        repo_name = payload['repository']['name']

        if event_type == "create":
            logging.debug('Type is create')
            if payload['ref_type'] != "branch" or payload['ref'] != app.config['REPO']:
                return 'OK'
            elif verify_key():
                logging.debug('Verifying key')
                add_repo(repo_name)
            else:
                abort(403)

        elif event_type == "delete":
            logging.debug('Type is delete')
            if payload['ref_type'] != "branch" or payload['ref'] != app.config['REPO']:
                return 'OK'
            elif verify_key():
                remove_repo(repo_name)
            else:
                abort(403)

        # Double check it's our precious template repo
        elif event_type == "push":
            logging.debug('Type is push')
            if repo_name != app.config['REPO'] or repo_owner != app.config['ORG']:
                return 'OK'
            elif verify_key():
                trigger_builds()
            else:
                abort(403)
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


def verify_key():
    # Verify the signature matches our webhook signature
    key = app.config['GITHUB_SECRET']
    if key:
        signature = request.headers.get('X-Hub-Signature').split(
            '=')[1]
        if type(key) == unicode:
            key = key.encode()
        mac = hmac.new(key, msg=request.data, digestmod=sha1)
        key_verified = compare_digest(mac.hexdigest(), signature)
        logging.debug('Key verified' + str(key_verified))
        return key_verified


def add_repo(repo):
    logging.debug('Adding repo')
    query = Repository.query(Repository.Name == 'repo').get()
    if query is None:
        new_repo = Repository(
            name=repo)
        new_repo.put()

def remove_repo(repo):
    logging.debug('Removing repo')
    stored_repo = Repository.query(Repository.Name == 'repo').get()
    if stored_repo is not None:
        stored_repo.key.delete()


def trigger_builds():
    logging.debug('Triggering rebuilds')
    repos_to_build = Repository.all()

    # Specify the branch to build in the payload
    payload = json.dumps({'request': {'branch': app.config['BRANCH']}})
    logging.info('Payload' + payload)
    # Do the request
    for repo in repos_to_build:
        logging.debug("Looping" + repo)
        url = 'https://api.travis-ci.org/repo/' + app.config['ORG'] + '%2F' + repo + '/requests'
        logging.debug("Url is " + url)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Travis-API-Version': 3,
                   'Authorization': 'token ' + app.config['TRAVIS_SECRET']}
        result = urlfetch.fetch(url=url, payload=payload, method=urlfetch.POST, headers=headers, follow_redirects=False)
        # try:
        #     travis_request = requests.post(url, data=payload, headers=headers, allow_redirects=False)
        #     if travis_request.status_code != 200 or travis_request.status_code != 202:
        #         logging.error(travis_request)
        #         break
        # except requests.exceptions as e:
        #     logging.error(e)
        if result.status_code == 202 or result.status_code == 200:
            logging.info(str(result.status_code) + '\n' + result.content)
        else:
            logging.error(str(result.status_code) + '\n' + result.content)

class Repository (ndb.Model):
    Name = ndb.StringProperty()
    URL = ndb.StringProperty()
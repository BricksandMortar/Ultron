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
quote = "<strong>Wanda Maximoff</strong>: Is that why you've come, to end the Avengers? <br \> <strong>Ultron</strong>: I've come to save the world! But, also... yeah. "


@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return quote
    elif request.method == 'POST':
        event_type = request.headers.get('X-GitHub-Event')

        # Accept pings
        if event_type == "ping":
            return json.dumps({'msg': 'Hi!'})

        # Accept pushes
        # TODO Change this to a method that compares against a datastructure of accepted events
        elif event_type != "push" and event_type != "create" and event_type != "delete" and event_type != "repository":
            return json.dumps({'msg': "wrong event type"})

        payload = json.loads(request.data)
        repo_name = payload['repository']['name']

        if event_type == "create":
            create_event(payload, repo_name)

        elif event_type == "delete" or event_type == "repository":
            logging.debug('Type is' + event_type)
            if (event_type == "delete" and (payload['ref_type'] != "branch" or not compare_ref(payload['ref']))) or (
                            event_type == "repository" and payload['action'] != "deleted"):
                return quote
            elif verify_key():
                remove_repo(repo_name)
            else:
                abort(403)

        elif event_type == "push":
            push_event(payload, repo_name)
    return quote


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


def compare_ref(ref):
    ref = ref.rpartition("/")[2]
    # logging.debug('Comparing ref, reduced ref is :' + ref + ' app.config branch is: ' + ref)
    return ref == app.config['BRANCH']


def create_event(payload, repo_name):
    logging.debug('Type is create')
    logging.debug('ref type:' + payload['ref_type'] + 'AND ref:' + payload['ref'] + 'AND repo:' + app.config['REPO'])
    if payload['ref_type'] != "branch" or not compare_ref(payload['ref']):
        return quote
    elif verify_key():
        logging.debug('Verifying key')
        add_repo(repo_name)
    else:
        abort(403)


def push_event(payload, repo_name):
    repo_owner = payload['repository']['owner']['name']
    logging.debug('Type is push')
    if repo_owner != app.config['ORG']:
        return quote
    elif verify_key():
        if payload['deleted'] and compare_ref(payload['ref']):
            remove_repo(repo_name)
        # Check to see if it's our template repo
        elif repo_name == app.config['REPO']:
            trigger_builds()
        else:
            return quote
    else:
        abort(403)


def add_repo(repo_name):
    logging.debug('Adding repo')
    query = Repository.query(Repository.Name == repo_name).get()
    if query is None:
        new_repo = Repository(
            Name=repo_name)
        new_repo.put()
        add_to_travis(repo_name)


def remove_repo(repo_name):
    logging.debug('Removing repo')
    stored_repo = Repository.query(Repository.Name == repo_name).get()
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
        if result.status_code == 202 or result.status_code == 200:
            logging.info(str(result.status_code) + '\n' + result.content)
        else:
            logging.error(str(result.status_code) + '\n' + result.content)


def add_to_travis(repo_name):
    travis_headers = {'Accept': 'application/json', 'Authorization': 'token ' + app.config['TRAVIS_SECRET']}
    repo_id = 0
    # Get repo id
    travis_repo_id_url = 'https://api.travis-ci.org/repos/BricksandMortar/' + repo_name
    logging.debug('Querying ' + travis_repo_id_url)
    try:
        result = urlfetch.fetch(url=travis_repo_id_url, method=urlfetch.GET, headers=travis_headers)
        if result.status_code == 200:
            travis_repo_id_response = json.loads(result.content)
            repo_id = str(travis_repo_id_response['id'])
            logging.info('Repo Id: ' + str(repo_id))
        else:
            logging.error('Received response:' + str(result.status_code) + '\n' + result.content)
            return
    except urlfetch.Error:
        logging.exception('Caught exception fetching' + travis_repo_id_url)

    # Add repo to Travis
    travis_repo_add_url = 'https://api.travis-ci.org/hooks/' + repo_id
    travis_add_data = {'hook[active]': 'true'}
    logging.debug('Adding Repo to Travis')
    try:
        form_data = urllib.urlencode(travis_add_data)
        logging.debug('Form data is:' + form_data)
        result = urlfetch.fetch(url=travis_repo_add_url, method=urlfetch.PUT, payload=form_data,
                                headers=travis_headers)
        if result.status_code != 200:
            logging.error('Received response:' + str(result.status_code) + '\n' + result.content)
            return
    except urlfetch.Error:
        logging.exception('Caught exception adding' + repo_id)

    # Ensure setting to only branches with .travis.yml present
    logging.debug('Configuring only to build this branch')
    travis_settings_url = 'https://api.travis-ci.org/repos/' + repo_id + '/settings'
    travis_settings_data = {"settings": {
        "builds_only_with_travis_yml": "true"}
    }
    try:

        json = json.dumps(travis_settings_data)
        result = urlfetch.fetch(url=travis_settings_url, method=urlfetch.PATCH, payload=json,
                                headers=travis_headers)
        if result.status_code != 200:
            logging.error('Received response:' + str(result.status_code) + '\n' + result.content)
        else:
            logging.info('Received response:' + str(result.status_code) + '\n' + result.content)
    except urlfetch.Error:
        logging.exception('Caught exception adding' + repo_id)


class Repository(ndb.Model):
    Name = ndb.StringProperty()
    URL = ndb.StringProperty()

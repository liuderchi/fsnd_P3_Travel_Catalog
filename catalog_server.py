#!/usr/bin/env python
"""catalog_server.py

Created Date: 2016-01-23
Author: Derek Liu
Description: UDND P3: Item Catalog
"""

import httplib2
import json
import requests # http lib
import random
import string

from flask import Flask
from flask import make_response
from flask import render_template
from flask import request
from flask import redirect
from flask import jsonify
from flask import url_for
from flask import flash
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from sqlalchemy import create_engine
from sqlalchemy import asc
from sqlalchemy.orm import sessionmaker

from database_setup import Base
from database_setup import User
from database_setup import Region
from database_setup import Spot

app = Flask(__name__)

#Connect to Database and create database session
engine = create_engine('sqlite:///regionspot_users.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
                open('client_secret.json', 'r').read())['web']['client_id']

# TODO: session_add_commit()


# Helper Functions User data
def create_user(login_session):
    new_user = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def get_user_object(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in range(32))  # psuedo-random
    login_session['state'] = state
    return render_template('login.html', STATE=state)
    #return 'login page. template: login.html'


@app.route('/gconnect', methods=['POST'])
def gconnect():
    #return 'google account connect. send requst by json.dump()'
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # get authorization code
    code = request.data
    try:
        # Upgrade Authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        # check client_secret.json has redirect_uris schema
        oauth_flow.redirect_uri = 'postmessage'
        # get credentials: may error due to flask version
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade authorization code'), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    # verifying access_token
    access_token = credentials.access_token
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
        % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # check1: check access_token inside credentials is valid
    if result.get('error') is not None:
        # If error in the access token info, abort with 500: internal error
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # check2: now access_token is valid, but not sure is for intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # check3: Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
    # check4: check if user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # now access_token is valid and user is making first login
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id
    # Get user info from API
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()  # user info from API
    # store interested user info
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # check if user exist in database, if no, create one for he/she
    user_id = get_user_id(login_session['email'])
    if not user_id:    # get_user_id() return None for new user
        user_id = create_user(login_session)
    # add current user_id to login_session
    login_session['user_id'] = user_id

    output = '<h1>Welcome, ' + login_session['username'] + '!</h1>'
    output += '<img src="' + login_session['picture'] + '" '
    output += ' style = "width: 300px; height: 300px;border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    #return 'google account DISsconnect. send requst by json.dump()'
    # DISCONNECT - Revoke a current user's token and reset their login_session
    # check user connection via credentials/access_token
    credentials = login_session.get('credentials')
    if credentials is None:
        #response = make_response(json.dumps('current user not connected'), 401)
        #response.headers['Content-Type'] = 'application/json'
        #return response
        flash('You are already logged out!')
        return redirect(url_for('show_region'))
    access_token = credentials.access_token
    # access_token = credentials['access_token']  # new version
    print ('[gdisconnect] access_token: {}'.format(access_token))
    print ('[gdisconnect] user name: {}'.format(login_session['username']))

    # revoke current token, c.f. verifying access_token @/gconnect
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print ('result from api server: {}'.format(result))

    # handle result from api
    if result['status'] == '200':
        del login_session['credentials']
        # del login_session['access_token']  # new version
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        #response = make_response(json.dumps('Successfully disconnected.'), 200)
        #response.headers['Content-Type'] = 'application/json'
        #return response
        flash("you are successfully logged out")
        return redirect(url_for('show_region'))
    else:
    	response = make_response(
                    json.dumps('Failed to revoke token for given user.', 400))
    	response.headers['Content-Type'] = 'application/json'
    	return response


@app.route('/region/JSON')
def show_region_json():
    regions = session.query(Region).all()
    return jsonify(Regions=[region.serialize for region in regions])

@app.route('/region/<int:region_id>/JSON')
@app.route('/region/<int:region_id>/spot/JSON')
def show_spot_json(region_id):
    spots = session.query(Spot).filter_by(region_id=region_id).all()
    return jsonify(Spots=[spot.serialize for spot in spots])

@app.route('/region/<int:region_id>/spot/<int:spot_id>/JSON')
def show_one_spot_json(region_id, spot_id):
    spot = session.query(Spot).filter_by(
              region_id=region_id).filter_by(
              id=spot_id).all()
    return jsonify(Spot=[s.serialize for s in spot])


@app.route('/')
@app.route('/region/')
def show_region():
    regions = session.query(Region).order_by(asc(Region.name))
    if 'username' not in login_session:
        return render_template('public_regions.html', regions=regions)
    else:
        return render_template('regions.html', regions=regions)

@app.route('/region/new/', methods=['GET', 'POST'])
def new_region():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        new_region = Region(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(new_region)
        session.commit()
        flash('New region %s is successfully Created' % new_region.name)
        return redirect(url_for('show_region'))
    if request.method == 'GET':
        return render_template('new_region.html')


@app.route('/region/<int:region_id>/edit/', methods=['GET', 'POST'])
def edit_region(region_id):
    if 'username' not in login_session:
        return redirect('/login')
    target_region = session.query(Region).filter_by(id=region_id).one()
    # check user permission to the region to prevent url attack
    if target_region.user_id != login_session['user_id']:
        regions = session.query(Region).order_by(asc(Region.name))
        return render_template(
            'regions_alert.html',
            regions=regions,
            message="You are not authorized to edit this region." \
                    " Please create your own region in order to edit.")
    if request.method == 'POST':
        if request.form['name']:
            target_region.name = request.form['name']
            session.add(target_region)
            session.commit()
            flash('Region %s is successfully Edited' % target_region.name)
        return redirect(url_for('show_region'))
    if request.method == 'GET':
        return render_template('edit_region.html', region=target_region)


@app.route('/region/<int:region_id>/delete/', methods=['GET', 'POST'])
def delete_region(region_id):
    if 'username' not in login_session:
        return redirect('/login')
    target_region = session.query(Region).filter_by(id=region_id).one()
    # check user permission to the region to prevent url attack
    if target_region.user_id != login_session['user_id']:
        regions = session.query(Region).order_by(asc(Region.name))
        return render_template(
            'regions_alert.html',
            regions=regions,
            message="You are not authorized to delete this region." \
                    " Please create your own region in order to delete.")
    if request.method == 'POST':
        session.delete(target_region)
        session.commit()
        flash('Region %s is successfully Deleted' % target_region.name)
        return redirect(url_for('show_region'))
    if request.method == 'GET':
        return render_template('delete_region.html', region=target_region)


@app.route('/region/<int:region_id>/')
@app.route('/region/<int:region_id>/spot/')
def show_spot(region_id):
    region = session.query(Region).filter_by(id=region_id).one()
    spots = session.query(Spot).filter_by(region_id=region_id).all()
    region_creator = get_user_object(region.user_id)
    if 'username' not in login_session or \
    region_creator.id != login_session['user_id']:
        # TODO: handle public template
        return render_template('public_spots.html',
                               region=region,
                               spots=spots,
                               region_creator=region_creator)
    else:
        return render_template('spots.html',
                               region=region,
                               spots=spots,
                               region_creator=region_creator)

@app.route('/region/<int:region_id>/spot/<int:spot_id>/')
def show_one_spot(region_id, spot_id):
    # Better to have
    return ('show spot #{} in region #{}. '
            + 'template: spot.html').format(spot_id, region_id)


@app.route('/region/<int:region_id>/spot/new/', methods=['GET','POST'])
def new_spot(region_id):
    if 'username' not in login_session:
        return redirect('/login')
    # check user permission to the region to prevent url attack
    target_region = session.query(Region).filter_by(id=region_id).one()
    if target_region.user_id != login_session['user_id']:
        regions = session.query(Region).order_by(asc(Region.name))
        return render_template(
            'regions_alert.html',
            regions=regions,
            message="You are not authorized to create spot." \
                    " Please create your own region in order to create.")
    if request.method == 'POST':
        region = session.query(Region).filter_by(id=region_id).one()
        new_spot = Spot(name=request.form['name'],
                        description=request.form['description'],
                        price=request.form['price'],
                        type=request.form['type'],
                        region_id=region_id,
                        user_id=region.user_id)
        session.add(new_spot)
        session.commit()
        flash('New spot %s is successfully Created' % new_spot.name)
        return redirect(url_for('show_spot', region_id=region_id))
    if request.method == 'GET':
        region = session.query(Region).filter_by(id=region_id).one()
        return render_template('new_spot.html', region=region)


@app.route('/region/<int:region_id>/spot/<int:spot_id>/edit/',
           methods=['GET','POST'])
def edit_spot(region_id, spot_id):
    if 'username' not in login_session:
        return redirect('/login')
    # check user permission to the spot to prevent url attack
    target_region = session.query(Region).filter_by(id=region_id).one()
    if target_region.user_id != login_session['user_id']:
        regions = session.query(Region).order_by(asc(Region.name))
        return render_template(
            'regions_alert.html',
            regions=regions,
            message="You are not authorized to edit this spot." \
                    " Please create your own region in order to edit.")
    target_spot = session.query(Spot).filter_by(id=spot_id).one()
    if target_spot:
        if request.method == 'POST':
            if request.form['name']:
                target_spot.name = request.form['name']
            if request.form['description']:
                target_spot.description = request.form['description']
            if request.form['price']:
                target_spot.price = request.form['price']
            if request.form['type']:
                target_spot.type = request.form['type']
            session.add(target_spot)
            session.commit()
            flash('Spot %s is successfully Edited' % target_spot.name)
            return redirect(url_for('show_spot', region_id=region_id))
        if request.method == 'GET':
            return render_template('edit_spot.html',
                                   region_id=region_id, spot=target_spot)


@app.route('/region/<int:region_id>/spot/<int:spot_id>/delete/',
           methods=['GET','POST'])
def delete_spot(region_id, spot_id):
    if 'username' not in login_session:
        return redirect('/login')
    # check user permission to the spot to prevent url attack
    target_region = session.query(Region).filter_by(id=region_id).one()
    if target_region.user_id != login_session['user_id']:
        regions = session.query(Region).order_by(asc(Region.name))
        return render_template(
            'regions_alert.html',
            regions=regions,
            message="You are not authorized to delete this spot." \
                    " Please create your own region in order to delete.")
    target_spot = session.query(Spot).filter_by(id=spot_id).one()
    if target_spot:
        if request.method == 'POST':
            session.delete(target_spot)
            session.commit()
            flash('Spot %s is successfully Deleted' % target_spot.name)
            return redirect(url_for('show_spot', region_id=region_id))
        if request.method == 'GET':
            return render_template('delete_spot.html',
                                   region_id=region_id, spot=target_spot)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'   # for flash message
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

#!/usr/bin/env python

from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "catalogapp"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)


@app.route('/login')
def show_login():
    # Create anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    print(h.request(url, 'GET')[1])
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
                                'Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        login_session['user_id'] = getUserID(login_session['email'])
        flash("You are logged in as %s" % login_session['username'])
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Add user id to DB if not in DB already, and add id to login_session
    user_id = getUserID(data['email'])
    if not user_id:
        added_user_id = createUser(login_session)
        login_session['user_id'] = added_user_id
    else:
        login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += (' " style = "width: 300px; height: 300px;border-radius: 150px;'
               '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> ')
    flash("You are now logged in as %s" % login_session['username'])
    print("done!")
    return output

# User Helper Functions


def createUser(login_session):
    session = DBSession()
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    session = DBSession()
    return session.query(User).filter_by(id=user_id).one()


def getUserID(email):
    session = DBSession()
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print("Access Token is None")
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print("In gdisconnect access token is %s" % (access_token))
    print("User name is: ")
    print(login_session['username'])
    url = "https://accounts.google.com/o/oauth2/revoke?token={}" \
        .format(login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print("result is ")
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        error_string = "Failed to revoke token for given user."
        response = make_response(json.dumps(error_string), 400)
        response.headers['Content-Type'] = "application/json"
        return response


# Render homepage
# Show categories on the left, and latest items in middle
@app.route('/')
@app.route('/home')
@app.route('/catalog')
def home():
    """
        Home page of application
    """
    session = DBSession()
    categories = session.query(Category).order_by(Category.name)
    # Pass to template, 10 items most recent items
    latest_items = session.query(Item).order_by(Item.id)[0:10]
    return render_template('home.html',
                           categories=categories,
                           items=latest_items)


@app.route('/JSON')
@app.route('/categories/JSON')
def all_json():
    """
        Returns JSON of all category database fields
    """
    session = DBSession()
    all_data = session.query(Category)
    return jsonify(categories=[cat.serialize for cat in all_data.all()])


@app.route('/catalog/<category>')
def show_category(category):
    """
        Generate page for a single category
    """
    session = DBSession()
    category_id = (session.query(Category).filter_by(name=category).one()).id
    items = session.query(Item).filter_by(category_id=category_id).all()
    # To generate side bar of categories
    cat_list = session.query(Category).order_by(Category.name)
    return render_template('show_category.html',
                           items=items,
                           category=category,
                           all_categories=cat_list)


@app.route('/catalog/<category>/<item>')
@app.route('/<category>/<item>')
def show_item(category, item):
    """
        Generate page for a single item
    """
    session = DBSession()
    item = session.query(Item).filter_by(name=item).one()
    return render_template('show_item.html', item=item, category=item.category)

@app.route('/catalog/add_category', methods=['GET', 'POST'])
def add_category():
    """
        On call, sends a post form to client to be able to add
        new item to catalog
    """
    session = DBSession()
    if 'username' not in login_session:
        flash('You must be logged in to add category!')
        return redirect('/home')
    # Process form from client to add item
    if request.method == 'POST':
        cat_id = session.query(Category) \
            .filter_by(name=request.form['category']) \
            .one() \
            .id
        new_category = Category(name=request.form['name'],
                        user_id=getUserID(login_session['email']))
        session.add(new_category)
        session.commit()
        flash("Added New Category: {}".format(new_category.name))
        return redirect(url_for('home'))
    else:
        # Serve add item form to client
        cat_names = [cat.name for cat in session.query(Category).all()]
        return render_template('add_category.html', cat_list=cat_names)


@app.route('/catalog/add_item', methods=['GET', 'POST'])
def add_item():
    """
        On call, sends a post form to client to be able to add
        new item to catalog
    """
    session = DBSession()
    if 'username' not in login_session:
        flash('You must be logged in to add item!')
        return redirect('/home')
    # Process form from client to add item
    if request.method == 'POST':
        cat_id = session.query(Category) \
            .filter_by(name=request.form['category']) \
            .one() \
            .id
        new_item = Item(name=request.form['name'],
                        description=request.form['description'],
                        user_id=getUserID(login_session['email']),
                        category_id=cat_id)
        session.add(new_item)
        session.commit()
        flash("Added New Item: {}".format(new_item.name))
        return redirect(url_for('home'))
    else:
        # Serve add item form to client
        cat_names = [cat.name for cat in session.query(Category).all()]
        return render_template('add_form_item.html', cat_list=cat_names)


@app.route('/catalog/<category_name>/<item_name>/delete',
           methods=['GET', 'POST'])
def delete_item(item_name, category_name):
    """
        Given an Item name and Category name, it sends a form to
        client to complete a POST Request to confirm Item deletion
    """
    session = DBSession()
    if 'username' not in login_session:
        flash('You must be logged in to delete an item!')
        return redirect('/home')
    item_to_delete = session.query(Item).filter_by(name=item_name).one()
    item_user_id = session.query(User).filter_by(id=item_to_delete.user_id) \
        .one() \
        .id
    if login_session['user_id'] != item_user_id:
        flash("You do not have permission to delete: {}"
              .format(item_to_delete.name))
        return redirect('/home')
    # Process form from client to delete item
    if request.method == 'POST':
        session.delete(item_to_delete)
        session.commit()
        flash("Deleted Item: {}".format(item_to_delete.name))
        return redirect(url_for('home'))
    else:
        # Serve delete confirmation form to client
        return render_template('delete_confirm_item.html',
                               item=item_to_delete,
                               category_name=category_name)


@app.route('/catalog/<category_name>/<item_name>/edit',
           methods=['GET', 'POST'])
def edit_item(item_name, category_name):
    """
        Given an Item name and Category name, it sends a form to
        client to complete a POST Request to change Item data
    """
    session = DBSession()
    if 'username' not in login_session:
        flash('You must be logged in to edit an item!')
        return redirect('/home')
    item_to_edit = session.query(Item).filter_by(name=item_name).one()
    # Verify if logged in user can edit item
    item_user_id = session.query(User).filter_by(id=item_to_edit.user_id) \
        .one() \
        .id
    if login_session['user_id'] != item_user_id:
        flash("You do not have permission to edit: {}"
              .format(item_to_edit.name))
        return redirect('/home')
    # Process form from client to update item
    if request.method == 'POST':
        if request.form['name']:
            item_to_edit.name = request.form['name']
        if request.form['description']:
            item_to_edit.description = request.form['description']
        if request.form['category']:
            new_cat_id = session.query(Category) \
                .filter_by(name=request.form['category']) \
                .one() \
                .id
            item_to_edit.category_id = new_cat_id
        session.add(item_to_edit)
        session.commit()
        flash("Edited Item: {}".format(item_to_edit.name))
        return redirect(url_for('home'))
    # Serve edit form to client
    else:
        cat_names = [cat.name for cat in session.query(Category).all()]
        return render_template('edit_form_item.html',
                               item=item_to_edit,
                               category_name=category_name,
                               cat_list=cat_names)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='127.0.0.1', port=5000)

# Imports
import sys
import bcrypt
import functools

from flask import Flask, flash, render_template, request, redirect, url_for, session
from pymongo import MongoClient


from bson import ObjectId
from flask.json import JSONEncoder
from werkzeug.routing import BaseConverter

from .forms import *
from .config import MONGO_URI, SECRET_KEY

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

client = MongoClient(MONGO_URI)
db = client.diliventures
devices = db.devices
users = db.users


class MongoJSONEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        else:
            return super().default(o)


class ObjectIdConverter(BaseConverter):
    def to_python(self, value):
        return ObjectId(value)

    def to_url(self, value):
        return str(value)


app.json_encoder = MongoJSONEncoder
app.url_map.converters['objectid'] = ObjectIdConverter


def login_required(func):
    @functools.wraps(func)
    def secure_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.url))
        return func(*args, **kwargs)

    return secure_function

# Homepage


@app.route("/", methods=['GET'])
def index():
    return render_template('pages/home.html')

# Register new user


@app.route("/register", methods=['POST', 'GET'])
def register():
    # if "email" in session:
    #     return redirect(url_for("logged_in"))

    if request.method == "GET":
        form = RegisterForm()
        return render_template('forms/register.html', form=form)

    if request.method == "POST":
        form = RegisterForm(request.form)
        user = form.user_name.data
        email = form.email.data
        password1 = form.password1.data
        password2 = form.password2.data

        if form.validate_on_submit():
            email_found = users.find_one({"email": email})

            if email_found:
                flash(request.form['email'] +
                      ' is already registered please try login in instead or try another email!')
                return render_template('forms/register.html', form=form)

            if password1 != password2:
                flash(
                    'passwords should match!')
                return render_template('forms/register.html', form=form)

            try:
                hashed = bcrypt.hashpw(
                    password2.encode('utf-8'), bcrypt.gensalt())
                user_input = {'name': user, 'email': email, 'password': hashed}
                saved_user = users.insert_one(user_input)
                saved_id = saved_user.inserted_id
                return redirect(url_for('dashboard', user_id=saved_id))

            except:
                print(sys.exc_info())
                flash(
                    'Please try again!')
                return render_template('forms/register.html', form=form)

        else:
            for field, message in form.errors.items():
                flash(field + ' - ' + str(message))
            return render_template('forms/register.html', form=form)


# Login user
@app.route('/login', methods=['POST', 'GET'])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard", user_id=session["user_id"]))

    form = LoginForm()
    if request.method == "POST":
        email = form.email.data
        password = form.password.data

        email_found = users.find_one({"email": email})

        if email_found:
            loged_id = email_found['_id']
            passwordcheck = email_found['password']

            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["user_id"] = loged_id
                return redirect(url_for('dashboard', user_id=loged_id))
            else:
                if "user_id" in session:
                    return redirect(url_for('dashboard', user_id=loged_id))
                flash('Wrong Password')
                return render_template('forms/login.html', form=form)
        else:
            flash('No Such Email Found!')
            return render_template('forms/login.html', form=form)
    return render_template('forms/login.html', form=form)


# logout
@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    flash('Logged out sucessfully')
    return redirect(url_for('index'))


# Dashboard
@app.route('/user/<objectid:user_id>', methods=['GET'])
@login_required
def dashboard(user_id):
    user = users.find_one({'_id': user_id})

    device_owned = []
    for device in devices.find({"user_id": user_id}):
        device_owned.append(device)
    return render_template('pages/dashboard.html', user=user, my_device=device_owned)


# Add device
@app.route('/addnewdevice/<objectid:user_id>', methods=['GET'])
@login_required
def add_device(user_id):
    form = DeviceForm()
    user = users.find_one({"_id": user_id})
    return render_template('/forms/addnewdevice.html', form=form, user=user)


@app.route('/addnewdevice/<objectid:user_id>', methods=['POST'])
@login_required
def newdevice_submission(user_id):
    current_user = users.find_one({"_id": user_id})
    form = DeviceForm()
    device_name = form.device_name.data
    device_imei = form.device_imei.data
    status = form.status.data
    owner_id = user_id

    device_found = devices.find_one({"device_imei": device_imei})

    if device_found:
        owner = device_found['user_id']
        user = users.find_one({"_id": owner})
        user_name = user['name']
        flash('This device already belong to ' + user_name +
              ' visit device search page to view more info about the device')
        return render_template('/forms/addnewdevice.html', form=form, user=current_user)

    if form.validate_on_submit():
        try:
            devices.insert_one({'user_id': owner_id, 'device_name': device_name,
                               'device_imei': device_imei, 'status': status})
            flash(
                device_name + ' added to your collection Sucessfully you can add a new device!')
            return render_template('/forms/addnewdevice.html', form=form, user=current_user)
        except:
            print(sys.exc_info())
            flash('Your ' + request.form['name'] +
                  ' was NOT added to your collection please try again!')
            return render_template('/forms/addnewdevice.html', form=form, user=current_user)

    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message))
        return render_template('/forms/addnewdevice.html', form=form, user=current_user)


# Tranfer/update device owner
@app.route('/device/<objectid:device_id>/transfer', methods=['GET'])
@login_required
def transfer_device(device_id):
    form = OwnershipTransferForm()
    device = devices.find_one({"_id": device_id})
    return render_template('forms/transfer.html', form=form, device=device)


@app.route('/device/<objectid:device_id>/transfer', methods=['POST'])
@login_required
def transfer_deviceSubmision(device_id):

    form = OwnershipTransferForm()
    device = devices.find_one({"_id": device_id})
    previous_user = device['user_id']
    previous_userDetail = users.find_one({"_id": previous_user})

    # new_name = form.new_userName.data
    new_email = form.new_userEmail.data
    new_userFound = users.find_one({"email": new_email})

    if form.validate_on_submit():
        if new_userFound:
            new_userID = new_userFound["_id"]
            try:
                devices.find_one_and_update(
                    {'_id': device_id}, {'$set': {'user_id': new_userID}})
                flash('owner changed sucessfully to ' + new_userFound['name'])

                remaing_devices = []
                for rem_device in devices.find({"user_id": previous_user}):
                    remaing_devices.append(rem_device)

                return render_template('pages/dashboard.html', user=previous_userDetail, my_device=remaing_devices)

            except:
                print(sys.exc_info())
                flash('INTERNAL SERVER ERROR PLEASE TRY AGAIN LATER')
                return render_template('forms/transfer.html', form=form, device=device)

    else:
        flash(
            'No user with that email in our database try registering the user and try again')
        return render_template('forms/transfer.html', form=form, device=device)


# Update device/tranfer device
@app.route('/device/<objectid:device_id>/status', methods=['GET'])
@login_required
def edit_deviceStatus(device_id):

    form = DeviceForm()
    device = devices.find_one({"_id": device_id})
    user_id = device["user_id"]
    user = users.find_one(user_id)

    if device == None:
        return render_template('errors/404.html')
    return render_template('forms/editdevicestatus.html', form=form, user=user, device=device)


@app.route('/device/<objectid:device_id>/status', methods=['POST'])
@login_required
def submit_editstatus(device_id):
    form = StatusForm()
    device = devices.find_one({"_id": device_id})
    user_id = device["user_id"]
    user = users.find_one({"_id": user_id})
    status = form.status.data

    if form.validate_on_submit():
        try:
            devices.find_one_and_update(
                {'_id': device_id}, {'$set': {'status': status}})
            flash('Status changed sucessfully to ' + status)

            device_owned = []
            for device in devices.find({"user_id": user_id}):
                device_owned.append(device)

            return render_template('pages/dashboard.html', user=user, my_device=device_owned)

        except:
            print(sys.exc_info())
            flash('INTERNAL SERVER ERROR PLEASE TRY AGAIN LATER')
            return render_template('forms/editdevicestatus.html', form=form, user=user, device=device)

    else:
        flash(
            'No user with that email in our database try registering the user and try again')
        return render_template('forms/editdevicestatus.html', form=form, user=user, device=device)


if __name__ == "__main__":
    app.run()

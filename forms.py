from datetime import datetime

from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SelectMultipleField, DateTimeField, BooleanField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, URL, Regexp


class DeviceForm(FlaskForm):
    device_name = StringField(
        'device name', validators=[DataRequired()]
    )

    device_imei = StringField(
        'deviceimei', validators=[DataRequired()]
    )

    status = SelectField(
        'status',
        choices=[
            ('Lost', 'Lost'),
            ('Available', 'Available'),
            ('Stolen', 'Stolen'),
        ], default='Available')

    submit = SubmitField(label=('Submit'))


class OwnershipTransferForm(FlaskForm):
    new_userName = StringField(
        'new user', validators=[DataRequired()]
    )
    new_userEmail = StringField(
        'new user', validators=[DataRequired()]
    )

    submit = SubmitField(label=('Submit'))


class RegisterForm(FlaskForm):
    user_name = StringField(
        'device name', validators=[DataRequired()]
    )

    email = EmailField(
        'email', validators=[DataRequired()]
    )

    password1 = PasswordField(
        'password', validators=[DataRequired()]
    )
    password2 = PasswordField(
        'password', validators=[DataRequired()]
    )

    submit = SubmitField(label=('Submit'))


class LoginForm(FlaskForm):

    email = EmailField(
        'email', validators=[DataRequired()]
    )

    password = PasswordField(
        'password', validators=[DataRequired()]
    )

    submit = SubmitField(label=('Submit'))


class StatusForm(FlaskForm):
    status = SelectField(
        'status',
        choices=[
            ('Lost', 'Lost'),
            ('Available', 'Available'),
            ('Stolen', 'Stolen'),
        ], default='Available')

    submit = SubmitField(label=('Submit'))

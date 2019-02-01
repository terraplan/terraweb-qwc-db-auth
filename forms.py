from flask_wtf import FlaskForm
from wtforms import BooleanField, HiddenField, PasswordField, PasswordField, \
    StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')


class VerifyForm(FlaskForm):
    token = StringField('Verification code', validators=[DataRequired()])


class NewPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])


class EditPasswordForm(FlaskForm):
    reset_password_token = HiddenField(validators=[Optional()])
    password = PasswordField(
        'New password',
        validators=[DataRequired(), Length(min=8)]
    )
    password_confirmation = PasswordField(
        'Confirm new password',
        validators=[DataRequired(), EqualTo('password')]
    )

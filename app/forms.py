"""
Authentication and registration forms for TrustVault.

Uses Flask-WTF to automatically provide CSRF protection across all forms.
"""
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Regexp, Optional
from app.models import Organization, User


class LoginForm(FlaskForm):
    """
    Login form for user authentication.
    """
    username = StringField(
        'Username',
        validators=[DataRequired(message="Username is required.")]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(message="Password is required.")]
    )
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegisterForm(FlaskForm):
    """
    Registration form.
    
    Creates a new Organization (tenant) and an initial Admin account
    who manages users and documents for that organization.
    """
    organization_name = StringField(
        'Organization Name',
        validators=[
            DataRequired(message="Organization name is required."),
            Length(min=2, max=100, message="Organization name must be between 2 and 100 characters.")
        ]
    )
    username = StringField(
        'Admin Username',
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=80, message="Username must be between 3 and 80 characters.")
        ]
    )
    email = StringField(
        'Admin Email Address',
        validators=[
            DataRequired(message="Email address is required."),
            Regexp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', message="Please provide a valid email address."),
            Length(max=120)
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required."),
            Length(min=10, message="Password must be at least 10 characters long.")
        ]
    )
    password_confirm = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message="Please confirm your password."),
            EqualTo('password', message="Passwords must match.")
        ]
    )
    submit = SubmitField('Register Organization & Admin')

    def validate_organization_name(self, field):
        """Ensure organization name is globally unique."""
        name = field.data.strip() if field.data else ''
        if Organization.query.filter_by(name=name).first():
            raise ValidationError("An organization with this name already exists.")

    def validate_username(self, field):
        """Ensure username is globally unique."""
        uname = field.data.strip() if field.data else ''
        if User.query.filter_by(username=uname).first():
            raise ValidationError("This username is already taken.")

    def validate_email(self, field):
        """Ensure email is globally unique (case-insensitive check)."""
        mail = field.data.strip().lower() if field.data else ''
        if User.query.filter(User.email.ilike(mail)).first():
            raise ValidationError("This email address is already registered.")


class DocumentUploadForm(FlaskForm):
    """
    Form for uploading a new document.
    """
    title = StringField(
        'Document Title',
        validators=[
            DataRequired(message="Document title is required."),
            Length(max=255, message="Title cannot exceed 255 characters.")
        ]
    )
    description = TextAreaField(
        'Description',
        validators=[
            Optional(),
            Length(max=2000, message="Description cannot exceed 2000 characters.")
        ]
    )
    file = FileField(
        'Select File (Max 5 MB)',
        validators=[
            DataRequired(message="Please select a file to upload.")
        ]
    )
    submit = SubmitField('Upload Document')


class DocumentEditForm(FlaskForm):
    """
    Form for editing an existing document's metadata or replacing with a new version.
    """
    title = StringField(
        'Document Title',
        validators=[
            DataRequired(message="Document title is required."),
            Length(max=255, message="Title cannot exceed 255 characters.")
        ]
    )
    description = TextAreaField(
        'Description',
        validators=[
            Optional(),
            Length(max=2000, message="Description cannot exceed 2000 characters.")
        ]
    )
    file = FileField(
        'Upload New Version (Optional, Max 5 MB)',
        validators=[
            Optional()
        ]
    )
    submit = SubmitField('Save Changes')


class GrantAccessForm(FlaskForm):
    """
    Form to grant document access to another user in the same organization.
    """
    user_id = SelectField(
        'Select Colleague',
        coerce=int,
        validate_choice=False,
        validators=[DataRequired(message="Please select a user.")]
    )
    permission = SelectField(
        'Permission Level',
        choices=[
            ('read', 'Read (View and Download)'),
            ('edit', 'Edit (View, Download, and Update)')
        ],
        validators=[DataRequired(message="Please select a permission level.")]
    )
    submit = SubmitField('Grant Access')


class ChangePermissionForm(FlaskForm):
    """
    Form to change an existing grant's permission level.
    """
    permission = SelectField(
        'Permission Level',
        choices=[
            ('read', 'Read'),
            ('edit', 'Edit')
        ],
        validators=[DataRequired()]
    )
    submit = SubmitField('Update Permission')


class CreateUserForm(FlaskForm):
    """
    Form for administrators to create a new user account within their organization.
    """
    username = StringField(
        'Username',
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=80, message="Username must be between 3 and 80 characters."),
            Regexp(r'^[a-zA-Z0-9_.-]+$', message="Username may only contain letters, numbers, dots, hyphens, and underscores.")
        ]
    )
    email = StringField(
        'Email Address',
        validators=[
            DataRequired(message="Email address is required."),
            Regexp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', message="Please provide a valid email address."),
            Length(max=120)
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required."),
            Length(min=10, message="Password must be at least 10 characters long.")
        ]
    )
    role = SelectField(
        'Role',
        choices=[
            ('viewer', 'Viewer (Read-only access to explicitly shared documents)'),
            ('owner', 'Owner (Can upload documents and manage document sharing)'),
            ('admin', 'Admin (Full access to all documents and user management)')
        ],
        default='viewer',
        validators=[DataRequired(message="Please select a user role.")]
    )
    submit = SubmitField('Create User')

    def validate_username(self, field):
        """Ensure username is globally unique."""
        uname = field.data.strip() if field.data else ''
        if User.query.filter_by(username=uname).first():
            raise ValidationError("A user with this username already exists.")

    def validate_email(self, field):
        """Ensure email is globally unique (case-insensitive check)."""
        mail = field.data.strip().lower() if field.data else ''
        if User.query.filter(User.email.ilike(mail)).first():
            raise ValidationError("This email address is already registered.")


class ChangeRoleForm(FlaskForm):
    """
    Form for administrators to change another user's role.
    """
    role = SelectField(
        'New Role',
        choices=[
            ('viewer', 'Viewer'),
            ('owner', 'Owner'),
            ('admin', 'Admin')
        ],
        validators=[DataRequired(message="Please select a role.")]
    )
    submit = SubmitField('Change Role')


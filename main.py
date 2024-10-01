from flask import Flask, abort, render_template, redirect, url_for, flash, request, render_template_string
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Text, DateTime, func
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, EmailField, TextAreaField, TelField
from wtforms.fields import PasswordField
from wtforms.validators import DataRequired, URL, Email, Length, EqualTo
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from sqlalchemy.orm import joinedload
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from reset_password_email_html_content import reset_password_email_html_content
import os
from dotenv import load_dotenv
from flask import current_app


load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
Bootstrap5(app)

# Email configuration (for Gmail in this case)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'

# Initialize Flask-Mail
mail = Mail(app)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI', 'sqlite:///posts.db')

db = SQLAlchemy(model_class=Base)
db.init_app(app)
ckeditor = CKEditor()
ckeditor.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect unauthorized users to the login page
login_manager.login_message_category = "info"
app.config['RESET_PASS_TOKEN_MAX_AGE'] = 3600  # Token expires in 1 hour


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class ResetPasswordRequestForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')
# CONFIGURE TABLE
class BlogPost(db.Model):
    __tablename__ = 'blog_posts'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author = relationship("User", back_populates="posts")
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post", cascade='all, delete-orphan')

class BlogForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    subtitle = StringField('Subtitle', validators=[DataRequired()])

    img_url = StringField('Image URL', validators=[DataRequired()])
    body = CKEditorField('Body', validators=[DataRequired()])
    submit = SubmitField('Submit')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(250), nullable=False)
    email: Mapped[str] = mapped_column(String(250), nullable=False, unique=True)

    password: Mapped[str] = mapped_column(String(250), nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    # Parent relationship: "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")

    @staticmethod
    def validate_reset_password_token(token: str, user_id: int):
        user = db.session.get(User, user_id)

        if user is None:
            return None

        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        try:
            token_user_email = serializer.loads(
                token,
                max_age=app.config["RESET_PASS_TOKEN_MAX_AGE"],
                salt=user.password,
            )
        except (BadSignature, SignatureExpired):
            return None

        if token_user_email != user.email:
            return None

        return user

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments", lazy="joined")  # Eager loading
    post_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    #timestamp: Mapped[datetime.datetime] = mapped_column(DateTime, default=func.now())

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = TelField('Phone', validators=[DataRequired(), Length(min=10, max=15)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10)])
    submit = SubmitField('Send Message')

class CommentForm(FlaskForm):
    text = CKEditorField('Text', validators=[DataRequired()])
    submit = SubmitField('Comment')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('repeat password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.options(joinedload(BlogPost.author)).all()
    year = date.today().year
    return render_template("index.html", year=year, all_posts=posts, current_user=current_user)

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = UserForm()

    if form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()

        if user:
            flash("Email already registered. Please log in.")
            return redirect(url_for('login'))

        # Create a user
        new_user = User(
            username=form.username.data,
            email=form.email.data,
        )
        hash_password = generate_password_hash(password=form.password.data, method="scrypt", salt_length=8)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hash_password,
        )
        db.session.add(new_user)
        db.session.commit()

        # Log the new user in
        login_user(new_user)

        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form, current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()

        if not user:
            flash("Couldn't find the email")
            return redirect(url_for('register'))

        elif not check_password_hash(user.password, form.password.data):
            flash("Wrong password")
            return redirect(url_for('login'))

        login_user(user)


        return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def show_post(post_id):

    with app.app_context():
        requested_post = db.session.execute(
            db.select(BlogPost).options(joinedload(BlogPost.author)).where(BlogPost.id == post_id)
        ).scalar()

        comments = requested_post.comments

    return render_template("post.html", post=requested_post, current_user=current_user, comments=comments)

@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    msg_sent = False

    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        phone = form.phone.data
        message = form.message.data

        # Create the email message
        msg = Message(
            "New Contact Form Submission",
            sender=email,  # The sender of the message will be the user's email
            recipients=app.config['MAIL_USERNAME']  # Your email address
        )

        # Format the message body
        msg.body = f"""
        New message from {name}:

        Email: {email}
        Phone: {phone}

        Message:
        {message}
        """

        try:
            # Send the email
            mail.send(msg)
            flash("Your message has been sent successfully!", "success")
            msg_sent = True
        except Exception as e:
            flash("Something went wrong. Please try again.", "danger")
            print(f"Failed to send email: {e}")

        return redirect(url_for('contact'))

    return render_template('contact.html', form=form, msg_sent=msg_sent)


@app.route("/new_post", methods=['GET', 'POST'])
@login_required
def new_post():
    form = BlogForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            author=current_user,
            img_url=form.img_url.data,
            body=form.body.data,
            date=date.today()
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))

    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit_post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = BlogPost.query.get_or_404(post_id)

    if post.author_id != current_user.id:
        flash("You do not have permission to edit this post.")
        return redirect(url_for('show_post', post_id=post_id))

    edit_form = BlogForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author_id = current_user.id  # Fix here
        post.body = edit_form.body.data
        db.session.commit()

        return redirect(url_for("get_all_posts", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user, is_edit=True)


@app.route("/delete_post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def delete_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if post.author_id != current_user.id:
        flash("You do not have permission to delete this post.", "danger")
        return redirect(url_for('get_all_posts'))

    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully.", "success")
    return redirect(url_for('get_all_posts'))



@app.route('/comment/<int:post_id>', methods=['GET', 'POST'])
@login_required
def comment(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(text=form.text.data, author_id=current_user.id, post_id=post_id)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("comment.html", form=form, current_user=current_user)
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/my-blogs/<int:user_id>', methods=['GET', 'POST'])
def my_blogs(user_id):
    user = User.query.get(user_id)
    all_posts = db.session.execute(db.select(BlogPost).where(BlogPost.author_id == user.id)).scalars().all()
    return render_template('my-blogs.html', posts=all_posts, current_user=current_user)

def generate_reset_password_token(self):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(self.email, salt=self.password)


# Verify the reset token
def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['3b7365523bf3ab416eb024b74cac59bc'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except:
        return None
    return User.query.filter_by(email=email).first()

def send_reset_password_email(user):
    token = generate_reset_password_token(user)
    reset_password_url = url_for('reset_password', token=token, user_id=user.id, _external=True)
    email_body = render_template_string(reset_password_email_html_content, reset_password_url=reset_password_url)
    msg = Message(subject='Password Reset Request',
                  sender='noreply@yourapp.com',
                  recipients=[user.email])
    msg.body = email_body
    msg.html = email_body  # In case you're sending HTML content
    mail.send(msg)

@app.route('/password-reset', methods=['GET', 'POST'])
def password_reset():
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if user:
            send_reset_password_email(user)
            flash('Instruction to reset your password has been sent to your email.', 'success')
            return redirect(url_for("password_reset"))
        else:
            flash("Email does not exist.", "danger")
    return render_template('password_reset_request.html', form=form)


@app.route('/reset_password/<token>/<int:user_id>', methods=['GET', 'POST'])
def reset_password(token, user_id):
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))
    user = User.validate_reset_password_token(token, user_id)
    if not user:
        return render_template('reset_password_error.html', title= "Reset Password error")

    form = ResetPasswordForm()
    if form.validate_on_submit():
        form.password.data = generate_password_hash(form.password.data, method='scrypt', salt_length=8)
        user.password = form.password.data
        db.session.commit()

        return render_template('reset_password_success.html', title="Reset Password success")
    return render_template('password-reset.html', title="Reset Password", form=form)

if __name__ == "__main__":
    app.run(debug=False)
from flask import Flask, render_template, url_for, flash, redirect, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
import os
import re
import uuid
from datetime import datetime
from PIL import Image, UnidentifiedImageError

app = Flask(__name__)
# KEAMANAN KETAT
app.config['SECRET_KEY'] = os.environ.get('OWSGRAM_SECRET_KEY') or os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///owsgram.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Maksimal file 5MB
app.config['ALLOWED_IMAGE_TYPES'] = {'image/jpeg', 'image/png', 'image/webp', 'image/gif'}

# Buat folder otomatis jika belum ada
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- DATABASE MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    liked_posts = db.relationship('Like', backref='user', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True, cascade='all, delete-orphan')

    def can_view(self, viewer):
        return not self.is_private or self.id == viewer.id or self.followers.filter_by(id=viewer.id).first() is not None

    followers = db.relationship('User', secondary='follows',
                                primaryjoin='User.id == follows.c.following_id',
                                secondaryjoin='User.id == follows.c.follower_id',
                                backref=db.backref('following', lazy='dynamic'), lazy='dynamic')


follows = db.Table('follows', db.Column('follower_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                   db.Column('following_id', db.Integer, db.ForeignKey('user.id'), primary_key=True))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_file = db.Column(db.String(255), nullable=False)
    caption = db.Column(db.Text, nullable=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_safe = db.Column(db.Boolean, default=True)
    likes = db.relationship('Like', backref='post', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_like'),)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(500), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    # Diperbarui menggunakan db.session.get() agar bersih dari warning versi terbaru
    return db.session.get(User, int(user_id))

# --- AI MODERATION SYSTEM ---
def ai_image_moderator(file, filename, caption=''):
    """
    Sistem AI Pengawas Owsgram:
    Jika nama file gambar mengandung kata 'buruk', 'nsfw', 'ilegal', atau 'kekerasan',
    AI akan langsung memblokir dan menghapus post tersebut.
    """
    if file.mimetype not in app.config['ALLOWED_IMAGE_TYPES']:
        return False
    try:
        image = Image.open(file)
        image.verify()
    except (UnidentifiedImageError, OSError):
        return False
    banned_words = r'nsfw|porn|porno|kekerasan|ilegal|kasar|senjata|narkoba'
    return not re.search(banned_words, f'{filename} {caption}', re.IGNORECASE)

# --- ROUTES ---
@app.route("/")
@login_required
def index():
    # FYP: Hanya tampilkan post aman & akun tidak privat (atau milik sendiri)
    posts = Post.query.join(User).filter(Post.is_safe.is_(True)).order_by(Post.date_posted.desc()).all()
    posts = [post for post in posts if post.author.can_view(current_user)]
    people = User.query.filter(User.id != current_user.id).order_by(User.username).limit(6).all()
    return render_template('index.html', posts=posts, people=people)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password')
        if not re.fullmatch(r'[a-z0-9_]{3,20}', username) or not password or len(password) < 8:
            flash('Username harus 3-20 karakter (huruf, angka, _) dan password minimal 8 karakter.', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username atau Email sudah terpakai. Gunakan yang lain.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Akun Owsgram berhasil dibuat! Silakan Login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            flash('Login Gagal. Periksa email dan password.', 'danger')
    return render_template('login.html')

@app.route("/logout", methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/upload", methods=['POST'])
@login_required
def upload():
    if 'image' not in request.files:
        flash('Pilih gambar terlebih dahulu.', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['image']
    caption = request.form.get('caption')

    if file and file.filename != '':
        filename = secure_filename(file.filename)
        
        # 🚨 PENGAWASAN AI DIMULAI 🚨
        if not ai_image_moderator(file, filename, caption):
            flash('Post diblokir: pemeriksaan keamanan Owsgram menolak file atau teks ini.', 'danger')
            return redirect(url_for('index'))
        
        unique_filename = f'{uuid.uuid4().hex}_{filename}'
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        new_post = Post(image_file=unique_filename, caption=caption, author=current_user)
        db.session.add(new_post)
        db.session.commit()
        flash('Post berhasil dibagikan!', 'success')
        
    return redirect(url_for('index'))


@app.post('/post/<int:post_id>/like')
@login_required
def like_post(post_id):
    post = db.get_or_404(Post, post_id)
    if not post.author.can_view(current_user):
        abort(403)
    existing = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(Like(user_id=current_user.id, post_id=post.id))
    db.session.commit()
    return redirect(request.referrer or url_for('index'))


@app.post('/post/<int:post_id>/comment')
@login_required
def comment_post(post_id):
    post = db.get_or_404(Post, post_id)
    body = request.form.get('body', '').strip()
    if not post.author.can_view(current_user):
        abort(403)
    if body and len(body) <= 500:
        db.session.add(Comment(body=body, user_id=current_user.id, post_id=post.id))
        db.session.commit()
    return redirect(request.referrer or url_for('index'))


@app.post('/user/<int:user_id>/follow')
@login_required
def follow_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.id != current_user.id:
        if current_user.following.filter_by(id=user.id).first():
            current_user.following.remove(user)
        else:
            current_user.following.append(user)
        db.session.commit()
    return redirect(request.referrer or url_for('index'))

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        is_private = request.form.get('is_private')
        current_user.is_private = True if is_private else False
        db.session.commit()
        flash('Pengaturan Privasi diperbarui.', 'success')
        return redirect(url_for('profile'))
    
    user_posts = Post.query.filter_by(author=current_user).order_by(Post.date_posted.desc()).all()
    return render_template('profile.html', posts=user_posts)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Buat database jika belum ada
    app.run(debug=os.environ.get('OWSGRAM_DEBUG', '').lower() == 'true')
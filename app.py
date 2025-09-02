from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_session import Session
from dotenv import load_dotenv
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError, OperationalError
import os
from datetime import datetime
import uuid
from collections import Counter
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") or 'default-secret-key'  # Fallback for missing SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL") or 'sqlite:///adeles_crafts.db'  # Fallback to SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'Uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['SESSION_TYPE'] = 'filesystem'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
Session(app)

# Ensure upload and session folders exist
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('flask_session', exist_ok=True)
except OSError as e:
    logger.error(f"Failed to create directories: {str(e)}")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Association table for Orders-Item relationship
order_items = db.Table('order_items',
    db.Column('order_id', db.Integer, db.ForeignKey('orders.id'), primary_key=True),
    db.Column('item_id', db.Integer, db.ForeignKey('item.id'), primary_key=True)
)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    full_name = db.Column(db.String(150))
    is_admin = db.Column(db.Boolean, default=False)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    image_path = db.Column(db.String(200))
    category = db.Column(db.String(100))

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    order_number = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('Item', secondary=order_items, backref='orders')
    user = db.relationship('User', backref='orders')

class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    content = db.Column(db.Text)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='blogs')

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {str(e)}")
        return None

# Admin required decorator
def admin_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            logger.warning(f"Unauthorized access attempt to admin route by user {current_user.id}")
            flash('You need admin privileges to access this page.')
            abort(403)
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    logger.error(f"404 error: {str(e)}")
    return render_template('error.html', error="Page not found."), 404

@app.errorhandler(403)
def forbidden(e):
    logger.error(f"403 error: {str(e)}")
    return render_template('error.html', error="Access forbidden."), 403

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 error: {str(e)}")
    return render_template('error.html', error="An unexpected error occurred. Please try again later."), 500

# Routes
@app.route('/')
def home():
    try:
        items = Item.query.all()
        blogs = Blog.query.order_by(Blog.date.desc()).limit(3).all()
        return render_template('home.html', items=items, blogs=blogs, description="Discover unique handmade crafts by Adele...")
    except OperationalError as e:
        logger.error(f"Database error in home route: {str(e)}")
        flash('Unable to load homepage due to a database issue. Please try again later.')
        return render_template('error.html', error="Database error."), 500

@app.route('/products')
def products():
    try:
        items = Item.query.all()
        return render_template('products.html', items=items)
    except OperationalError as e:
        logger.error(f"Database error in products route: {str(e)}")
        flash('Unable to load products due to a database issue.')
        return render_template('error.html', error="Database error."), 500

@app.route('/product/<int:id>')
def product_detail(id):
    try:
        item = Item.query.get_or_404(id)
        return render_template('product_detail.html', item=item)
    except Exception as e:
        logger.error(f"Error in product_detail for id {id}: {str(e)}")
        flash('Unable to load product details.')
        return render_template('error.html', error="Product not found."), 404

@app.route('/add-to-cart/<int:item_id>', methods=['POST'])
def add_to_cart(item_id):
    try:
        item = Item.query.get_or_404(item_id)
        if item.price <= 0:
            flash('This item is for display only and cannot be added to the cart.')
            return redirect(url_for('product_detail', id=item_id))
        
        if 'cart' not in session or not isinstance(session['cart'], list):
            session['cart'] = []
        
        for cart_item in session['cart']:
            if cart_item['id'] == item_id:
                cart_item['quantity'] += 1
                session.modified = True
                flash(f'{item.name} quantity updated in cart.')
                return redirect(url_for('cart'))
        
        session['cart'].append({
            'id': item_id,
            'name': item.name,
            'price': item.price,
            'quantity': 1
        })
        session.modified = True
        flash(f'{item.name} added to cart.')
        return redirect(url_for('cart'))
    except Exception as e:
        logger.error(f"Error adding item {item_id} to cart: {str(e)}")
        flash('An error occurred while adding the item to the cart.')
        return redirect(url_for('products'))

@app.route('/cart')
def cart():
    try:
        cart_items = []
        total = 0
        if 'cart' in session and isinstance(session['cart'], list):
            for cart_item in session['cart']:
                item = Item.query.get(cart_item['id'])
                if item and item.price > 0:
                    cart_items.append({
                        'id': item.id,
                        'name': item.name,
                        'price': item.price,
                        'quantity': cart_item['quantity'],
                        'image_path': item.image_path
                    })
                    total += item.price * cart_item['quantity']
        return render_template('cart.html', cart_items=cart_items, total=total)
    except Exception as e:
        logger.error(f"Error in cart route: {str(e)}")
        flash('Unable to load cart due to an error.')
        return render_template('error.html', error="Cart error."), 500

@app.route('/remove-from-cart/<int:item_id>', methods=['POST'])
def remove_from_cart(item_id):
    try:
        if 'cart' in session and isinstance(session['cart'], list):
            session['cart'] = [item for item in session['cart'] if item['id'] != item_id]
            session.modified = True
            flash('Item removed from cart.')
        return redirect(url_for('cart'))
    except Exception as e:
        logger.error(f"Error removing item {item_id} from cart: {str(e)}")
        flash('An error occurred while removing the item from the cart.')
        return redirect(url_for('cart'))

@app.route('/submit-order', methods=['POST'])
@login_required
def submit_order():
    try:
        if 'cart' not in session or not session['cart'] or not isinstance(session['cart'], list):
            flash('Your cart is empty or invalid.')
            return redirect(url_for('cart'))
        
        order = Order(user_id=current_user.id, status='pending')
        for cart_item in session['cart']:
            item = Item.query.get(cart_item['id'])
            if item and item.price > 0:
                if not isinstance(cart_item['quantity'], int) or cart_item['quantity'] <= 0:
                    logger.warning(f"Invalid quantity for item {item.id}: {cart_item['quantity']}")
                    flash('Invalid item quantity in cart.')
                    return redirect(url_for('cart'))
                for _ in range(cart_item['quantity']):
                    order.items.append(item)
        db.session.add(order)
        db.session.commit()
        session.pop('cart', None)
        flash(f'Order #{order.order_number} submitted! Please contact Adele at adelescrafts@yahoo.com for payment and shipping details.')
        return redirect(url_for('orders'))
    except IntegrityError as e:
        db.session.rollback()
        logger.error(f"Database integrity error in submit_order: {str(e)}")
        flash('An error occurred while submitting your order. Please try again.')
        return redirect(url_for('cart'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in submit_order: {str(e)}")
        flash('An unexpected error occurred while submitting your order.')
        return redirect(url_for('cart'))

@app.route('/orders')
@login_required
def orders():
    try:
        if current_user.is_admin:
            orders = Order.query.order_by(Order.created_at.desc()).all()
        else:
            orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
        return render_template('orders.html', orders=orders)
    except OperationalError as e:
        logger.error(f"Database error in orders route: {str(e)}")
        flash('Unable to load orders due to a database issue.')
        return render_template('error.html', error="Database error."), 500

@app.route('/order/<int:id>')
@login_required
def order_detail(id):
    try:
        order = Order.query.get_or_404(id)
        if not (current_user.is_admin or current_user.id == order.user_id):
            logger.warning(f"Unauthorized access to order {id} by user {current_user.id}")
            flash('You do not have permission to view this order.')
            abort(403)
        item_counts = Counter(item.id for item in order.items)
        order_items = []
        total = 0
        for item_id, quantity in item_counts.items():
            item = Item.query.get(item_id)
            if item:
                order_items.append({
                    'id': item.id,
                    'name': item.name,
                    'price': item.price,
                    'quantity': quantity,
                    'image_path': item.image_path,
                    'subtotal': item.price * quantity
                })
                total += item.price * quantity
        return render_template('order_detail.html', order=order, order_items=order_items, total=total)
    except Exception as e:
        logger.error(f"Error in order_detail for id {id}: {str(e)}")
        flash('Unable to load order details.')
        return render_template('error.html', error="Order error."), 500

@app.route('/order/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_order(id):
    try:
        order = Order.query.get_or_404(id)
        if not (current_user.is_admin or current_user.id == order.user_id):
            logger.warning(f"Unauthorized edit attempt for order {id} by user {current_user.id}")
            flash('You do not have permission to edit this order.')
            abort(403)
        if request.method == 'POST':
            status = request.form.get('status')
            if status not in ['pending', 'completed', 'canceled']:
                logger.warning(f"Invalid status {status} for order {id}")
                flash('Invalid status.')
                return render_template('edit_order.html', order=order)
            order.status = status
            db.session.commit()
            flash(f'Order #{order.order_number} updated successfully.')
            return redirect(url_for('order_detail', id=order.id))
        return render_template('edit_order.html', order=order)
    except Exception as e:
        logger.error(f"Error in edit_order for id {id}: {str(e)}")
        flash('An error occurred while editing the order.')
        return render_template('error.html', error="Order edit error."), 500

@app.route('/order/delete/<int:id>')
@login_required
def delete_order(id):
    try:
        order = Order.query.get_or_404(id)
        if not (current_user.is_admin or current_user.id == order.user_id):
            logger.warning(f"Unauthorized delete attempt for order {id} by user {current_user.id}")
            flash('You do not have permission to delete this order.')
            abort(403)
        db.session.delete(order)
        db.session.commit()
        flash(f'Order #{order.order_number} deleted successfully.')
        return redirect(url_for('orders'))
    except Exception as e:
        logger.error(f"Error deleting order {id}: {str(e)}")
        flash('An error occurred while deleting the order.')
        return redirect(url_for('orders'))

@app.route('/admin/users')
@admin_required
def list_users():
    try:
        users = User.query.all()
        return render_template('users.html', users=users)
    except OperationalError as e:
        logger.error(f"Database error in list_users: {str(e)}")
        flash('Unable to load user list due to a database issue.')
        return render_template('error.html', error="Database error."), 500

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/blog')
def blog():
    try:
        blogs = Blog.query.order_by(Blog.date.desc()).all()
        return render_template('blog.html', blogs=blogs)
    except OperationalError as e:
        logger.error(f"Database error in blog route: {str(e)}")
        flash('Unable to load blog posts due to a database issue.')
        return render_template('error.html', error="Database error."), 500

@app.route('/blog/<int:id>')
def blog_detail(id):
    try:
        blog = Blog.query.get_or_404(id)
        return render_template('blog_detail.html', blog=blog)
    except Exception as e:
        logger.error(f"Error in blog_detail for id {id}: {str(e)}")
        flash('Unable to load blog post.')
        return render_template('error.html', error="Blog post not found."), 404

@app.route('/search')
def search():
    try:
        query = request.args.get('q')
        if query:
            items = Item.query.filter((Item.name.like(f'%{query}%')) | (Item.description.like(f'%{query}%'))).all()
        else:
            items = []
        return render_template('search.html', items=items, query=query)
    except Exception as e:
        logger.error(f"Error in search route: {str(e)}")
        flash('Unable to perform search.')
        return render_template('error.html', error="Search error."), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            email = request.form['email']
            full_name = request.form['full_name']
            password = request.form['password']
            if not all([username, email, full_name, password]):
                flash('All fields are required.')
                return render_template('register.html')
            if len(password) < 6:
                flash('Password must be at least 6 characters long.')
                return render_template('register.html')
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, email=email, full_name=full_name, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except IntegrityError as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}")
            flash('Username or email already exists.')
            return render_template('register.html')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error in register: {str(e)}")
            flash('An error occurred during registration. Please try again.')
            return render_template('register.html')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            if not all([username, password]):
                flash('Username and password are required.')
                return render_template('login.html')
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                login_user(user)
                logger.info(f"User {username} logged in successfully")
                return redirect(url_for('home'))
            flash('Login failed. Check username and password.')
            logger.warning(f"Failed login attempt for username {username}")
        except Exception as e:
            logger.error(f"Error in login: {str(e)}")
            flash('An error occurred during login. Please try again.')
        return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    try:
        logout_user()
        session.pop('cart', None)
        logger.info(f"User {current_user.id} logged out")
        return redirect(url_for('home'))
    except Exception as e:
        logger.error(f"Error in logout: {str(e)}")
        flash('An error occurred during logout.')
        return redirect(url_for('home'))

@app.route('/admin/upload', methods=['GET', 'POST'])
@admin_required
def upload_item():
    if request.method == 'POST':
        try:
            name = request.form['name']
            description = request.form['description']
            price = request.form['price']
            category = request.form['category']
            if not all([name, description, price, category]):
                flash('All fields are required.')
                return render_template('upload.html')
            try:
                price = float(price)
                if price < 0:
                    flash('Price cannot be negative.')
                    return render_template('upload.html')
            except ValueError:
                flash('Price must be a valid number.')
                return render_template('upload.html')
            if 'image' not in request.files:
                flash('No image file provided.')
                return render_template('upload.html')
            file = request.files['image']
            if file.filename == '':
                flash('No image selected.')
                return render_template('upload.html')
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                new_item = Item(name=name, description=description, price=price, image_path=filename, category=category)
                db.session.add(new_item)
                db.session.commit()
                flash('Item uploaded successfully!')
                return redirect(url_for('products'))
            else:
                flash('Invalid file type. Allowed types: png, jpg, jpeg, gif.')
                return render_template('upload.html')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error in upload_item: {str(e)}")
            flash('An error occurred while uploading the item.')
            return render_template('upload.html')
    return render_template('upload.html')

@app.route('/admin/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_item(id):
    try:
        item = Item.query.get_or_404(id)
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            price = request.form['price']
            category = request.form['category']
            if not all([name, description, price, category]):
                flash('All fields are required.')
                return render_template('edit.html', item=item)
            try:
                price = float(price)
                if price < 0:
                    flash('Price cannot be negative.')
                    return render_template('edit.html', item=item)
            except ValueError:
                flash('Price must be a valid number.')
                return render_template('edit.html', item=item)
            item.name = name
            item.description = description
            item.price = price
            item.category = category
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    item.image_path = filename
            db.session.commit()
            flash('Item updated successfully!')
            return redirect(url_for('products'))
        return render_template('edit.html', item=item)
    except Exception as e:
        logger.error(f"Error in edit_item for id {id}: {str(e)}")
        flash('An error occurred while editing the item.')
        return render_template('error.html', error="Item edit error."), 500

@app.route('/admin/delete/<int:id>')
@admin_required
def delete_item(id):
    try:
        item = Item.query.get_or_404(id)
        db.session.delete(item)
        db.session.commit()
        flash('Item deleted successfully!')
        return redirect(url_for('products'))
    except Exception as e:
        logger.error(f"Error deleting item {id}: {str(e)}")
        flash('An error occurred while deleting the item.')
        return redirect(url_for('products'))

@app.route('/admin/blog/new', methods=['GET', 'POST'])
@login_required
def new_blog():
    if request.method == 'POST':
        try:
            title = request.form['title']
            content = request.form['content']
            if not all([title, content]):
                flash('Title and content are required.')
                return render_template('new_blog.html')
            new_blog = Blog(title=title, content=content, user_id=current_user.id)
            db.session.add(new_blog)
            db.session.commit()
            flash('Blog post created!')
            return redirect(url_for('blog'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error in new_blog: {str(e)}")
            flash('An error occurred while creating the blog post.')
            return render_template('new_blog.html')
    return render_template('new_blog.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logger.error(f"Error serving file {filename}: {str(e)}")
        flash('Unable to load the requested image.')
        return redirect(url_for('home'))

if __name__ == '__main__':
    try:
        with app.app_context():
            db.create_all()
        logger.info("Application started")
        app.run(debug=True)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
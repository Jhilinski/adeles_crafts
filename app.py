from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from flask_session import Session

app = Flask(__name__)
app.config['SECRET_KEY'] = '7ba4404e70259612726d4995b2b0a812'  # Change to a secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:mynewtoy@localhost/adeles_crafts'  # Update with your MySQL credentials
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['SESSION_TYPE'] = 'filesystem'  # Use filesystem for session storage

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
Session(app)  # Initialize session

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Association table for Order-Item relationship
order_items = db.Table('order_items',
    db.Column('order_id', db.Integer, db.ForeignKey('order.id'), primary_key=True),
    db.Column('item_id', db.Integer, db.ForeignKey('item.id'), primary_key=True)
)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    image_path = db.Column(db.String(200))
    category = db.Column(db.String(100))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('Item', secondary=order_items, backref='orders')

class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    content = db.Column(db.Text)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    items = Item.query.all()
    blogs = Blog.query.order_by(Blog.date.desc()).limit(3).all()
    return render_template('home.html', items=items, blogs=blogs, description="Discover unique handmade crafts by Adele, including beaded jewelry like bracelets, earrings, rings, necklaces, ornaments, and keychains. Explore plastic canvas items such as religious decor, tissue box holders, and bookmarks. Also available: diamond painted keychains, fridge magnets, and more. Handcrafted with love for every occasion – perfect for gifts or personal treats!")

@app.route('/products')
def products():
    items = Item.query.all()
    return render_template('products.html', items=items)

@app.route('/product/<int:id>')
def product_detail(id):
    item = Item.query.get_or_404(id)
    return render_template('product_detail.html', item=item)

@app.route('/add-to-cart/<int:item_id>', methods=['POST'])
def add_to_cart(item_id):
    item = Item.query.get_or_404(item_id)
    if item.price <= 0:
        flash('This item is for display only and cannot be added to the cart.')
        return redirect(url_for('product_detail', id=item_id))
    
    if 'cart' not in session:
        session['cart'] = []
    
    # Check if item is already in cart
    for cart_item in session['cart']:
        if cart_item['id'] == item_id:
            cart_item['quantity'] += 1
            session.modified = True
            flash(f'{item.name} quantity updated in cart.')
            return redirect(url_for('cart'))
    
    # Add new item to cart
    session['cart'].append({
        'id': item_id,
        'name': item.name,
        'price': item.price,
        'quantity': 1
    })
    session.modified = True
    flash(f'{item.name} added to cart.')
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    cart_items = []
    total = 0
    if 'cart' in session:
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

@app.route('/remove-from-cart/<int:item_id>', methods=['POST'])
def remove_from_cart(item_id):
    if 'cart' in session:
        session['cart'] = [item for item in session['cart'] if item['id'] != item_id]
        session.modified = True
        flash('Item removed from cart.')
    return redirect(url_for('cart'))

@app.route('/submit-order', methods=['POST'])
@login_required
def submit_order():
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty.')
        return redirect(url_for('cart'))
    
    try:
        order = Order(user_id=current_user.id, status='pending')
        for cart_item in session['cart']:
            item = Item.query.get(cart_item['id'])
            if item and item.price > 0:
                order.items.append(item)
        db.session.add(order)
        db.session.commit()
        session.pop('cart', None)  # Clear cart
        flash('Order submitted! Please contact Adele at adelescrafts@yahoo.com for payment and shipping details.')
        return redirect(url_for('home'))
    except Exception as e:
        flash(f'Error submitting order: {str(e)}')
        return redirect(url_for('cart'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/blog')
def blog():
    blogs = Blog.query.order_by(Blog.date.desc()).all()
    return render_template('blog.html', blogs=blogs)

@app.route('/blog/<int:id>')
def blog_detail(id):
    blog = Blog.query.get_or_404(id)
    return render_template('blog_detail.html', blog=blog)

@app.route('/search')
def search():
    query = request.args.get('q')
    if query:
        items = Item.query.filter((Item.name.like(f'%{query}%')) | (Item.description.like(f'%{query}%'))).all()
    else:
        items = []
    return render_template('search.html', items=items, query=query)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        flash('Login failed. Check username and password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('cart', None)  # Clear cart on logout
    return redirect(url_for('home'))

@app.route('/admin/upload', methods=['GET', 'POST'])
@login_required
def upload_item():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category']
        if 'image' not in request.files:
            flash('No image file')
            return redirect(request.url)
        file = request.files['image']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_item = Item(name=name, description=description, price=price, image_path=filename, category=category)
            db.session.add(new_item)
            db.session.commit()
            flash('Item uploaded successfully!')
            return redirect(url_for('products'))
    return render_template('upload.html')

@app.route('/admin/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_item(id):
    item = Item.query.get_or_404(id)
    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.price = float(request.form['price'])
        item.category = request.form['category']
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

@app.route('/admin/delete/<int:id>')
@login_required
def delete_item(id):
    item = Item.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Item deleted successfully!')
    return redirect(url_for('products'))

@app.route('/admin/blog/new', methods=['GET', 'POST'])
@login_required
def new_blog():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        new_blog = Blog(title=title, content=content, user_id=current_user.id)
        db.session.add(new_blog)
        db.session.commit()
        flash('Blog post created!')
        return redirect(url_for('blog'))
    return render_template('new_blog.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
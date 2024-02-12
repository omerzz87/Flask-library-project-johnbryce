
import datetime 
import json,time,os
from functools import wraps
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import jwt
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, decode_token, get_jwt_identity, jwt_required
from sqlalchemy import and_
from sqlalchemy.orm import joinedload
app = Flask(__name__)
app.secret_key = 'secret_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)


app_directory = os.path.dirname(__file__)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    year_published = db.Column(db.Integer, nullable=False)
    type = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='Available')

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.Integer, default=0)

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cust_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    loan_date = db.Column(db.DateTime, nullable=False)
    return_date = db.Column(db.DateTime, nullable=False)

    customer = db.relationship('Customer', backref=db.backref('loans', lazy=True))
    book = db.relationship('Book', backref=db.backref('loans', lazy=True))


# Generate a JWT
def generate_token(user_id):
    expiration = int(time.time()) + 3600  # Set the expiration time to 1 hour from the current time
    payload = {'user_id': user_id, 'exp': expiration}
    token = jwt.encode(payload, 'blablablabl', algorithm='HS256')
    return token


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401


        return f(current_user_id, *args, **kwargs)


    return decorated


def model_to_dict(model):
    serialized_model = {}
    for key in model.__mapper__.c.keys():
        serialized_model[key] = getattr(model, key)
    return serialized_model








@app.route('/', methods=['POST'])
def login():
    data =request.get_json()
    print( data)
    username = data["username"]
    password = data["password"]

    # Check if the user exists
    user = Customer.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Generate an access token with an expiration time
        expires = datetime.timedelta(hours=1)
        access_token = create_access_token(identity={'id':user.id,'role': user.role,'username': username}, expires_delta=expires)
        print(user.id)


        return jsonify({'access_token': access_token, 'username':username,'name':user.name, 'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid username or password!'}), 401
    

    




@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user = Customer.query.filter_by(username=data['username']).first()
    if user:
        return jsonify({'message': 'User already exists'}), 409
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = Customer(username=data['username'], password=hashed_password, role=data['role'], name=data['name'], city=data['city'], age=data['age'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully'}), 200


@app.route('/add_loan', methods=['POST'])
@jwt_required()
def add_loan():
    request_data = request.get_json()
    book_id = request_data['book_id']
    loan_date = datetime.datetime.now()  
    current_user_info = get_jwt_identity()
    current_user_id = current_user_info['id']
    print("==============================",current_user_id)
    current_user = Customer.query.get(current_user_id)
    user=Customer.query.filter_by(id = current_user_id).first()
    book = Book.query.get(book_id)
    if user.role == 0:
         # Check if the user already has a book on loan
        existing_loan = Loan.query.filter(and_(Loan.cust_id == current_user_id, Loan.return_date > loan_date)).first()
        userloan = Loan.query.filter_by(cust_id=current_user_id, book_id=book_id).first()
        if userloan:
            return jsonify({'message': 'You are already leasing this book'}), 403
        
        if existing_loan:
            return jsonify({'message': 'You can only lease one book at a time or return your currently leased!'}), 403
        
        if book.status != 'Available':
            return jsonify({'message': 'This book is already leased by someone else'}), 403

        

        if not book:
            return jsonify({'message': 'Book not found'}), 404

        # Calculate return_date based on book.type
        if book.type == 1:
            return_date = loan_date + datetime.timedelta(days=10)
        elif book.type == 2:
            return_date = loan_date + datetime.timedelta(days=5)
        elif book.type == 3:
            return_date = loan_date + datetime.timedelta(days=2)
        

        new_loan = Loan(cust_id=current_user.id, book_id=book_id, loan_date=loan_date, return_date=return_date)
        db.session.add(new_loan)
        db.session.commit()

        book.status = 'Leased by ' + current_user.name
        db.session.commit()

        return jsonify({'message': 'Loan added successfully'}), 201
    else:
        return jsonify({'message': 'Only customers can lease books!'}), 403
    
@app.route('/delete_book/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
    current_user = get_jwt_identity()
    username = current_user['username']
    user = Customer.query.filter_by(username=username).first()
    book = Book.query.get(book_id)
    if user and user.role == 1:
        if book is None:
            return jsonify({'message': 'Book not found'}), 404
        # Check if the book is currently on loan
        loan_date = datetime.datetime.now()
        existing_loan = Loan.query.filter(and_(Loan.book_id == book_id, Loan.return_date > loan_date)).first()
        if existing_loan:
            return jsonify({'message': 'Cannot remove a book that is currently on loan!'}), 403
        db.session.delete(book)
        db.session.commit()
        return jsonify({'message': 'Book deleted successfully'}), 200
    else:
        return jsonify({'message': 'Only admins can delete books!'}), 403

@app.route('/getbooks/', methods=['GET'])
def get_books():
    books = Book.query.all()
    books_data = [model_to_dict(book) for book in books]
    return jsonify(books_data), 200

@app.route('/getcustomers/', methods=['GET'])
def get_customers():
    customers = Customer.query.options(joinedload(Customer.loans).joinedload(Loan.book)).all()
    customers_data = []
    for customer in customers:
        customer_dict = {
            'id': customer.id,
            'name': customer.name,
            'city': customer.city,
            'age': customer.age,
            'username': customer.username,
            'password': customer.password,
            'role': customer.role,
            'loans': []
        }
        for loan in customer.loans:
            loan_dict = {
                'id': loan.id,
                'loan_date': loan.loan_date,
                'return_date': loan.return_date,
                'book': {
                    'id': loan.book.id,
                    'title': loan.book.title,
                    'author': loan.book.author,
                    'year_published': loan.book.year_published,
                    'type': loan.book.type,
                    'status': loan.book.status
                }
            }
            customer_dict['loans'].append(loan_dict)
        customers_data.append(customer_dict)
    return jsonify(customers_data), 200

@app.route('/getbooks/<int:book_id>', methods=['GET'])
def get_specificbook(book_id):
    book = Book.query.get(book_id)
    return jsonify(model_to_dict(book)), 200




@app.route('/add_book', methods=['POST'])
@jwt_required()
def add_book():
    request_data = request.get_json()
    current_user = get_jwt_identity()
    username = current_user['username']
    user = Customer.query.filter_by(username=username).first()
    if user and user.role == 1:  
        new_book = Book(title=request_data['title'], author=request_data['author'], year_published=request_data['year_published'] , type=request_data['type'])
        db.session.add(new_book)
        db.session.commit()
        return jsonify({'message': 'Book added successfully'}), 200
    else:
        return jsonify({'message': 'Only admins can add books'}), 403

@app.route('/update_book/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    data = request.get_json()
    book = Book.query.get(book_id)
    current_user = get_jwt_identity()
    username = current_user['username']
    user = Customer.query.filter_by(username=username).first()
    if user and user.role == 1:
        if book is None:
            return jsonify({'message': 'Book not found'}), 404
        loan_date = datetime.datetime.now()
        existing_loan = Loan.query.filter(and_(Loan.book_id == book_id, Loan.return_date > loan_date)).first()
        if existing_loan:
            return jsonify({'message': 'Cannot update a book that is currently on loan!'}), 403
        book.title = data.get('title', book.title)
        book.author = data.get('author', book.author)
        book.year_published = data.get('year_published', book.year_published)
        book.type = data.get('type', book.type)
        db.session.commit()
        return jsonify({'message': 'Book updated successfully'}), 200
    else: 
        return jsonify({'message': 'Only admins can update books'}), 403
    
@app.route('/return_book/<int:loan_id>', methods=['DELETE'])
@jwt_required()
def return_book(loan_id):
    current_user = get_jwt_identity()
    username = current_user['username']
    user = Customer.query.filter_by(username=username).first()
    loan = Loan.query.get(loan_id)
    if user and user.role == 0:
        if loan is None:
            return jsonify({'message': 'Loan not found'}), 404
        if loan.cust_id != user.id:  # Check if the loan is associated with the user
            return jsonify({'message': 'You are not leasing this book'}), 403
        loan_date = datetime.datetime.now()
        if loan.return_date < loan_date:
            return jsonify({'message': 'Book is overdue!'}), 403
        loan.book.status = 'Available'
        db.session.delete(loan)
        db.session.commit()
        return jsonify({'message': 'Book returned successfully'}), 200
    else:
        return jsonify({'message': 'Only customers can return books'}), 403


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
    get_books()
from flask import Flask, make_response, request, jsonify, render_template, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'your_secure_secret_key_here'  
app.config['JWT_TOKEN_LOCATION'] = ['cookies']  # Use cookies to store JWT
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'  # Cookie name for JWT access token
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable CSRF for development
jwt = JWTManager(app)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '9510756038@Dp' 
app.config['MYSQL_DB'] = 'satsang'

def get_db_connection():
    return mysql.connector.connect(host=app.config['MYSQL_HOST'],
                                   user=app.config['MYSQL_USER'],
                                   password=app.config['MYSQL_PASSWORD'],
                                   database=app.config['MYSQL_DB'])


# Route to login page (GET) and login action (POST)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user_regestration WHERE username=%s", (username,))
        user = cursor.fetchone()    
        cursor.close()
        conn.close()

        if user and user['password'] == password:  # temp disabled hashing verification
            access_token = create_access_token(identity={'username': user['username']})
            response = make_response(redirect(url_for('admin')))
            
            # Setting the JWT token in the cookie with secure=False for HTTP
            response.set_cookie('access_token_cookie', access_token, httponly=True, secure=False)
            return response
        else:
            return jsonify({"error": "Invalid credentials"}), 401

    return render_template('login.html')


# Admin panel, protected route (JWT required)
@app.route('/admin', methods=['GET'])
@jwt_required()  # Ensure JWT is required
def admin():
    current_user = get_jwt_identity()  # Retrieve the current user from the JWT
    
    # Admin page with Add User and Add Donation button
    return render_template('admin.html', current_user=current_user)


# Route to handle adding a user (GET to display form, POST to handle form submission)
@app.route('/add_user', methods=['GET', 'POST'])
@jwt_required()  # Ensure JWT is required
def add_user():
    current_user = get_jwt_identity()  # Retrieve the current user from the JWT

    if request.method == 'POST':
        # Retrieve form data
        user_id = request.form['user_id']
        username = request.form['username']
        password = generate_password_hash(request.form['password'])  # Hash the password
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        phone_number = request.form['phone_number']
        date_of_birth = request.form['date_of_birth']
        registration_date = request.form['registration_date']
        status = request.form['status']

        # Add the new user to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert query for the new user
        query = """
        INSERT INTO user_regestration (user_id, username, password, email, first_name, last_name, phone_number, date_of_birth, registration_date, status) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (user_id, username, password, email, first_name, last_name, phone_number, date_of_birth, registration_date, status)
        cursor.execute(query, values)
        
        # Commit the transaction and close the connection
        conn.commit()
        cursor.close()
        conn.close()

        # Redirect back to admin panel after successful user addition
        return redirect(url_for('admin'))

    # Render the "Add User" form
    return render_template('add_user.html', current_user=current_user)


# Route to view all users
@app.route('/users', methods=['GET'])
@jwt_required()  # Ensure JWT is required
def users():
    current_user = get_jwt_identity()  # Retrieve the current user from the JWT
    
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Query to get all users
    cursor.execute("SELECT * FROM user_regestration")
    users = cursor.fetchall()  # Fetch all user details
    
    cursor.close()
    conn.close()

    # Render the user details in an HTML template
    return render_template('users.html', users=users, current_user=current_user)



# Route to handle adding a donation (GET to display form, POST to handle form submission)
@app.route('/add_donation', methods=['GET', 'POST'])
@jwt_required()  # Ensure JWT is required
def add_donation():
    current_user = get_jwt_identity()  # Retrieve the current user from the JWT

    if request.method == 'POST':
        # Retrieve form data
        name = request.form['name']
        swastyayani = request.form['swastyayani']
        istavrity = request.form['istavrity']
        acharyavrity = request.form['acharyavrity']
        dakshina = request.form['dakshina']
        sangathani = request.form['sangathani']
        anandabazar = request.form['anandabazar']
        pronami_bhog = request.form['pronami_bhog']
        sri_mandir = request.form['sri_mandir']
        ritwiki = request.form['ritwiki']
        utsav = request.form['utsav']
        centenary = request.form['centenary']
        miscellaneous = request.form['miscellaneous']

        # Add the donation details to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert query for the new donation
        query = """
        INSERT INTO donations (name, swastyayani, istavrity, acharyavrity, dakshina, sangathani, anandabazar, pronami_bhog, sri_mandir, ritwiki, utsav, centenary, miscellaneous) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (name, swastyayani, istavrity, acharyavrity, dakshina, sangathani, anandabazar, pronami_bhog, sri_mandir, ritwiki, utsav, centenary, miscellaneous)
        cursor.execute(query, values)

        # Commit the transaction and close the connection
        conn.commit()
        cursor.close()
        conn.close()

        # Redirect back to admin panel after successful donation addition
        return redirect(url_for('admin'))

    # Fetch available names from the database to display in the dropdown
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT username FROM user_regestration")
    names = cursor.fetchall()  # Fetch all user names
    cursor.close()
    conn.close()

    # Render the "Add Donation" form
    return render_template('add_donations.html', current_user=current_user, names=names)


# Route to view all donations
@app.route('/add_donation', methods=['GET'])
@jwt_required()
def donation():
    current_user = get_jwt_identity()

    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch names from the correct column in user_regestration table
    cursor.execute("SELECT username FROM user_regestration")  # Use the actual column name
    result = cursor.fetchall()

    cursor.close()
    conn.close()

    # Extract names from the result set
    names = [row[0] for row in result]

    # Pass names to the template
    return render_template('add_donations.html', names=names, current_user=current_user)



# Route to view all transactions
@app.route('/transaction', methods=['GET'])  # Corrected route name from 'transation' to 'transaction'
@jwt_required()  # Ensure JWT is required
def view_transactions():
    current_user = get_jwt_identity()  # Retrieve the current user from the JWT
    
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Query to get all donations
    cursor.execute("SELECT * FROM donations")
    donations = cursor.fetchall()  # Fetch all donation details
    
    cursor.close()
    conn.close()

    # Render the donation details in an HTML template
    return render_template('transation.html', donations=donations, current_user=current_user)






if __name__ == '__main__':
    app.run(debug=True)
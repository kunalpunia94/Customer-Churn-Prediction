from flask import Flask, render_template, request
import numpy as np
import pickle
import json
import os
import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
# import mysql.connector
# import os
from functools import wraps
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

from twilio.rest import Client
import random

def send_otp(phone_number):
    otp = str(random.randint(1000, 9999))
    message = f"Your OTP for Churn App signup is: {otp}"

    client = Client("YOUR_TWILIO_SID", "YOUR_TWILIO_AUTH_TOKEN")
    client.messages.create(
        body=message,
        from_="YOUR_TWILIO_PHONE_NUMBER",
        to=phone_number
    )
    return otp

# env file details
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Use environment variables in your application
# app.secret_key = os.getenv('FLASK_SECRET_KEY')
DB_HOST = os.getenv('DB_HOST')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')
TWILIO_SID = os.getenv('TWILIO_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')



app = Flask(__name__)
# app.secret_key = 'kunal1234'
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# ------------------------------
# Load model and predict churn
# ------------------------------
def churn_prediction(tenure, citytier, warehousetohome, gender, hourspendonapp, numberofdeviceregistered,
                     satisfactionscore, maritalstatus, numberofaddress, complain,
                     orderamounthikefromlastyear, couponused, ordercount, daysincelastorder, cashbackamount):

    model_path = os.path.join('models', 'churn_prediction_model.pkl')
    columns_path = os.path.join('models', 'columns.json')

    with open(model_path, 'rb') as f:
        model = pickle.load(f)

    with open(columns_path, "r") as f:
        data_columns = json.load(f)['data_columns']

    input_dict = {
        "tenure": tenure,
        "citytier": citytier,
        "warehousetohome": warehousetohome,
        "gender": gender,
        "hourspendonapp": hourspendonapp,
        "numberofdeviceregistered": numberofdeviceregistered,
        "satisfactionscore": satisfactionscore,
        "maritalstatus": maritalstatus,
        "numberofaddress": numberofaddress,
        "complain": complain,
        "orderamounthikefromlastyear": orderamounthikefromlastyear,
        "couponused": couponused,
        "ordercount": ordercount,
        "daysincelastorder": daysincelastorder,
        "cashbackamount": cashbackamount
    }

    # Preprocess categorical inputs
    for col in data_columns:
        if col in input_dict and isinstance(input_dict[col], str):
            input_dict[col] = input_dict[col].lower().replace(' ', '_')

    input_array = np.zeros(len(data_columns))
    for i, col in enumerate(data_columns):
        if col in input_dict:
            input_array[i] = input_dict[col]
        elif f"{col}_{input_dict.get(col, '')}" in data_columns:
            input_array[data_columns.index(f"{col}_{input_dict[col]}")] = 1

    output_probab = model.predict_proba([input_array])[0][1]
    return round(output_probab, 4)

# ------------------------------------------
# Insert prediction into MySQL database
# ------------------------------------------
def insert_into_db(data):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        query = """
            INSERT INTO predictions (
                tenure, citytier, warehousetohome, gender, hourspendonapp,
                numberofdeviceregistered, satisfactionscore, maritalstatus,
                numberofaddress, complain, orderamounthikefromlastyear,
                couponused, ordercount, daysincelastorder, cashbackamount,
                prediction_result, prediction_probability
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        # Convert all numpy types to native Python types
        values = tuple(
            float(v) if isinstance(v, (np.float32, np.float64)) else
            int(v) if isinstance(v, (np.int32, np.int64)) else
            str(v)
            for v in [
                data['tenure'], data['citytier'], data['warehousetohome'], data['gender'], data['hourspendonapp'],
                data['numberofdeviceregistered'], data['satisfactionscore'], data['maritalstatus'],
                data['numberofaddress'], data['complain'], data['orderamounthikefromlastyear'],
                data['couponused'], data['ordercount'], data['daysincelastorder'], data['cashbackamount'],
                data['prediction_result'], data['prediction_probability']
            ]
        )

        cursor.execute(query, values)
        conn.commit()
        cursor.close()
        conn.close()

    except mysql.connector.Error as err:
        print("❌ MySQL Error:", err)

# -----------------------------------
# Main route
# -----------------------------------
@app.route('/', methods=['GET', 'POST'])
@login_required
def index_page():
    if request.method == 'POST':
        try:
            form_data = [
                request.form['Tenure'],
                request.form['Citytier'],
                request.form['Warehousetohome'],
                request.form['Gender'],
                request.form['Hourspendonapp'],
                request.form['Numberofdeviceregistered'],
                request.form['Satisfactionscore'],
                request.form['Maritalstatus'],
                request.form['Numberofaddress'],
                request.form['Complain'],
                request.form['Orderamounthikefromlastyear'],
                request.form['Couponused'],
                request.form['Ordercount'],
                request.form['Daysincelastorder'],
                request.form['Cashbackamount']
            ]

            # Convert to appropriate types
            cleaned_data = []
            for i in form_data:
                try:
                    if '.' in i:
                        cleaned_data.append(float(i))
                    else:
                        cleaned_data.append(int(i))
                except:
                    cleaned_data.append(i.lower().replace(' ', '_'))

            output_probab = churn_prediction(*cleaned_data)
            pred = "Churn" if output_probab > 0.4 else "Not Churn"

            result_data = {
                'tenure': cleaned_data[0],
                'citytier': cleaned_data[1],
                'warehousetohome': cleaned_data[2],
                'gender': cleaned_data[3],
                'hourspendonapp': cleaned_data[4],
                'numberofdeviceregistered': cleaned_data[5],
                'satisfactionscore': cleaned_data[6],
                'maritalstatus': cleaned_data[7],
                'numberofaddress': cleaned_data[8],
                'complain': cleaned_data[9],
                'orderamounthikefromlastyear': cleaned_data[10],
                'couponused': cleaned_data[11],
                'ordercount': cleaned_data[12],
                'daysincelastorder': cleaned_data[13],
                'cashbackamount': cleaned_data[14],
                'prediction_result': pred,
                'prediction_probability': output_probab
            }

            insert_into_db(result_data)

            return render_template('result.html', data={
                'prediction': pred,
                'predict_probabality': output_probab
            })

        except Exception as e:
            return render_template('index.html', error=f"Error: {str(e)}")

    return render_template('index.html')

# history part
@app.route('/history')
@login_required
def view_history():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM predictions ORDER BY id DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return render_template('history.html', records=rows)

    except mysql.connector.Error as err:
        return f"MySQL Error: {err}"

import csv
from flask import Response


# donwload part
@app.route('/download')
@login_required
def download_csv():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM predictions")
        rows = cursor.fetchall()
        header = [i[0] for i in cursor.description]
        cursor.close()
        conn.close()

        def generate():
            yield ','.join(header) + '\n'
            for row in rows:
                yield ','.join(map(str, row)) + '\n'

        return Response(generate(), mimetype='text/csv',
                        headers={"Content-Disposition": "attachment;filename=predictions.csv"})

    except mysql.connector.Error as err:
        return f"MySQL Error: {err}"


from twilio.rest import Client

# Your Twilio credentials (use environment variables in production)
TWILIO_SID = TWILIO_SID
TWILIO_AUTH_TOKEN = TWILIO_AUTH_TOKEN
TWILIO_PHONE_NUMBER = TWILIO_PHONE_NUMBER

client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        # phone = request.form['phone']
        phone = request.form['phone'].strip()
        # Auto-format to +91
        if len(phone) == 10 and phone.isdigit():
            phone = '+91' + phone
        elif not phone.startswith('+'):
            phone = '+91' + phone


        hashed_pw = generate_password_hash(password)

        # Store user temporarily in session
        session['signup_temp'] = {
            'username': username,
            'email': email,
            'password_hash': hashed_pw,
            'phone': phone,
            'role': 'user'
        }

        # Generate and send OTP
        otp = str(randint(1000, 9999))
        otp_store[phone] = otp
        session['phone_for_otp'] = phone
        session['post_otp_redirect'] = 'finalize_signup'

        try:
            client.messages.create(
                body=f"Your signup OTP is: {otp}",
                from_=TWILIO_PHONE_NUMBER,
                to=phone
            )
            return redirect(url_for('verify_otp'))
        except Exception as e:
            return render_template('signup.html', error=f"OTP send failed: {e}")

    return render_template('signup.html')


@app.route('/finalize_signup')
def finalize_signup():
    if session.get('verified') and 'temp_signup_data' in session:
        data = session.pop('temp_signup_data')
        session.pop('verified', None)

        try:
            conn = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )

            cursor = conn.cursor()
            query = "INSERT INTO users (username, email, password_hash, phone, role) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query, (
                data['username'],
                data['email'],
                data['password_hash'],
                data['phone'],
                data.get('role', 'user')
            ))
            conn.commit()
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        except mysql.connector.IntegrityError as err:
            if "Duplicate entry" in str(err) and "email" in str(err):
                return render_template("signup.html", error="Email already exists. Please log in.")
            elif "Duplicate entry" in str(err) and "phone" in str(err):
                return render_template("signup.html", error="Phone number already registered.")
            else:
                return f"MySQL Error: {err}"

    else:
        return redirect(url_for('signup'))


from random import randint
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']  # ✅ Add this in your login form if not already

        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            # ✅ Set session values
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['is_superadmin'] = user.get('is_superadmin', False)

            # ✅ Admins and Superadmins skip OTP
            if user['role'] == 'admin' or user.get('is_superadmin'):
                return redirect(url_for('admin_panel'))

            # ✅ Regular users → OTP login
            formatted_phone = phone if phone.startswith('+91') else '+91' + phone
            session['phone_for_otp'] = formatted_phone
            session['email_for_otp'] = email

            # Generate OTP
            otp = str(random.randint(100000, 999999))
            otp_store[formatted_phone] = otp

            try:
                client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
                message = client.messages.create(
                    body=f"Your OTP for login is: {otp}",
                    from_=TWILIO_PHONE_NUMBER,
                    to=formatted_phone
                )
            except Exception as e:
                return render_template("login.html", error=f"OTP send failed: {e}")

            return redirect(url_for('verify_otp'))

        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route('/finalize_login')
def finalize_login():
    if session.get('verified') and 'phone_for_otp' in session:
        phone = session.pop('phone_for_otp')
        session.pop('verified', None)

        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE phone = %s", (phone,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('index_page'))

    return redirect(url_for('login'))


# logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# for admin
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_panel():
    conn = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
    cursor = conn.cursor(dictionary=True)
    message = ""

    if request.method == 'POST':
        if 'delete_user_id' in request.form:
            user_id = request.form.get('delete_user_id')
            if user_id:
                # Check if current user is a super admin
                current_user_id = session.get('user_id')
                cursor.execute("SELECT is_superadmin FROM users WHERE id = %s", (current_user_id,))
                current_user = cursor.fetchone()

                if current_user and current_user['is_superadmin']:
                    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
                    conn.commit()
                    message = "User deleted successfully."
                else:
                    message = "You do not have permission to delete other admins."

        elif 'new_username' in request.form:
            new_username = request.form['new_username']
            new_email = request.form['new_email']
            new_phone = request.form['new_phone']
            new_password = request.form['new_password']
            new_role = request.form['new_role']
            hashed_pw = generate_password_hash(new_password)

            try:
                cursor.execute("""
                    INSERT INTO users (username, email, phone, password_hash, role) 
                    VALUES (%s, %s, %s, %s, %s)
                """, (new_username, new_email, new_phone, hashed_pw, new_role))
                conn.commit()
                message = "New admin added!" if new_role == 'admin' else "New user added!"
            except mysql.connector.Error as err:
                message = f"MySQL Error: {err}"

    # Fetch all users
    cursor.execute("SELECT id, username, email, phone, role, is_superadmin FROM users")
    if cursor.with_rows:  # Ensure there are rows to fetch
        users = cursor.fetchall()
    else:
        users = []  # No rows returned

    cursor.close()
    conn.close()

    return render_template('admin.html', users=users, message=message)



# for opt purpose
from random import randint

# Store OTP temporarily (you can use a better solution like DB/Redis in production)
otp_store = {}

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        phone = session.get('phone_for_otp')
        email = session.get('email_for_otp')

        if phone and otp_store.get(phone) == entered_otp:
            del otp_store[phone]  # Remove OTP after verification

            # Check if it's a signup flow
            if 'signup_temp' in session:
                user_data = session.pop('signup_temp')

                conn = mysql.connector.connect(
                    host=DB_HOST,
                    user=DB_USER,
                    password=DB_PASSWORD,
                    database=DB_NAME
                )
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, phone, role) VALUES (%s, %s, %s, %s, %s)",
                    (user_data['username'], user_data['email'], user_data['password_hash'], user_data['phone'], user_data['role'])
                )
                conn.commit()
                cursor.close()
                conn.close()

                return redirect(url_for('login'))

            #  Else, it's a login flow
            conn = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )

            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s AND phone = %s", (email, phone))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('index_page'))

        return render_template('verify_otp.html', error="Invalid OTP")

    return render_template('verify_otp.html')


# forgot password route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        phone = request.form['phone']
        formatted_phone = phone if phone.startswith('+91') else f'+91{phone}'

        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s AND phone = %s", (email, formatted_phone))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            otp = str(random.randint(100000, 999999))
            otp_store[formatted_phone] = otp

            try:
                client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
                message = client.messages.create(
                    body=f"Your OTP for password reset is: {otp}",
                    from_=TWILIO_PHONE_NUMBER,
                    to=formatted_phone
                )
                session['reset_email'] = email
                session['reset_phone'] = formatted_phone
                return redirect(url_for('verify_reset_otp'))
            except Exception as e:
                return render_template('forgot_password.html', error=f"OTP send failed: {e}")

        else:
            return render_template('forgot_password.html', error="User not found with that email and phone.")

    return render_template('forgot_password.html')

# verify reset otp
@app.route('/verify-reset-otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        phone = session.get('reset_phone')

        if phone and otp_store.get(phone) == entered_otp:
            session['otp_verified'] = True
            del otp_store[phone]
            return redirect(url_for('reset_password'))
        else:
            return render_template('verify_reset_otp.html', error="Invalid OTP")

    return render_template('verify_reset_otp.html')


# now reset the password
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('otp_verified') or 'reset_email' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return render_template('reset_password.html', error="Passwords do not match")

        hashed_pw = generate_password_hash(new_password)
        email = session.pop('reset_email')
        session.pop('otp_verified', None)
        session.pop('reset_phone', None)

        try:
            conn = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )

            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_pw, email))
            conn.commit()
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            return f"MySQL Error: {err}"

    return render_template('reset_password.html')

# --------------------
# Run the app
# --------------------
if __name__ == '__main__':
    app.run(debug=True)

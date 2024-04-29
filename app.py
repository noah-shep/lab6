import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify, Response
import sqlite3
import bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime
from geopy.geocoders import Nominatim
import requests
import google.generativeai as genai
from math import radians, sin, cos, sqrt, atan2
import io
import csv
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a secure random secret key

# Allowed file extensions
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Set the upload folder configuration
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
DATABASE = 'users.db'
REPORT_DATABASE = 'user_report.db'

def init_db(database):
    try:
        with sqlite3.connect(database) as conn:
            cursor = conn.cursor()
            
            # Create user table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                api_key TEXT NOT NULL
            )
            """)
            
            # Create user report table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_report (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                time_entry TEXT NOT NULL,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                text TEXT NOT NULL,
                file_data BLOB,
                filename TEXT,
                temperature REAL,
                state TEXT,
                country TEXT,
                ip_address TEXT,
                CLASSIFICATION TEXT
            )
            """)
            
            conn.commit()

    except Exception as e:
        print(f"Error initializing database: {e}")

# Initialize the databases
init_db(DATABASE)
init_db(REPORT_DATABASE)

def get_db(database=DATABASE):
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(database)
    return db

@app.teardown_appcontext
def close_connection(exception=None):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def register_user(name, username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    api_key = bcrypt.hashpw(os.urandom(16), bcrypt.gensalt()).decode('utf-8')
    db = get_db()
    db.execute("INSERT INTO users (name, username, hashed_password, api_key) VALUES (?, ?, ?, ?)",
                (name, username, hashed_password.decode('utf-8'), api_key))
    db.commit()

def get_user_by_username(username):
    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    return user

def verify_password(input_password, stored_hashed_password):
    return bcrypt.checkpw(input_password.encode('utf-8'), stored_hashed_password.encode('utf-8'))


def add_user_report(username, time_entry, latitude, longitude, text, file_data, filename, temperature, state, country, ip_address, classification):
    db = get_db()
    db.execute("""
        INSERT INTO user_report (
            username, 
            time_entry, 
            latitude, 
            longitude, 
            text, 
            file_data, 
            filename,
            temperature,
            state,
            country,
            ip_address,
            CLASSIFICATION
        ) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username, 
        time_entry, 
        latitude, 
        longitude, 
        text, 
        file_data, 
        filename,
        temperature,
        state,
        country,
        ip_address,
        classification
    ))
    db.commit()

# how to analyze text with generativeai
def analyze_text_with_generativeai(text):
    # Read API key
    with open("api_google.txt", "r") as file:
        api_key = file.read().strip()

    # Configure genai with the API key
    genai.configure(api_key=api_key)

    # Initialize the generative model
    model = genai.GenerativeModel('gemini-pro')

    # Set up the prompt
    prompt = f"Answer with offensive or normal if the following text offensive or normal?\n\n{text}\n\nResponse: "
    
    try:
        # Generate the response
        response = model.generate_content(prompt)
        
        # Print the raw response
        print(f"Raw GenerativeAI response: {response}")

        # Extract the classification from the response
        if 'Normal' in response.candidates[0].content.parts[0].text:
            return 'normal'
        elif 'Offensive' in response.candidates[0].content.parts[0].text:
            return 'offensive'
        else:
            return 'unknown'

    except Exception as e:
        print(f"Error generating response: {e}")
        return None


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')

        if not name or not username or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        user = get_user_by_username(username)
        
        if user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        register_user(name, username, password)
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_by_username(username)
        
        if user and verify_password(password, user[3]):
            session['logged_in'] = True
            session['username'] = user[2]
            session['api_key'] = user[4]  # Store the API key in the session
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard', username=session['username']))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/dashboard/<username>', methods=['GET', 'POST'])
def dashboard(username):
    if 'logged_in' in session and session['username'] == username:
        user = get_user_by_username(username)
        api_key = user[4] if user else None
        
        if request.method == 'POST':
            if 'api_key' in session and request.form['api_key'] == session['api_key']:
                time_entry = datetime.utcnow().isoformat()
                latitude = request.form['latitude']
                longitude = request.form['longitude']
                text = request.form['text']
                
                # Save file if uploaded
                file_data = None
                filename = None
                if 'file' in request.files:
                    file = request.files['file']
                    if file.filename != '':
                        filename = secure_filename(file.filename)
                        file_data = file.read()
                
                add_user_report(username, time_entry, latitude, longitude, text, file_data, filename)
                flash('Report added successfully!', 'success')
                return redirect(url_for('report', 
                                        username=username, 
                                        api_key=api_key, 
                                        time_entry=time_entry, 
                                        latitude=latitude, 
                                        longitude=longitude, 
                                        text=text, 
                                        filename=filename))

        return render_template('dashboard.html', username=username, api_key=api_key)
    else:
        flash('You need to login first.', 'warning')
        return redirect(url_for('login'))
    

#################################
#this is the submit report code 
################################
def get_geocode_api_key():
    with open('api.txt', 'r') as file:
        api_key = file.read().strip()
    return api_key

@app.route('/submit_report', methods=['POST'])
def submit_report():
    try:
        if 'logged_in' in session:
            username = session['username']
            user = get_user_by_username(username)
            
            # Retrieve the API key from the database
            stored_api_key = user[4] if user else None
            
            # Retrieve the API key entered by the user in the form
            entered_api_key = request.form['api_key']
            
            if stored_api_key != entered_api_key:
                flash('Invalid API key.', 'danger')
                return redirect(url_for('dashboard', username=username))
            
            time_entry = request.form['time_entry']
            latitude = request.form['latitude']
            longitude = request.form['longitude']
            text = request.form['text']
            
            print(f"Received report from {username}:")
            print(f"Time Entry: {time_entry}")
            print(f"Location: {latitude}, {longitude}")
            print(f"Text: {text}")

            # Analyze text with GenerativeAI
            analysis_result = analyze_text_with_generativeai(text)
        
            print(f"GenerativeAI analysis result: {analysis_result}")

            if analysis_result is None:
                classification = 'N/A'
            elif 'offensive' in analysis_result:
                classification = 'Offensive'
            elif 'normal' in analysis_result:
                classification = 'Normal'
            else:
                classification = 'Unknown'
            
            file_data = None
            filename = None
            if 'file' in request.files:
                file = request.files['file']
                if file.filename != '':
                    filename = secure_filename(file.filename)
                    file_data = file.read()
            
            # Fetch state and country using Geocode.xyz API
            geocode_api_key = get_geocode_api_key()
            url = f"https://geocode.xyz/{latitude},{longitude}?json=1&auth={geocode_api_key}"
            
            response = requests.get(url)
            data = response.json()
            
            state = data.get('region', 'N/A')
            country = data.get('country', 'N/A')
            
            # Fetch current temperature using Open-Meteo
            open_meteo_url = f"https://api.open-meteo.com/v1/forecast?latitude={latitude}&longitude={longitude}&current=temperature_2m"
            open_meteo_response = requests.get(open_meteo_url)
            open_meteo_data = open_meteo_response.json()
            temperature = open_meteo_data.get('current', {}).get('temperature_2m', 'N/A')

            # Get IP address of the client
            ip_address = request.remote_addr
            
            # Add the report to the user_report table
            add_user_report(username, time_entry, latitude, longitude, text, file_data, filename, temperature, state, country, ip_address, classification)

            
            print("Report added successfully to the database.")
            
            # Render the report.html template with the required data
            return render_template('report.html', username=username, api_key=stored_api_key,
                                    time_entry=time_entry, latitude=latitude,
                                    longitude=longitude, text=text, filename=filename,
                                    state=state, country=country, ip_address=ip_address, temperature=temperature, classification=classification)
        
    except Exception as e:
        print(f"Error submitting report: {e}")
        flash('Error submitting report.', 'danger')
        return redirect(url_for('dashboard', username=username))

    
    else:
        flash('You need to login first.', 'warning')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('api_key', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ... (other imports and code)

@app.route('/report')
def report():
    username = request.args.get('username')
    api_key = request.args.get('api_key')
    time_entry = request.args.get('time_entry')
    latitude = request.args.get('latitude')
    longitude = request.args.get('longitude')
    text = request.args.get('text')
    filename = request.args.get('filename')
    
    # Validate latitude and longitude
    if latitude is None or longitude is None:
        return jsonify({"error": "Latitude and longitude are required parameters"}), 400

    return render_template('report.html',
                           username=username,
                           api_key=api_key,
                           time_entry=time_entry,
                           latitude=latitude,
                           longitude=longitude,
                           text=text,
                           filename=filename,
                           ip_address=request.remote_addr)

# this is the api key
@app.route('/get_geocode_api_key')
def get_geocode_api_key():
    with open('api.txt', 'r') as file:
        api_key = file.read().strip()
    return api_key


def get_filtered_user_reports(latitude=None, longitude=None, radius=None, start_date=None, end_date=None, limit=None):
    try:
        db = sqlite3.connect('users.db')
        cursor = db.cursor()

        # Base query
        query = "SELECT id, username, time_entry, latitude, longitude, text, file_data, filename, temperature, state, country, ip_address, CLASSIFICATION FROM user_report"
        conditions = []
        params = []

        # Add conditions for start_date and end_date if provided
        if start_date and end_date:
            conditions.append("time_entry BETWEEN ? AND ?")
            params.extend([start_date, end_date])

        # If latitude, longitude, and radius are provided, add location-based conditions
        if latitude is not None and longitude is not None and radius is not None:
            conditions.append("(latitude - ?) * (latitude - ?) + (longitude - ?) * (longitude - ?) <= ? * ?")
            params.extend([latitude, latitude, longitude, longitude, radius, radius])

        # Build the final query
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        # Sort by time_entry in descending order
        query += " ORDER BY time_entry DESC"

        # Add LIMIT clause to limit the number of rows returned
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        cursor.execute(query, params)
        reports = cursor.fetchall()

        print(f"Executing query: {query}")
        print(f"Parameters: {params}")
        print(f"Fetched reports: {reports}")
        print(f"Filtered reports count: {len(reports)}")

        db.close()

        return reports

    except Exception as e:
        print(f"Error fetching data: {e}")
        return None


# calc distance
def calculate_distance(lat1, lon1, lat2, lon2):
    # approximate radius of earth in km
    R = 6373.0

    lat1 = radians(lat1)
    lon1 = radians(lon1)
    lat2 = radians(lat2)
    lon2 = radians(lon2)

    dlon = lon2 - lon1
    dlat = lat2 - lat1

    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    distance = R * c
    
    print(f"Calculated distance between ({lat1}, {lon1}) and ({lat2}, {lon2}): {distance} km")

    return distance



def convert_reports_to_csv(filtered_reports):
    csv_data = "id,username,time_entry,latitude,longitude,text,file_data,filename,temperature,state,country,ip_address,CLASSIFICATION\n"
    
    for row in filtered_reports:
        formatted_row = []
        for item in row:
            # Convert item to string and handle any errors
            try:
                formatted_item = str(item)
            except Exception as e:
                print(f"Error converting item to string: {e}")
                formatted_item = "ERROR"
            formatted_row.append(formatted_item)
        
        # Join the formatted row elements with commas
        row_data = ','.join(formatted_row)
        csv_data += row_data + '\n'
    
    print(f"Generated CSV data length: {len(csv_data)}")
    
    return csv_data


@app.route('/data', methods=['GET', 'POST'])
def data_page():
    if request.method == 'POST':
        flash('POST method not supported.', 'danger')
        return redirect(url_for('data_page'))

    elif request.method == 'GET':
        latitude = request.args.get('latitude')
        longitude = request.args.get('longitude')
        radius = request.args.get('radius')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        # Debugging line to print received parameters
        print(f"Received request with parameters: latitude={latitude}, longitude={longitude}, radius={radius}, start_date={start_date}, end_date={end_date}")

        if latitude is None or longitude is None or radius is None:
            flash('Latitude, longitude, and radius are required.', 'danger')
            return render_template('data_page.html')

        try:
            latitude = float(latitude)
            longitude = float(longitude)
            radius = float(radius)
        except ValueError:
            flash('Latitude, longitude, and radius must be valid numbers.', 'danger')
            return render_template('data_page.html')

        if start_date and end_date:
            try:
                datetime.strptime(start_date, '%Y-%m-%d')
                datetime.strptime(end_date, '%Y-%m-%d')
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
                return render_template('data_page.html')

        # Filter the reports based on the provided parameters
        filtered_reports = get_filtered_user_reports(latitude, longitude, radius, start_date, end_date)

        # Convert filtered reports to CSV data
        csv_data = convert_reports_to_csv(filtered_reports)
        if csv_data:
            print("Sending CSV data...")
            # Return CSV data as a response
            return Response(
                csv_data,
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=user_reports.csv"}
            )
        else:
            flash('Error generating CSV.', 'danger')
            return render_template('data_page.html')

    return render_template('data_page.html')


 

if __name__ == '__main__':
    app.run(debug=True, port=8080)
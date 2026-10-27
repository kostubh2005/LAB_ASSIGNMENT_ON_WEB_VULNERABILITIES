# ---------------------------------------------------------------
# app_vulnerable.py
# A simple login page with a SQL injection vulnerability.
# Used to DEMONSTRATE the attack (Variant 1: authentication bypass).
# ---------------------------------------------------------------

from flask import Flask, request, render_template_string  # Flask builds the web server; request reads form data; render_template_string builds HTML
import sqlite3  # Built-in Python library for SQLite databases (stored in a single file)

app = Flask(__name__)  # Create the web application object


def get_db():
    """Open a connection to the SQLite database file users.db."""
    conn = sqlite3.connect("users.db")  # Creates users.db if it doesn't exist yet
    conn.row_factory = sqlite3.Row      # Lets us access columns by name, e.g. user["username"]
    return conn


def init_db():
    """Create the users table and add two sample accounts. Runs once at startup."""
    conn = get_db()
    conn.execute("DROP TABLE IF EXISTS users")  # Remove old table so each run starts fresh
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    # Sample accounts. Passwords are stored in plain text on purpose, to keep the demo simple.
    conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'secret123')")
    conn.execute("INSERT INTO users (username, password) VALUES ('alice', 'alicepass')")
    conn.commit()  # Save the changes to the database file
    conn.close()   # Close the connection


# CSS styling for the page. Kept in a separate string so the HTML stays readable.
PAGE_STYLE = """
<style>
  body {
    font-family: Arial, sans-serif;     /* Clean, readable font */
    background-color: #f2f4f7;          /* Light grey page background */
    display: flex;                      /* Use flexbox to centre the card */
    justify-content: center;            /* Centre horizontally */
    align-items: center;                /* Centre vertically */
    min-height: 100vh;                  /* Full height of the browser window */
    margin: 0;                          /* Remove default browser margin */
  }
  .card {
    background: white;                  /* White box for the form */
    padding: 30px 40px;                 /* Space inside the box */
    border-radius: 8px;                 /* Rounded corners */
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);  /* Soft shadow behind the box */
    width: 300px;                       /* Fixed width */
  }
  h2 { margin-top: 0; color: #333; }    /* Heading style, no extra space above */
  input {
    width: 100%;                        /* Make inputs fill the card width */
    padding: 8px;                       /* Space inside each input box */
    margin: 6px 0 14px 0;               /* Space around each input */
    box-sizing: border-box;             /* Padding doesn't add to the width */
    border: 1px solid #ccc;             /* Light grey border */
    border-radius: 4px;                 /* Rounded corners */
  }
  button {
    width: 100%;                        /* Full-width button */
    padding: 10px;                      /* Space inside the button */
    background-color: #2563eb;          /* Blue button */
    color: white;                       /* White text */
    border: none;                       /* No border */
    border-radius: 4px;                 /* Rounded corners */
    cursor: pointer;                    /* Hand cursor on hover */
    font-size: 16px;                    /* Readable button text */
  }
  button:hover { background-color: #1d4ed8; }  /* Darker blue when hovered */
  .msg { color: #dc2626; }              /* Red text for error messages */
</style>
"""


# The HTML for the login form. {{ message }} is a placeholder filled in by Flask.
LOGIN_PAGE = PAGE_STYLE + """
<div class="card">                      <!-- White card that holds the form -->
  <h2>Login</h2>
  <form method="post" action="/login">
    Username:
    <input name="username">
    Password:
    <input name="password" type="password">
    <button type="submit">Login</button>
  </form>
  <p class="msg">{{ message }}</p>      <!-- Error message appears here in red -->
</div>
"""


@app.route("/")  # When someone visits the home page...
def home():
    # ...show the login form with no message
    return render_template_string(LOGIN_PAGE, message="")


@app.route("/login", methods=["POST"])  # Runs when the login form is submitted
def login():
    # Read what the user typed into the two form fields
    username = request.form["username"]
    password = request.form["password"]

    # VULNERABLE LINE: the user's input is pasted directly into the SQL text.
    # The database cannot tell the difference between our SQL and the user's input,
    # so input like ' OR '1'='1' -- changes what the query means.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    conn = get_db()
    user = conn.execute(query).fetchone()  # fetchone() returns the first matching row, or None
    conn.close()

    if user:
        # A matching row was found, so the login is treated as successful
        return render_template_string(
            PAGE_STYLE + """
            <div class="card">                      <!-- Same card style as the login page -->
              <h2>Welcome, {{ name }}!</h2>
              <p>You are logged in.</p>
            </div>
            """,
            name=user["username"],
        )

    # No matching row, so the login failed
    return render_template_string(LOGIN_PAGE, message="Invalid username or password")


if __name__ == "__main__":
    # This block runs only when you start the file directly (python app_vulnerable.py)
    init_db()            # Set up the database first
    app.run(debug=True)  # Start the web server at http://127.0.0.1:5000
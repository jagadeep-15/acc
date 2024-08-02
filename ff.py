import streamlit as st
import sqlite3
import bcrypt
import pandas as pd
from datetime import datetime

# Page configuration
st.set_page_config(page_title="Login and Register", page_icon="🔒", layout="centered")

# Database setup and functions
def create_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def insert_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hash_password(password)))
    conn.commit()
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE username = ?', (username,))
    stored_password = c.fetchone()
    conn.close()
    if stored_password and bcrypt.checkpw(password.encode('utf-8'), stored_password[0]):
        return True
    return False

# Ensure the database and table exist
create_db()

# Initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "invoices" not in st.session_state:
    st.session_state.invoices = []

# Main function
def main():
    # Retrieve query parameters
    query_params = st.query_params

    # Determine which page to display based on query parameters
    if "page" in query_params and query_params["page"][0] == "invoice_uploader":
        if st.session_state.logged_in:
            invoice_uploader()
        else:
            st.write("You need to log in first.")
            login_form()
    else:
        if not st.session_state.logged_in:
            st.title("Welcome! Please log in or register to continue.")

            # Sidebar branding (optional)
            logo_path = r"C:\Users\SBAL036\Pictures\SBA LOGO.png"  # Use raw string for the file path
            try:
                st.sidebar.image(logo_path, use_column_width=True)
            except Exception as e:
                st.sidebar.write("Logo not found.")

            st.sidebar.markdown("### SBA")

            # Tabs for login and register
            tab_login, tab_register = st.tabs(["Login", "Register"])

            with tab_login:
                login_form()

            with tab_register:
                register_form()
        else:
            # Use URL manipulation to handle redirection
            st.set_query_params(page="invoice_uploader")

# Login form function
def login_form():
    st.header("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")
    
    if submit_button:
        if authenticate_user(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success("Login successful!")
            # Redirect to the invoice uploader page
            st.set_query_params(page="invoice_uploader")
            st.experimental_rerun()
        else:
            st.error("Invalid username or password")

# Register form function
def register_form():
    st.header("Register")
    with st.form("register_form"):
        username = st.text_input("New Username")
        password = st.text_input("New Password", type="password")
        submit_button = st.form_submit_button("Register")
    
    if submit_button:
        if username and password:
            try:
                insert_user(username, password)
                st.success("Registration successful! Please log in.")
            except sqlite3.IntegrityError:
                st.error("Username already exists.")
        else:
            st.error("Please provide both username and password.")

# Invoice uploader page function
def invoice_uploader():
    st.title(f"Welcome, {st.session_state.username}!")
    st.write("You are successfully logged in.")
    st.write("This is the invoice uploader page.")
    uploaded_file = st.file_uploader("Choose an invoice file", type=["pdf", "jpg", "jpeg", "png"])
    if uploaded_file is not None:
        st.write("File uploaded successfully!")
        # Process the uploaded file as needed

    # Additional functionality for invoice processing
    st.write("---")
    st.title("Invoice Processing Workflow")

    # Function to validate invoice data
    def validate_invoice(data):
        if data['Amount'] <= 0:
            return False, "Amount must be greater than 0"
        return True, ""

    # Function to simulate approval workflow
    def approve_invoice(data):
        if data['Amount'] > 1000:
            data['Status'] = "Needs Manager Approval"
        else:
            data['Status'] = "Approved"
        return data

    # Invoice submission form
    with st.form(key='invoice_form'):
        supplier = st.text_input("Supplier Name")
        invoice_number = st.text_input("Invoice Number")
        amount = st.number_input("Amount", min_value=0.0)
        submit_date = st.date_input("Submit Date", datetime.today())
        submit_button = st.form_submit_button(label='Submit Invoice')

    if submit_button:
        new_invoice = {
            "Supplier": supplier,
            "Invoice Number": invoice_number,
            "Amount": amount,
            "Submit Date": submit_date,
            "Status": "Submitted"
        }

        # Validate the invoice
        is_valid, validation_message = validate_invoice(new_invoice)
        if is_valid:
            # Approve the invoice
            approved_invoice = approve_invoice(new_invoice)
            st.session_state.invoices.append(approved_invoice)
            st.success(f"Invoice {invoice_number} submitted successfully!")
        else:
            st.error(f"Validation Error: {validation_message}")

    # Display the list of invoices
    st.subheader("Invoices")
    if st.session_state.invoices:
        df_invoices = pd.DataFrame(st.session_state.invoices)
        st.dataframe(df_invoices)
    else:
        st.write("No invoices submitted yet.")

    # Exception handling (placeholder)
    st.subheader("Exceptions")
    # You can add more logic to handle exceptions here

    # Real-time analytics (placeholder)
    st.subheader("Analytics")
    # You can add more analytics and reporting here

# Run the main function
if __name__ == "__main__":
    main()

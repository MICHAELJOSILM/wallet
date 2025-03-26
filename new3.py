import streamlit as st
import sqlite3
import hashlib
import uuid
import time
import os
import secrets
import jwt
import bcrypt
from datetime import datetime, timedelta
import pandas as pd
import re
from sqlalchemy import create_engine, Column, String, Float, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# Constants
SESSION_TIMEOUT_MINUTES = 15
JWT_SECRET = secrets.token_hex(32)  # Generate secure random JWT secret
SALT_ROUNDS = 12  # For bcrypt password hashing
DB_PATH = "blockchain_wallet.db"
MIN_PASSWORD_LENGTH = 8

# Using a more robust wallet implementation
class BlockchainWallet:
    def __init__(self, username, password=None):
        # Create a unique deterministic wallet using both username and a secret
        seed = username + (password or "") + os.environ.get("WALLET_SEED_SALT", secrets.token_hex(16))
        self.private_key = hashlib.sha256(seed.encode()).hexdigest()
        # Public address is derived from private key using double hash (similar to Bitcoin)
        sha256_hash = hashlib.sha256(self.private_key.encode()).digest()
        ripemd160_hash = hashlib.new('ripemd160')
        ripemd160_hash.update(sha256_hash)
        self.address = "bc1" + ripemd160_hash.hexdigest()[:34]
    
    def get_address(self):
        return self.address
    
    def get_partial_private_key(self):
        # Never expose the full private key
        return self.private_key[:5] + "..." + self.private_key[-5:]

# Database setup with SQLAlchemy for better SQL injection protection
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    wallet_address = Column(String, unique=True, nullable=False)
    balance = Column(Float, default=100.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    failed_login_attempts = Column(Float, default=0)
    locked_until = Column(DateTime, nullable=True)
    
class Transaction(Base):
    __tablename__ = 'transactions'
    
    id = Column(String, primary_key=True)
    sender = Column(String, ForeignKey('users.username'))
    receiver = Column(String, ForeignKey('users.username'))
    amount = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    signature = Column(String, nullable=False)  # Digital signature to verify transaction
    status = Column(String, default="confirmed")

# Setup database connection with SQLAlchemy
def init_database():
    engine = create_engine(f'sqlite:///{DB_PATH}')
    Base.metadata.create_all(engine)
    return engine

# Create database session
def get_db_session():
    engine = create_engine(f'sqlite:///{DB_PATH}')
    Session = sessionmaker(bind=engine)
    return Session()

# Initialize database
def initialize_app():
    if not os.path.exists(DB_PATH):
        init_database()
    
    # Initialize session state variables
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "username" not in st.session_state:
        st.session_state.username = None
    if "login_time" not in st.session_state:
        st.session_state.login_time = None
    if "export_excel" not in st.session_state:
        st.session_state.export_excel = False

# Authentication functions
def hash_password(password):
    # Use bcrypt for secure password hashing
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=SALT_ROUNDS)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(stored_hash, provided_password):
    # Verify password with bcrypt
    stored_bytes = stored_hash.encode('utf-8')
    provided_bytes = provided_password.encode('utf-8')
    return bcrypt.checkpw(provided_bytes, stored_bytes)

def create_session_token(username):
    # Create JWT token with expiration
    expiration = datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    payload = {
        'username': username,
        'exp': expiration
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def validate_session_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        st.warning("Your session has expired. Please log in again.")
        return None
    except:
        return None

def check_session_timeout():
    # Check if session has timed out
    if st.session_state.login_time:
        elapsed = datetime.now() - st.session_state.login_time
        if elapsed > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            logout_user()
            st.warning("Your session has expired due to inactivity. Please log in again.")
            return True
    return False

def logout_user():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.login_time = None

# Strong password validation
def is_strong_password(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        return False
    
    # Check for at least one uppercase, one lowercase, one digit, and one special character
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    
    return True

# User registration with enhanced security
def register_user(username, password):
    if not username or not password:
        return False, "Username and password cannot be empty."
    
    # Validate username (alphanumeric only)
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores."
    
    # Validate password strength
    if not is_strong_password(password):
        return False, "Password must be at least 8 characters and include uppercase, lowercase, numbers, and special characters."
    
    # Create user with hashed password
    session = get_db_session()
    try:
        # Check if username already exists
        existing_user = session.query(User).filter_by(username=username).first()
        if existing_user:
            session.close()
            return False, "Username already exists."
        
        # Create wallet
        wallet = BlockchainWallet(username, password)
        wallet_address = wallet.get_address()
        
        # Create user
        user_id = str(uuid.uuid4())
        password_hash = hash_password(password)
        
        new_user = User(
            id=user_id,
            username=username,
            password_hash=password_hash,
            wallet_address=wallet_address,
            balance=100.0
        )
        
        session.add(new_user)
        session.commit()
        session.close()
        
        return True, f"Wallet created successfully! Your address: {wallet_address}"
    except Exception as e:
        session.rollback()
        session.close()
        return False, f"Error creating wallet: {str(e)}"

# User login with rate limiting
def login_user(username, password):
    session = get_db_session()
    try:
        user = session.query(User).filter_by(username=username).first()
        
        if not user:
            session.close()
            return False, "Invalid username or password."
        
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            locked_for = (user.locked_until - datetime.utcnow()).seconds // 60
            session.close()
            return False, f"Account is locked due to multiple failed attempts. Try again in {locked_for} minutes."
        
        # Verify password
        if verify_password(user.password_hash, password):
            # Reset failed login attempts on successful login
            user.failed_login_attempts = 0
            session.commit()
            session.close()
            
            # Update session state
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.login_time = datetime.now()
            
            return True, "Login successful."
        else:
            # Increment failed login attempts
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                session.commit()
                session.close()
                return False, "Too many failed login attempts. Account locked for 15 minutes."
            
            session.commit()
            session.close()
            return False, "Invalid username or password."
    except Exception as e:
        session.rollback()
        session.close()
        return False, f"Login error: {str(e)}"

# Change password functionality
def change_password(username, current_password, new_password):
    session = get_db_session()
    try:
        # Get user
        user = session.query(User).filter_by(username=username).first()
        
        if not user:
            session.close()
            return False, "User not found."
        
        # Verify current password
        if not verify_password(user.password_hash, current_password):
            # Increment failed login attempts as security measure
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                session.commit()
                session.close()
                return False, "Too many failed password attempts. Account locked for 15 minutes."
            
            session.commit()
            session.close()
            return False, "Current password is incorrect."
        
        # Validate new password strength
        if not is_strong_password(new_password):
            session.close()
            return False, "New password must be at least 8 characters and include uppercase, lowercase, numbers, and special characters."
        
        # Hash the new password
        new_password_hash = hash_password(new_password)
        
        # Update user's password
        user.password_hash = new_password_hash
        
        # Reset failed login attempts
        user.failed_login_attempts = 0
        
        # Update the wallet with new credentials (optional, depending on your design)
        # In a real blockchain system, changing password might require re-encrypting keys
        
        session.commit()
        session.close()
        
        return True, "Password changed successfully! Please log in with your new password."
    except Exception as e:
        session.rollback()
        session.close()
        return False, f"Password change failed: {str(e)}"

# Get user balance
def get_balance(username):
    session = get_db_session()
    try:
        user = session.query(User).filter_by(username=username).first()
        balance = user.balance if user else 0
        session.close()
        return balance
    except Exception as e:
        session.close()
        return 0

# Get wallet address
def get_wallet_address(username):
    session = get_db_session()
    try:
        user = session.query(User).filter_by(username=username).first()
        address = user.wallet_address if user else None
        session.close()
        return address
    except Exception as e:
        session.close()
        return None

# Get all users
def get_users():
    session = get_db_session()
    try:
        users = [user.username for user in session.query(User).all()]
        session.close()
        return users
    except Exception as e:
        session.close()
        return []

# Create digital signature for transaction
def sign_transaction(sender, receiver, amount, timestamp):
    # In a real blockchain, this would use the sender's private key
    # For this demo, we'll use a hash-based signature
    message = f"{sender}{receiver}{amount:.3f}{timestamp}"
    return hashlib.sha256(message.encode()).hexdigest()

# Transfer funds with enhanced security
def transfer_funds(sender, receiver, amount):
    if sender == receiver:
        return False, "Cannot send to yourself!"
    
    session = get_db_session()
    try:
        # Get sender user
        sender_user = session.query(User).filter_by(username=sender).first()
        
        # Check if receiver exists
        receiver_user = session.query(User).filter_by(username=receiver).first()
        if not receiver_user:
            session.close()
            return False, "Receiver does not exist!"
        
        # Check sender balance
        if sender_user.balance < amount:
            session.close()
            return False, "Insufficient balance!"
        
        # Create transaction timestamp
        timestamp = datetime.utcnow()
        
        # Create digital signature
        signature = sign_transaction(sender, receiver, amount, timestamp)
        
        # Create transaction ID
        tx_id = str(uuid.uuid4())
        
        # Process the transaction (simulating blockchain confirmations)
        with st.spinner("Processing transaction..."):
            # Simulate blockchain confirmation time
            time.sleep(2)
            
            # Update balances
            sender_user.balance -= amount
            receiver_user.balance += amount
            
            # Create transaction record
            new_transaction = Transaction(
                id=tx_id,
                sender=sender,
                receiver=receiver,
                amount=amount,
                timestamp=timestamp,
                signature=signature
            )
            
            session.add(new_transaction)
            session.commit()
            session.close()
            
            return True, f"Transaction Successful! Transaction ID: {tx_id[:8]}..."
    except Exception as e:
        session.rollback()
        session.close()
        return False, f"Transaction failed: {str(e)}"

# Get user transactions
def get_transactions(username):
    session = get_db_session()
    try:
        transactions = session.query(Transaction).filter(
            (Transaction.sender == username) | (Transaction.receiver == username)
        ).order_by(Transaction.timestamp.desc()).all()
        
        result = [(
            t.sender, 
            t.receiver, 
            t.amount, 
            t.timestamp.strftime("%Y-%m-%d %H:%M:%S"), 
            t.id,
            t.signature[:8] + "..."  # First few characters of signature
        ) for t in transactions]
        
        session.close()
        return result
    except Exception as e:
        session.close()
        return []

# Get all transactions for export
def get_all_transactions():
    session = get_db_session()
    try:
        transactions = session.query(Transaction).order_by(Transaction.timestamp.desc()).all()
        
        result = [(
            t.id,
            t.sender, 
            t.receiver, 
            t.amount, 
            t.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            t.signature[:8] + "...",
            t.status
        ) for t in transactions]
        
        session.close()
        return result
    except Exception as e:
        session.close()
        return []

# Export transactions to Excel
def export_transactions_to_excel():
    transactions = get_all_transactions()
    
    if not transactions:
        return None
    
    # Create DataFrame
    df = pd.DataFrame(transactions, columns=[
        "Transaction ID", 
        "Sender", 
        "Receiver", 
        "Amount (BTC)", 
        "Timestamp", 
        "Signature", 
        "Status"
    ])
    
    # Format amount with 3 decimal places
    df["Amount (BTC)"] = df["Amount (BTC)"].apply(lambda x: f"{x:.3f}")
    
    # Excel file path
    filename = "blockchain_transactions.xlsx"
    
    try:
        df.to_excel(filename, index=False, engine="openpyxl")
        return filename
    except Exception as e:
        return None

# Main UI function
def main():
    # Initialize the app
    initialize_app()
    
    # Apply CSS styling
    st.markdown("""
    <style>
        .transaction-sent { color: #ff4b4b; }
        .transaction-received { color: #4bb543; }
        .balance-display { font-size: 24px; font-weight: bold; }
        .security-box {
            background-color: #f8f9fa;
            border-left: 4px solid #ff4b4b;
            padding: 10px;
            margin-bottom: 10px;
        }
        .stDownloadButton button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .stDownloadButton button:hover {
            background-color: #45a049;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Check for session timeout
    if st.session_state.logged_in:
        if check_session_timeout():
            st.rerun()  # Using st.rerun() instead of st.experimental_rerun()
    
    # Main title
    st.title("M J Secure Blockchain Wallet")
    
    # Authentication UI
    if not st.session_state.logged_in:
        tab1, tab2 = st.tabs(["Login", "Create Wallet"])
        
        with tab1:
            st.subheader("Login to Your Wallet")
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            
            if st.button("Login"):
                success, message = login_user(username, password)
                if success:
                    st.success(message)
                    st.rerun()  # Using st.rerun() instead of st.experimental_rerun()
                else:
                    st.error(message)
        
        with tab2:
            st.subheader("Create New Wallet")
            username = st.text_input("Username", key="register_username")
            password = st.text_input("Password", type="password", key="register_password")
            confirm_password = st.text_input("Confirm Password", type="password")
            
            # Password strength indicator
            if password:
                is_strong = is_strong_password(password)
                if is_strong:
                    st.success("Strong password")
                else:
                    st.warning("Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters")
            
            if st.button("Create Wallet"):
                if password != confirm_password:
                    st.error("Passwords do not match!")
                else:
                    success, message = register_user(username, password)
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
    
    # Main wallet UI (only shown when logged in)
    else:
        st.sidebar.success(f"Logged in as: {st.session_state.username}")
        if st.sidebar.button("Logout"):
            logout_user()
            st.rerun()  # Using st.rerun() instead of st.experimental_rerun()
        
        # Show inactivity timer
        if st.session_state.login_time:
            elapsed = datetime.now() - st.session_state.login_time
            remaining = timedelta(minutes=SESSION_TIMEOUT_MINUTES) - elapsed
            remaining_mins = int(remaining.total_seconds() / 60)
            remaining_secs = int(remaining.total_seconds() % 60)
            st.sidebar.info(f"Session expires in: {remaining_mins}m {remaining_secs}s")
        
        # Main menu
        menu = ["View Balance", "Send Bitcoin", "Transaction History", "Export Transactions", "Security"]
        choice = st.sidebar.selectbox("Menu", menu)
        
        if choice == "View Balance":
            st.subheader("View Wallet Balance")
            username = st.session_state.username
            balance = get_balance(username)
            wallet_address = get_wallet_address(username)
            
            st.markdown(f"<p class='balance-display'>{balance:.3f} BTC</p>", unsafe_allow_html=True)
            st.markdown("---")
            st.subheader("Wallet Details")
            st.info(f"Address: {wallet_address}")
            
            # QR code for wallet (in a real app, this would be a QR code)
            st.markdown("---")
            st.subheader("Wallet QR Code")
            st.caption("For demonstration purposes only. In a real application, this would display a QR code of your wallet address.")
        
        elif choice == "Send Bitcoin":
            st.subheader("Send Bitcoin")
            username = st.session_state.username
            users = get_users()
            
            # Remove current user from receivers list
            receivers = [user for user in users if user != username]
            
            if not receivers:
                st.warning("No other wallets found to send to. Please create another wallet.")
            else:
                receiver = st.selectbox("To (Receiver)", receivers)
                
                # Show current balance
                sender_balance = get_balance(username)
                st.info(f"Available Balance: {sender_balance:.3f} BTC")
                
                # Amount input with validation
                amount = st.number_input(
                    "Amount (BTC)", 
                    min_value=0.001, 
                    max_value=float(sender_balance) if sender_balance > 0 else 1.0, 
                    value=min(0.001, float(sender_balance)) if sender_balance > 0 else 0.001, 
                    format="%.3f", 
                    step=0.001
                )
                
                # Security confirmation
                st.markdown("<div class='security-box'>⚠️ Always verify the receiver address before sending funds.</div>", unsafe_allow_html=True)
                
                confirm = st.checkbox("I confirm this transaction")
                
                if st.button("Send Bitcoin", disabled=not confirm):
                    success, message = transfer_funds(username, receiver, amount)
                    if success:
                        st.success(message)
                        st.session_state.export_excel = True
                        # Reset login_time to prevent timeout during transaction
                        st.session_state.login_time = datetime.now()
                    else:
                        st.error(message)
        
        elif choice == "Transaction History":
            st.subheader("Transaction History")
            username = st.session_state.username
            transactions = get_transactions(username)
            
            # Add export button
            col1, col2 = st.columns([3, 1])
            with col2:
                if st.button("Export to Excel"):
                    filename = export_transactions_to_excel()
                    if filename:
                        with open(filename, "rb") as file:
                            st.download_button(
                                label="Download Excel",
                                data=file,
                                file_name=filename,
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                            )
            
            if transactions:
                st.markdown("### Recent Transactions")
                for t in transactions:
                    sender, receiver, amount, timestamp, tx_id, signature = t
                    
                    # Different styling for sent vs received
                    if sender == username:
                        st.markdown(f"""
                        <div style='border-left: 4px solid #ff4b4b; padding-left: 10px; margin-bottom: 10px;'>
                            <span class='transaction-sent'>Sent {amount:.3f} BTC</span> to <b>{receiver}</b><br>
                            <small>{timestamp} | TX: {tx_id[:8]}... | Sig: {signature}</small>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div style='border-left: 4px solid #4bb543; padding-left: 10px; margin-bottom: 10px;'>
                            <span class='transaction-received'>Received {amount:.3f} BTC</span> from <b>{sender}</b><br>
                            <small>{timestamp} | TX: {tx_id[:8]}... | Sig: {signature}</small>
                        </div>
                        """, unsafe_allow_html=True)
            else:
                st.info("No transactions found.")
        
        elif choice == "Export Transactions":
            st.subheader("Export All Transactions")
            
            st.write("This will export all blockchain transactions to an Excel file.")
            
            if st.button("Generate Excel Report"):
                filename = export_transactions_to_excel()
                if filename:
                    st.success("Excel file generated successfully!")
                    with open(filename, "rb") as file:
                        st.download_button(
                            label="Download Transaction Report",
                            data=file,
                            file_name=filename,
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            key="download"
                        )
                else:
                    st.error("Failed to generate Excel file.")
                    
            # Display a preview of the data
            transactions = get_all_transactions()
            if transactions:
                df = pd.DataFrame(transactions, columns=[
                    "Transaction ID", 
                    "Sender", 
                    "Receiver", 
                    "Amount (BTC)", 
                    "Timestamp", 
                    "Signature", 
                    "Status"
                ])
                df["Amount (BTC)"] = df["Amount (BTC)"].apply(lambda x: f"{x:.3f}")
                st.subheader("Transaction Preview")
                st.dataframe(df)
            else:
                st.info("No transactions available to export.")
        
        elif choice == "Security":
            st.subheader("Security Settings")
            
            st.markdown("### Session Information")
            st.info(f"Your session will automatically expire after {SESSION_TIMEOUT_MINUTES} minutes of inactivity.")
            
            st.markdown("### Security Recommendations")
            st.markdown("""
            - Never share your password with anyone
            - Use a unique password for your blockchain wallet
            - Enable two-factor authentication (coming soon)
            - Check the URL before logging in to avoid phishing attacks
            - Be cautious of suspicious emails or messages asking for your wallet information
            """)
            
            # Password change option
            st.markdown("### Change Password")
            current_password = st.text_input("Current Password", type="password", key="current_pwd")
            new_password = st.text_input("New Password", type="password", key="new_pwd")
            confirm_new_password = st.text_input("Confirm New Password", type="password", key="confirm_new_pwd")
            
            # Password strength indicator
            if new_password:
                is_strong = is_strong_password(new_password)
                if is_strong:
                    st.success("Strong password")
                else:
                    st.warning("Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters")
            
            if st.button("Change Password"):
                if new_password != confirm_new_password:
                    st.error("New passwords do not match!")
                elif not current_password:
                    st.error("Please enter your current password.")
                elif current_password == new_password:
                    st.error("New password must be different from current password.")
                else:
                    success, message = change_password(st.session_state.username, current_password, new_password)
                    if success:
                        st.success(message)
                        # Log the user out after password change
                        st.warning("You will be logged out for security reasons. Please log in with your new password.")
                        time.sleep(3)  # Give user time to read the message
                        logout_user()
                        st.rerun()
                    else:
                        st.error(message)

# Run the app
if __name__ == "__main__":
    main()
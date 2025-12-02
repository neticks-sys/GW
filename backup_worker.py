#!/usr/bin/env python3
"""
Neticks Backup Worker - Python Version
High-performance, concurrent backup processing for Google Workspace

Features:
- Concurrent job processing (multiple users at once)
- Automatic retry logic
- Incremental backup support (based on S3 logs)
- Full EML file backup (not just JSON)
- CloudWatch logging
- Graceful error handling
"""

import os
import sys
import json
import time
import logging
import traceback
import base64
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from email.utils import parsedate_to_datetime
from email import message_from_bytes
from email.message import EmailMessage

# AWS SDK
import boto3
from botocore.exceptions import ClientError, BotoCoreError

# Google API
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Cryptography (compatible with PHP openssl_decrypt)
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad

# HTTP requests for API calls
import requests

# Backup API client and file writers
from backup_api_client import BackupApiClient
from backup_file_writers import BackupLogWriter, BackupSqlWriter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] BACKUP WORKER: %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Configuration
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')
SQS_BACKUP_QUEUE_URL = os.getenv('SQS_BACKUP_QUEUE_URL', '')
SQS_INDEX_QUEUE_URL = os.getenv('SQS_INDEX_QUEUE_URL', '')
MAX_WORKERS = int(os.getenv('MAX_WORKERS', '3'))  # Process 3 jobs concurrently
POLL_WAIT_TIME = 20  # Long polling wait time
VISIBILITY_TIMEOUT = 43200  # 12 hours (maximum allowed by SQS) - for enterprise backups
VISIBILITY_EXTEND_INTERVAL = 3600  # Extend visibility every hour for long jobs

# Initialize AWS clients
# Use explicit credentials from environment variables if available, otherwise use default (IAM role)
aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')

if aws_access_key and aws_secret_key:
    # Use explicit credentials from environment variables
    sqs_client = boto3.client(
        'sqs',
        region_name=AWS_REGION,
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key
    )
    log_message(f"Using explicit AWS credentials for SQS (from environment variables)")
else:
    # Fall back to default credentials (IAM role or ~/.aws/credentials)
    sqs_client = boto3.client('sqs', region_name=AWS_REGION)
    log_message(f"Using default AWS credentials for SQS (IAM role or local credentials)")

def log_message(message: str, level: str = 'INFO'):
    """Log message with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] BACKUP WORKER: {message}"
    
    if level == 'ERROR':
        logger.error(log_msg)
    elif level == 'WARNING':
        logger.warning(log_msg)
    else:
        logger.info(log_msg)
    
    print(log_msg)
    sys.stdout.flush()

def decrypt_credentials(encrypted_data: str, instance_id: str) -> str:
    """
    Decrypt credentials using EXACT same method as PHP openssl_decrypt
    This matches the old PHP worker that was working perfectly.
    
    PHP code (from backup_functions_cli.php):
        $encryptionKey = hash('sha256', $instance_id . 'neticks_encryption_key_2024');
        $iv = substr(hash('sha256', $instance_id), 0, 16);
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $encryptionKey, 0, $iv);
    
    After extensive testing: PHP's openssl_decrypt with hex string key/IV uses them as ASCII bytes.
    However, if that fails, PHP might be doing hex2bin conversion. Let's try both methods.
    """
    if not encrypted_data:
        return ""
    
    # Generate hex strings (EXACT PHP match)
    encryption_key_hex = hashlib.sha256(
        f"{instance_id}neticks_encryption_key_2024".encode('utf-8')
    ).hexdigest()  # 64-char hex string
    
    iv_hex = hashlib.sha256(instance_id.encode('utf-8')).hexdigest()[:16]  # 16-char hex string
    
    encrypted_bytes = base64.b64decode(encrypted_data)
    
    # Try Method 1: Hex string as ASCII bytes (most likely)
    try:
        encryption_key = encryption_key_hex[:32].encode('utf-8')  # First 32 hex chars as ASCII
        iv = iv_hex.encode('utf-8')  # 16 hex chars as ASCII
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        decrypted = unpad(decrypted_padded, AES.block_size)
        return decrypted.decode('utf-8')
    except ValueError:
        # Try Method 2: Hex to binary conversion (hex2bin)
        # Key: 64 hex → 32 bytes
        # IV: Need 16 bytes, but only have 16 hex chars = 8 bytes
        # So repeat/pad IV: use 32 hex chars to get 16 bytes
        try:
            encryption_key = bytes.fromhex(encryption_key_hex)  # 64 hex → 32 bytes
            iv_hex_32 = hashlib.sha256(instance_id.encode('utf-8')).hexdigest()[:32]  # 32 hex chars
            iv = bytes.fromhex(iv_hex_32)  # 32 hex → 16 bytes
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_bytes)
            decrypted = unpad(decrypted_padded, AES.block_size)
            return decrypted.decode('utf-8')
        except ValueError:
            # Try Method 3: Raw binary hash (if PHP uses hash with raw_output=true equivalent)
            encryption_key = hashlib.sha256(
                f"{instance_id}neticks_encryption_key_2024".encode('utf-8')
            ).digest()  # 32 bytes directly
            iv = hashlib.sha256(instance_id.encode('utf-8')).digest()[:16]  # First 16 bytes
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_bytes)
            decrypted = unpad(decrypted_padded, AES.block_size)
            return decrypted.decode('utf-8')

def decrypt_s3_credentials(instance: Dict[str, Any]) -> Dict[str, str]:
    """Decrypt S3 credentials from instance data"""
    instance_id = instance.get('instance_id', '')
    
    encrypted_access_key = instance.get('s3_access_key', '')
    encrypted_secret_key = instance.get('s3_secret_key', '')
    
    access_key = decrypt_credentials(encrypted_access_key, instance_id)
    secret_key = decrypt_credentials(encrypted_secret_key, instance_id)
    
    return {
        'access_key': access_key,
        'secret_key': secret_key,
        'bucket': instance.get('s3_bucket', ''),
        'region': instance.get('s3_region', AWS_REGION)
    }

def decrypt_google_credentials(instance: Dict[str, Any]) -> Dict[str, Any]:
    """Decrypt Google service account key from instance data"""
    instance_id = instance.get('instance_id', '')
    encrypted_key = instance.get('google_service_account_key', '')
    
    decrypted_json = decrypt_credentials(encrypted_key, instance_id)
    return json.loads(decrypted_json)

def get_s3_client(s3_config: Dict[str, str]):
    """Create S3 client with decrypted credentials"""
    return boto3.client(
        's3',
        region_name=s3_config['region'],
        aws_access_key_id=s3_config['access_key'],
        aws_secret_access_key=s3_config['secret_key']
    )

def get_google_client(service_account_key: Dict[str, Any], user_email: str):
    """Initialize Google API client"""
    credentials = service_account.Credentials.from_service_account_info(
        service_account_key,
        scopes=[
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/drive.readonly',
            'https://www.googleapis.com/auth/calendar.readonly',
            'https://www.googleapis.com/auth/contacts.readonly',
            'https://www.googleapis.com/auth/admin.directory.user.readonly'
        ]
    )
    
    # Impersonate the user
    credentials = credentials.with_subject(user_email)
    
    return credentials

def backup_gmail(s3_client, gmail_service, user_email: str, s3_config: Dict, instance_id: str, 
                receipt_handle: Optional[str] = None, 
                sqs_client_instance=None, domain: str = '', account_id: str = '', session_id: str = '',
                is_incremental: bool = False, last_backup_info: Optional[Dict] = None, log_writer=None, sql_writer=None,
                api_client=None) -> List[Dict]:
    """Backup Gmail messages to S3 (FULL EML files) - NO LIMITS, can run for hours"""
    log_message(f"📧 ===== STARTING GMAIL BACKUP =====")
    log_message(f"📧 User: {user_email}")
    log_message(f"📧 Instance: {instance_id}")
    log_message(f"📧 Backup type: {'INCREMENTAL' if is_incremental else 'FULL'}")
    log_message(f"Starting Gmail backup for {user_email} - NO LIMITS, will process ALL messages")
    
    uploaded_resources = []
    batch_size = 500  # Increased batch size for efficiency
    total_messages = 0
    start_time = time.time()
    last_visibility_extend = time.time()
    
    # NEW STRATEGY for incremental backup: Use actual last backup timestamp + MySQL check
    # This ensures we only backup messages that are actually new (not already in MySQL)
    last_backup_timestamp = None
    if is_incremental and last_backup_info:
        last_backup_timestamp = last_backup_info.get('backup_timestamp', '')
        if last_backup_timestamp:
            log_message(f"🔄 INCREMENTAL BACKUP: Using last backup timestamp: {last_backup_timestamp}")
            log_message(f"🔄 Will fetch messages after last backup and check MySQL to see which are already backed up")
        else:
            log_message(f"⚠️ WARNING: Incremental backup but no timestamp found - will use 7-day window as fallback", 'WARNING')
    else:
        log_message(f"🆕 FULL BACKUP: Will fetch ALL messages from ALL labels (no date filter)")
    
    try:
        log_message(f"📧 Entering try block - starting message collection...")
        # Get all messages (NO LIMIT - processes millions if needed)
        # IMPORTANT: We need to iterate over main labels to get ALL messages
        # Gmail API doesn't support labelIds=['all'], so we query each label separately
        # Main labels to process: INBOX, SENT, DRAFT, TRASH, and ALL CATEGORIES (excluding SPAM)
        # IMPORTANT: All labels (INBOX, SENT, DRAFT, TRASH, and ALL CATEGORIES) are processed with the SAME incremental backup logic
        # - For incremental backup: Uses date filter (after:YYYY/MM/DD) based on last backup timestamp
        # - For full backup: No date filter, processes ALL messages
        # - All labels are checked against MySQL to skip already backed up messages
        # INBOX is treated exactly the same as SENT, DRAFT, TRASH, and all categories for incremental backups
        # NOTE: ALL CATEGORIES are included to ensure no emails are missed:
        # - CATEGORY_PROMOTIONS: Google Payments and promotional emails
        # - CATEGORY_UPDATES: Google billing invoices and important update emails
        # - CATEGORY_PERSONAL: Personal emails
        # - CATEGORY_SOCIAL: Social media notifications
        # - CATEGORY_FORUMS: Forum notifications
        main_labels = ['INBOX', 'SENT', 'DRAFT', 'TRASH', 'CATEGORY_PROMOTIONS', 'CATEGORY_UPDATES', 'CATEGORY_PERSONAL', 'CATEGORY_SOCIAL', 'CATEGORY_FORUMS']
        
        log_message(f"📧 Will process these main labels: {', '.join(main_labels)}")
        log_message(f"📧 INCREMENTAL BACKUP: All labels (INBOX, SENT, DRAFT, TRASH, and ALL CATEGORIES) use the same incremental logic")
        log_message(f"📧 - Date filter: Based on last backup timestamp (applied to ALL labels)")
        log_message(f"📧 - MySQL check: All labels checked against backup_GW_emails table")
        log_message(f"📧 - INBOX backup: Same incremental behavior as SENT, DRAFT, TRASH, and all categories")
        log_message(f"📧 - ALL CATEGORIES included: CATEGORY_PROMOTIONS, CATEGORY_UPDATES, CATEGORY_PERSONAL, CATEGORY_SOCIAL, CATEGORY_FORUMS")
            
        # Get all user labels to include custom labels
        try:
            labels_response = gmail_service.users().labels().list(userId='me').execute()
            user_labels = labels_response.get('labels', [])
            # Add custom labels (exclude only non-category system labels)
            # NOTE: ALL CATEGORIES are kept in main_labels and NOT excluded here:
            # - CATEGORY_PROMOTIONS: Google Payments and promotional emails
            # - CATEGORY_UPDATES: Google billing invoices and important update emails
            # - CATEGORY_PERSONAL: Personal emails
            # - CATEGORY_SOCIAL: Social media notifications
            # - CATEGORY_FORUMS: Forum notifications
            system_labels = {'UNREAD', 'STARRED', 'IMPORTANT', 'SPAM', 'TRASH', 'INBOX', 'SENT', 'DRAFT'}
            for label in user_labels:
                label_id = label.get('id', '')
                if label_id and label_id not in system_labels and label_id not in main_labels:
                    main_labels.append(label_id)
            log_message(f"📧 Found {len(main_labels)} labels to process: {', '.join(main_labels[:10])}{'...' if len(main_labels) > 10 else ''}")
        except Exception as e:
            log_message(f"⚠️ WARNING: Could not fetch user labels, using default labels only: {str(e)}", 'WARNING')
            # Continue with default labels
        
        # Process each label separately and collect ALL messages
        all_messages = {}  # Use dict to avoid duplicates (message_id as key)
        
        log_message(f"📧 ===== STARTING MESSAGE COLLECTION =====")
        log_message(f"📧 Starting to collect messages from all labels...")
        log_message(f"📧 Total labels to process: {len(main_labels)}")
        log_message(f"📧 Labels list: {main_labels}")
        
        for label_index, label_id in enumerate(main_labels, 1):
            log_message(f"📧 ===== Processing label {label_index}/{len(main_labels)}: {label_id} =====")
            
            # Initialize counter for this label
            label_messages_count = 0
            
            # Build query parameters for this label
            request_params = {
                'userId': 'me',
                'maxResults': batch_size,
                'labelIds': [label_id]  # Query this specific label
            }
            
            # Build query - exclude SPAM, exclude Google Alerts, and add date filter for incremental
            # IMPORTANT: For FULL backup, NO date filter - fetch ALL messages (but still exclude Google Alerts)
            # For INCREMENTAL, use date filter to fetch only recent messages (NO S3 check - trust the date filter)
            # EFFICIENCY: We don't check S3 individually - too slow for large accounts (10,000+ users)
            query_parts = []
            
            # ALWAYS exclude Google Alerts/Notifications (not real user emails)
            # These are automated emails from Google that users don't need backed up
            google_alert_domains = [
                'noreply@google.com',
                'alerts-noreply@google.com',
                'no-reply@google.com',
                'accounts-noreply@google.com',
                'mail-noreply@google.com',
                'notification-noreply@google.com'
            ]
            for domain in google_alert_domains:
                query_parts.append(f'-from:{domain}')
            
            # For incremental backup: add date filter based on ACTUAL last backup timestamp
            if is_incremental and last_backup_timestamp:
                try:
                    # Parse last backup timestamp and convert to Gmail date format
                    from datetime import timedelta
                    backup_time = datetime.strptime(last_backup_timestamp, '%Y-%m-%d %H:%M:%S')
                    # Use last backup date (subtract 1 day for safety margin to catch edge cases)
                    date_filter = (backup_time - timedelta(days=1)).strftime('%Y/%m/%d')
                    query_parts.append(f'after:{date_filter}')
                    if label_index == 1:
                        log_message(f"📧 INCREMENTAL MODE: Using date filter 'after:{date_filter}' based on last backup: {last_backup_timestamp}")
                        log_message(f"📧 INCREMENTAL MODE: This date filter applies to ALL labels (INBOX, SENT, DRAFT, TRASH, and ALL CATEGORIES)")
                        log_message(f"📧 INCREMENTAL MODE: This date filter applies to ALL labels (INBOX, SENT, DRAFT, TRASH, and ALL CATEGORIES)")
                except Exception as e:
                    # Fallback to 7-day window if timestamp parsing fails
                    from datetime import timedelta
                    date_7_days_ago = (datetime.now() - timedelta(days=7)).strftime('%Y/%m/%d')
                    query_parts.append(f'after:{date_7_days_ago}')
                    if label_index == 1:
                        log_message(f"⚠️ WARNING: Could not parse last backup timestamp, using 7-day fallback: {str(e)}", 'WARNING')
            elif is_incremental:
                # Fallback: no timestamp available, use 7-day window
                from datetime import timedelta
                date_7_days_ago = (datetime.now() - timedelta(days=7)).strftime('%Y/%m/%d')
                query_parts.append(f'after:{date_7_days_ago}')
                if label_index == 1:
                    log_message(f"⚠️ WARNING: No last backup timestamp available, using 7-day fallback window", 'WARNING')
            else:
                if label_index == 1:
                    log_message(f"📧 FULL BACKUP MODE: NO date filter - will fetch ALL real emails (excluding Google Alerts)")
                # No date filter for full backup - fetch everything (except Google Alerts)
            
            # Combine query parts
            if query_parts:
                request_params['q'] = ' '.join(query_parts)
                if label_index == 1:
                    log_message(f"📧 Applied query filter: {request_params['q']}")
                    log_message(f"📧 Filter excludes: Google Alerts/Notifications (noreply@google.com, etc.)")
            else:
                if label_index == 1:
                    log_message(f"📧 No query filter applied - fetching ALL messages")
            
            # Fetch messages for this label with FULL pagination (NO LIMIT)
            label_page_token = None
            
            while True:
                # Extend visibility timeout for long-running jobs
                if receipt_handle and sqs_client_instance and (time.time() - last_visibility_extend) >= VISIBILITY_EXTEND_INTERVAL:
                    try:
                        sqs_client_instance.change_message_visibility(
                            QueueUrl=SQS_BACKUP_QUEUE_URL,
                            ReceiptHandle=receipt_handle,
                            VisibilityTimeout=VISIBILITY_TIMEOUT
                        )
                        elapsed_hours = (time.time() - start_time) / 3600
                        log_message(f"Extended visibility timeout. Backup running for {elapsed_hours:.2f} hours. Collected {len(all_messages)} messages so far...")
                        last_visibility_extend = time.time()
                    except Exception as e:
                        log_message(f"Warning: Could not extend visibility timeout: {str(e)}", 'WARNING')
                
                if label_page_token:
                    request_params['pageToken'] = label_page_token
                else:
                    request_params.pop('pageToken', None)
                
                # Retry logic for API rate limits
                max_retries = 5
                retry_count = 0
                response = None
                
                while retry_count < max_retries:
                    try:
                        log_message(f"📧 Calling Gmail API: messages().list() for label {label_id} (pageToken: {label_page_token is not None})")
                        response = gmail_service.users().messages().list(**request_params).execute()
                        log_message(f"📧 Gmail API response received for label {label_id}")
                        break
                    except HttpError as e:
                        if e.resp.status == 429:  # Rate limit
                            retry_count += 1
                            wait_time = (2 ** retry_count) * 60  # Exponential backoff
                            log_message(f"Rate limit hit for label {label_id}. Waiting {wait_time}s...", 'WARNING')
                            time.sleep(wait_time)
                        else:
                            raise
                    except Exception as e:
                        log_message(f"Error listing messages for label {label_id}: {str(e)}", 'ERROR')
                        break  # Skip this label if error
                
                if not response:
                    log_message(f"⚠️ No response from Gmail API for label {label_id} - skipping this label", 'WARNING')
                    break  # Skip this label if failed
                
                label_messages = response.get('messages', [])
                if not label_messages:
                    if label_page_token is None:  # First page, no messages at all
                        log_message(f"📧 No messages found in label: {label_id} (first page empty)")
                    # Break pagination loop if no messages
                    break
                
                # Add messages to dict (avoid duplicates)
                for msg in label_messages:
                    all_messages[msg['id']] = msg
                
                label_messages_count += len(label_messages)
                
                # Log progress for this label
                if label_messages_count % 100 == 0:
                    log_message(f"📧 Collected {label_messages_count} messages from label {label_id} so far... (Total unique across all labels: {len(all_messages)})")
                
                # Check for next page
                label_page_token = response.get('nextPageToken')
                if not label_page_token:
                    break
            
            if label_messages_count > 0:
                log_message(f"📧 ✓ Collected {label_messages_count} messages from label: {label_id} (Total unique across all labels: {len(all_messages)})")
                if is_incremental:
                    log_message(f"📧 ✓ INCREMENTAL: {label_id} label processed with date filter (same as other labels including all categories)")
            else:
                log_message(f"📧 No messages found in label: {label_id}")
                if is_incremental:
                    log_message(f"📧 ✓ INCREMENTAL: {label_id} label checked (no new messages after last backup date)")
        
        # Convert dict to list - ALL messages from ALL labels
        messages = list(all_messages.values())
        
        log_message(f"📧 Collection complete. Total unique messages collected: {len(messages)}")
        
        if not messages:
            if is_incremental:
                log_message(f"⚠️ WARNING: No messages found after last backup date (excluding SPAM)", 'WARNING')
                log_message(f"⚠️ This might indicate: 1) All messages are older than last backup, 2) Filter issue, 3) No messages in account", 'WARNING')
            else:
                log_message(f"⚠️ WARNING: No messages found (excluding SPAM)", 'WARNING')
                log_message(f"⚠️ This might indicate: 1) Account has no messages, 2) API access issue, 3) Filter problem", 'WARNING')
            return uploaded_resources
        
        # For incremental backup: Check MySQL to see which messages are already backed up
        # IMPORTANT: This check applies to ALL labels (INBOX, SENT, DRAFT, TRASH) - same logic for all
        if is_incremental and api_client:
            log_message(f"📧 Checking MySQL (backup_GW_emails) to see which of {len(messages)} messages are already backed up...")
            log_message(f"📧 INCREMENTAL: MySQL check applies to ALL labels (INBOX, SENT, DRAFT, TRASH) - same verification for all")
            message_ids = [msg['id'] for msg in messages]
            
            # Check in batches of 1000 (API limit)
            batch_size_check = 1000
            already_backed_up = set()
            new_messages = []
            
            for i in range(0, len(message_ids), batch_size_check):
                batch_ids = message_ids[i:i+batch_size_check]
                check_result = api_client.check_backed_up_items('emails', batch_ids)
                
                if check_result:
                    backed_up = check_result.get('backed_up_items', [])
                    new_items = check_result.get('new_items', [])
                    
                    # If new_items is empty but we have message_ids, calculate it ourselves
                    # This handles cases where the API doesn't return new_items correctly
                    if not new_items and len(batch_ids) > 0:
                        new_items = [msg_id for msg_id in batch_ids if msg_id not in backed_up]
                        log_message(f"📧 DEBUG: Calculated new_items from batch_ids: {len(new_items)} new items")
                    
                    already_backed_up.update(backed_up)
                    log_message(f"📧 Batch {i//batch_size_check + 1}: {len(backed_up)} already backed up, {len(new_items)} NEW (will be inserted into MySQL)")
                    if len(new_items) > 0 and i == 0:  # Log first batch's new items for debugging
                        log_message(f"📧 First batch NEW message IDs: {new_items[:5]}{'...' if len(new_items) > 5 else ''}")
                else:
                    log_message(f"⚠️ WARNING: Could not check backed up items for batch {i//batch_size_check + 1} - will process all", 'WARNING')
                    # If check fails, process all messages to be safe
                    already_backed_up = set()
                    break
            
            # Filter out already backed up messages
            if already_backed_up:
                new_messages = [msg for msg in messages if msg['id'] not in already_backed_up]
                log_message(f"📧 ✓ Filtered: {len(already_backed_up)} already backed up, {len(new_messages)} new messages to backup")
                if new_messages:
                    log_message(f"📧 ✓ NEW messages to process: {[msg['id'] for msg in new_messages[:5]]}{'...' if len(new_messages) > 5 else ''}")
                messages = new_messages
            else:
                log_message(f"📧 ✓ All {len(messages)} messages are new (or check failed - processing all for safety)")
        
        if not messages:
            log_message(f"📧 ✓ All messages are already backed up - nothing to do!")
            return uploaded_resources
        
        log_message(f"📧 ✓✓✓ Collected {len(messages)} unique NEW messages from all labels. Starting to process ALL messages...")
        log_message(f"📧 IMPORTANT: These {len(messages)} messages will be uploaded to S3 AND inserted into MySQL backup_GW_emails table")
        log_message(f"📧 This may take a while for large accounts. Processing {len(messages)} messages...")
        log_message(f"📧 Labels processed: {', '.join(main_labels)}")
        
        # Process ALL collected messages - NO LIMIT, process everything
        processed_count = 0
        for msg_index, msg in enumerate(messages, 1):
            try:
                
                # Get raw message (EML format) - with retry
                max_get_retries = 3
                get_retry = 0
                message = None
                
                while get_retry < max_get_retries:
                    try:
                        message = gmail_service.users().messages().get(
                            userId='me',
                            id=msg['id'],
                            format='raw'
                        ).execute()
                        break
                    except HttpError as e:
                        if e.resp.status == 429:
                            get_retry += 1
                            wait_time = (2 ** get_retry) * 30
                            log_message(f"Rate limit getting message {msg['id']}. Waiting {wait_time}s...", 'WARNING')
                            time.sleep(wait_time)
                        else:
                            raise
                
                if not message:
                    log_message(f"Failed to get message {msg['id']} after retries", 'WARNING')
                    continue
                
                # Decode raw email (base64url encoded)
                raw_email = base64.urlsafe_b64decode(message['raw'] + '==')  # Add padding
                
                # Get full message metadata for MySQL insert and label extraction
                # We need this to extract labels for S3 folder organization
                message_metadata = None
                labels = []
                primary_label = 'INBOX'  # Default label if we can't get metadata
                
                try:
                    message_metadata = gmail_service.users().messages().get(
                        userId='me',
                        id=msg['id'],
                        format='full'
                    ).execute()
                    
                    # Extract primary label/folder from message labels
                    # Priority: INBOX > SENT > DRAFT > TRASH > other labels
                    # This determines which S3 folder the email goes into
                    labels = message_metadata.get('labelIds', [])
                    
                except Exception as e:
                    log_message(f"⚠️ WARNING: Could not get full metadata for message {msg['id']}: {str(e)}", 'WARNING')
                    log_message(f"⚠️ Will use default label 'INBOX' and continue backup", 'WARNING')
                    # Continue with default label - we'll still backup the message
                    # We just won't have full metadata for MySQL
                    # IMPORTANT: Without message_metadata, we cannot insert into MySQL
                    # So we need to try again or skip MySQL insert for this message
                    log_message(f"⚠️ CRITICAL: Message {msg['id']} uploaded to S3 but will NOT be inserted into MySQL (no metadata)", 'WARNING')
                
                # Extract primary label from labels (if we got metadata)
                if labels:
                    if 'INBOX' in labels:
                        primary_label = 'INBOX'
                    elif 'SENT' in labels:
                        primary_label = 'SENT'
                    elif 'DRAFT' in labels:
                        primary_label = 'DRAFT'
                    elif 'TRASH' in labels:
                        primary_label = 'TRASH'
                    elif 'SPAM' in labels:
                        # Should not happen due to query filter, but handle just in case
                        log_message(f"Skipping message {msg['id']} - marked as SPAM (should have been filtered)", 'INFO')
                        continue
                    else:
                        # Use first non-system label, or create a generic folder
                        # Filter out system labels
                        system_labels = {'UNREAD', 'STARRED', 'IMPORTANT', 'SPAM', 'TRASH', 'INBOX', 'SENT', 'DRAFT'}
                        # NOTE: ALL CATEGORIES are kept and NOT excluded:
                        # - CATEGORY_PROMOTIONS: Google Payments and promotional emails
                        # - CATEGORY_UPDATES: Google billing invoices and important update emails
                        # - CATEGORY_PERSONAL: Personal emails
                        # - CATEGORY_SOCIAL: Social media notifications
                        # - CATEGORY_FORUMS: Forum notifications
                        custom_labels = [l for l in labels if l not in system_labels]
                        if custom_labels:
                            # Use first custom label, sanitize for S3 path
                            primary_label = custom_labels[0].replace('/', '_').replace('\\', '_')
                        else:
                            # No custom labels, use first label (sanitized)
                            primary_label = labels[0].replace('/', '_').replace('\\', '_')
                
                # Upload to S3
                # Structure: emails/{user_email}/{label}/{date}/{message_id}.eml
                # This organizes emails by label/folder in S3
                backup_date = datetime.now()
                # Sanitize user_email and label for S3 path
                safe_user_email = user_email.replace('@', '_at_')
                safe_label = primary_label.replace('/', '_').replace('\\', '_').replace(' ', '_')
                s3_key = f"backups/{instance_id}/emails/{safe_user_email}/{safe_label}/{backup_date.strftime('%Y/%m')}/{msg['id']}.eml"
                
                # EFFICIENCY IMPROVEMENT: We NO LONGER check S3 individually for incremental backups
                # This was too slow for large accounts (10,000+ users with thousands of emails)
                # Instead, we trust the Gmail API date filter (after:YYYY/MM/DD) to only return new messages
                # The date filter is much more efficient than millions of S3 HEAD requests
                # For full backups, we process everything (no check needed)
                
                # Upload to S3
                try:
                    s3_client.put_object(
                        Bucket=s3_config['bucket'],
                        Key=s3_key,
                        Body=raw_email,
                        ContentType='message/rfc822',
                        Metadata={
                            'message_id': msg['id'],
                            'user_email': user_email,
                            'label': primary_label,
                            'backup_date': backup_date.isoformat()
                        }
                    )
                    log_message(f"✓ Uploaded message {msg['id']} to S3: {s3_key} (label: {primary_label})", 'INFO')
                except Exception as e:
                    log_message(f"❌ ERROR uploading message {msg['id']} to S3: {str(e)}", 'ERROR')
                    log_message(traceback.format_exc(), 'ERROR')
                    continue  # Skip this message if S3 upload fails
                
                # Extract and save attachments individually to S3
                # This allows downloading attachments separately for visualization
                # Initialize attachments_metadata BEFORE the try block so it's always defined
                attachments_metadata = []
                if message_metadata:
                    try:
                        # Parse the EML to extract attachments
                        email_msg = message_from_bytes(raw_email)
                        
                        # Extract attachments from the email message
                        attachment_index = 0
                        for part in email_msg.walk():
                            # Check if this part is an attachment
                            content_disposition = part.get("Content-Disposition", "")
                            if "attachment" in content_disposition or (part.get_content_maintype() != 'text' and part.get_content_maintype() != 'multipart' and part.get_filename()):
                                attachment_filename = part.get_filename()
                                if attachment_filename:
                                    # Decode filename if it's encoded
                                    try:
                                        from email.header import decode_header
                                        decoded_parts = decode_header(attachment_filename)
                                        decoded_filename = ''
                                        for part_bytes, encoding in decoded_parts:
                                            if isinstance(part_bytes, bytes):
                                                decoded_filename += part_bytes.decode(encoding or 'utf-8', errors='ignore')
                                            else:
                                                decoded_filename += part_bytes
                                        attachment_filename = decoded_filename
                                    except:
                                        pass
                                    
                                    # Get attachment content
                                    attachment_content = part.get_payload(decode=True)
                                    if attachment_content:
                                        attachment_index += 1
                                        
                                        # Sanitize filename for S3
                                        safe_attachment_filename = attachment_filename.replace('/', '_').replace('\\', '_').replace(' ', '_')
                                        
                                        # Create S3 key for attachment
                                        # Structure: emails/{user_email}/{label}/{date}/{message_id}/attachments/{attachment_filename}
                                        attachment_s3_key = f"backups/{instance_id}/emails/{safe_user_email}/{safe_label}/{backup_date.strftime('%Y/%m')}/{msg['id']}/attachments/{safe_attachment_filename}"
                                        
                                        # Upload attachment to S3
                                        try:
                                            attachment_content_type = part.get_content_type() or 'application/octet-stream'
                                            s3_client.put_object(
                                                Bucket=s3_config['bucket'],
                                                Key=attachment_s3_key,
                                                Body=attachment_content,
                                                ContentType=attachment_content_type,
                                                Metadata={
                                                    'message_id': msg['id'],
                                                    'attachment_filename': attachment_filename,
                                                    'user_email': user_email,
                                                    'label': primary_label,
                                                    'backup_date': backup_date.isoformat()
                                                }
                                            )
                                            
                                            # Store attachment metadata for MySQL
                                            attachments_metadata.append({
                                                'filename': attachment_filename,
                                                's3_key': attachment_s3_key,
                                                'content_type': attachment_content_type,
                                                'size': len(attachment_content),
                                                'attachment_index': attachment_index
                                            })
                                            
                                            log_message(f"📎 Uploaded attachment {attachment_index}: {attachment_filename} ({len(attachment_content)} bytes) to S3: {attachment_s3_key}", 'INFO')
                                        except Exception as e:
                                            log_message(f"⚠️ WARNING: Could not upload attachment {attachment_filename}: {str(e)}", 'WARNING')
                                            # Continue with other attachments
                    except Exception as e:
                        log_message(f"⚠️ WARNING: Could not extract attachments from message {msg['id']}: {str(e)}", 'WARNING')
                        # Continue with email metadata even if attachment extraction fails
                
                # Extract and send email metadata to MySQL via API
                # CRITICAL: message_metadata is REQUIRED for MySQL insert
                if not message_metadata:
                    log_message(f"❌ ERROR: Cannot insert message {msg['id']} into MySQL - message_metadata is None (uploaded to S3 but not in MySQL)", 'ERROR')
                    # Try to get metadata one more time as fallback
                    try:
                        message_metadata = gmail_service.users().messages().get(
                            userId='me',
                            id=msg['id'],
                            format='full'
                        ).execute()
                        log_message(f"✓ Retry successful - got metadata for message {msg['id']}", 'INFO')
                    except Exception as e2:
                        log_message(f"❌ Retry failed - message {msg['id']} will NOT be in MySQL: {str(e2)}", 'ERROR')
                        # Continue to next message - this one is uploaded to S3 but not in MySQL
                        continue
                
                if message_metadata and sql_writer:
                    try:
                        # Log that we're processing this message for SQL insert
                        if is_incremental:
                            if total_messages % 100 == 0:
                                log_message(f"📧 Processing message {msg['id']} for SQL insert (incremental mode)")
                            elif total_messages <= 10:  # Log first 10 for debugging
                                log_message(f"📧 Processing message {msg['id']} for SQL insert - WILL BE INSERTED INTO MySQL")
                        # Extract headers
                        headers = {h['name']: h['value'] for h in message_metadata.get('payload', {}).get('headers', [])}
                        
                        # Extract email fields
                        subject = headers.get('Subject', '')
                        from_addr = headers.get('From', '')
                        to_addrs = headers.get('To', '')
                        cc_addrs = headers.get('Cc', '')
                        bcc_addrs = headers.get('Bcc', '')
                        
                        # Additional safety filter: Skip Google Alerts if they somehow passed the query filter
                        # This is a safety net in case the query filter didn't catch all Google Alerts
                        # The query filter should catch most, but this ensures 100% exclusion
                        if from_addr:
                            from_lower = from_addr.lower()
                            google_alert_patterns = ['noreply@google.com', 'alerts-noreply@google.com', 'no-reply@google.com', 
                                                    'accounts-noreply@google.com', 'mail-noreply@google.com', 'notification-noreply@google.com']
                            if any(pattern in from_lower for pattern in google_alert_patterns):
                                # Skip silently (query filter should have caught this, but just in case)
                                continue
                        
                        # Extract dates
                        date_sent_str = headers.get('Date', '')
                        date_received = None
                        date_sent = None
                        if date_sent_str:
                            try:
                                date_sent = parsedate_to_datetime(date_sent_str)
                            except:
                                pass
                        
                        # Use internal date if available
                        if message_metadata.get('internalDate'):
                            try:
                                date_received = datetime.fromtimestamp(int(message_metadata['internalDate']) / 1000)
                            except:
                                pass
                        
                        # Extract attachment info (use actual extracted attachments if available)
                        if attachments_metadata:
                            has_attachments = 1
                            attachment_count = len(attachments_metadata)
                        else:
                            # Fallback: count from payload structure
                            payload = message_metadata.get('payload', {})
                            has_attachments = 0
                            attachment_count = 0
                            if payload.get('parts'):
                                for part in payload['parts']:
                                    if part.get('filename'):
                                        attachment_count += 1
                                    if part.get('parts'):
                                        for subpart in part['parts']:
                                            if subpart.get('filename'):
                                                attachment_count += 1
                            if attachment_count > 0:
                                has_attachments = 1
                        
                        # Store attachments JSON for MySQL (list of attachment metadata)
                        attachments_json = json.dumps(attachments_metadata) if attachments_metadata else '[]'
                        
                        # Get file size
                        file_size = len(raw_email)
                        
                        # Build SQL VALUES clause
                        # Escape single quotes in strings
                        def escape_sql(s):
                            if s is None:
                                return 'NULL'
                            s_str = str(s)
                            # Escape single quotes and backslashes
                            s_str = s_str.replace("\\", "\\\\").replace("'", "''")
                            return "'" + s_str + "'"
                        
                        # Format dates for SQL
                        date_sent_sql = f"'{date_sent.strftime('%Y-%m-%d %H:%M:%S')}'" if date_sent else 'NULL'
                        date_received_sql = f"'{date_received.strftime('%Y-%m-%d %H:%M:%S')}'" if date_received else 'NULL'
                        backup_date_sql = f"'{backup_date.strftime('%Y-%m-%d %H:%M:%S')}'"
                        
                        # Extract primary label (already determined above)
                        # Store all labels as JSON for reference
                        labels_json = json.dumps(labels) if labels else '[]'
                        
                        # Build SQL VALUES with label fields and attachments_json
                        # Note: If database doesn't have label/labels_json/attachments_json columns yet, this will fail
                        # The error will be caught and logged by the API endpoint
                        values_sql = f"({escape_sql(instance_id)}, {escape_sql(domain)}, {escape_sql(account_id)}, {escape_sql('google_workspace')}, {escape_sql(session_id)}, {escape_sql(msg['id'])}, {escape_sql(message_metadata.get('threadId'))}, {escape_sql(subject)}, {escape_sql(from_addr)}, {escape_sql(to_addrs)}, {escape_sql(cc_addrs)}, {escape_sql(bcc_addrs)}, {date_sent_sql}, {date_received_sql}, {escape_sql(s3_key)}, NULL, {file_size}, {escape_sql('message/rfc822')}, {has_attachments}, {attachment_count}, {escape_sql(primary_label)}, {escape_sql(labels_json)}, {escape_sql(attachments_json)}, {backup_date_sql})"
                        
                        # Add to batch
                        sql_writer.add_insert('backup_GW_emails', values_sql)
                        if is_incremental:
                            if total_messages % 100 == 0:
                                log_message(f"✓ Added message {msg['id']} to SQL batch (incremental backup)")
                            elif total_messages <= 10:  # Log first 10 messages for debugging
                                log_message(f"✓ Added message {msg['id']} to SQL batch - will be inserted into MySQL backup_GW_emails table")
                        
                        # Insert individual attachments into backup_GW_email_attachments table
                        if attachments_metadata and sql_writer:
                            for att in attachments_metadata:
                                try:
                                    attachment_values_sql = f"({escape_sql(instance_id)}, {escape_sql(domain)}, {escape_sql(account_id)}, {escape_sql('google_workspace')}, {escape_sql(session_id)}, {escape_sql(msg['id'])}, {att['attachment_index']}, {escape_sql(att['filename'])}, {escape_sql(att['s3_key'])}, {escape_sql(att['content_type'])}, {att['size']}, {backup_date_sql})"
                                    sql_writer.add_insert('backup_GW_email_attachments', attachment_values_sql)
                                except Exception as e:
                                    log_message(f"⚠️ WARNING: Could not add attachment {att.get('filename', 'unknown')} to SQL batch: {str(e)}", 'WARNING')
                        
                    except Exception as e:
                            error_msg = str(e)
                            log_message(f"❌ ERROR: Could not extract email metadata for {msg['id']}: {error_msg}", 'ERROR')
                            # Check if it's a schema error
                            if 'Unknown column' in error_msg or 'label' in error_msg.lower():
                                log_message(f"❌ CRITICAL: Database schema error detected. Please run SQL ALTER statement to add label and labels_json columns to backup_GW_emails table.", 'ERROR')
                            log_message(traceback.format_exc(), 'ERROR')
                            # Don't skip the message - it's already uploaded to S3, just log the error
                    
                # Add to uploaded resources list
                uploaded_resources.append({
                    'type': 'email',
                    's3_key': s3_key,
                    'resource_id': msg['id'],
                    'operation': 'upsert',
                    'metadata': {
                        'user_email': user_email,
                        'label': primary_label,
                        'backup_date': backup_date.isoformat()
                    }
                })
                
                total_messages += 1
                processed_count += 1
                
                # Progress updates every 50 messages (more frequent for visibility)
                if total_messages % 50 == 0 or msg_index == len(messages):
                    elapsed_hours = (time.time() - start_time) / 3600
                    progress_pct = (msg_index / len(messages) * 100) if messages else 0
                    log_message(f"📧 Progress: {total_messages} messages backed up ({msg_index}/{len(messages)} = {progress_pct:.1f}%) in {elapsed_hours:.2f} hours... (current label: {primary_label})")
            
            except Exception as e:
                    error_msg = str(e)
                    log_message(f"❌ ERROR backing up message {msg['id']}: {error_msg}", 'ERROR')
                    log_message(traceback.format_exc(), 'ERROR')
                    # Continue with next message instead of stopping entire backup
                    continue
        
        elapsed_hours = (time.time() - start_time) / 3600
        if total_messages > 0:
            log_message(f"✅ Gmail backup completed: {total_messages} messages backed up in {elapsed_hours:.2f} hours")
            
            # CRITICAL: Flush remaining SQL batches for emails to ensure all records are inserted into MySQL
            if sql_writer:
                log_message(f"🔄 Flushing remaining SQL batches for emails to ensure all records are inserted into MySQL...")
                try:
                    sql_writer.flush_table('backup_GW_emails')
                    sql_writer.flush_table('backup_GW_email_attachments')
                    log_message(f"✓ Email SQL batches flushed successfully - all {total_messages} emails should now be in MySQL")
                except Exception as e:
                    log_message(f"❌ ERROR flushing email SQL batches: {str(e)}", 'ERROR')
                    import traceback
                    log_message(traceback.format_exc(), 'ERROR')
        else:
            log_message(f"⚠️ WARNING: Gmail backup completed but NO messages were backed up (0 messages)", 'WARNING')
            log_message(f"⚠️ This might indicate an issue with the Gmail API query or message retrieval", 'WARNING')
        return uploaded_resources
        
    except Exception as e:
        elapsed_hours = (time.time() - start_time) / 3600
        log_message(f"❌❌❌ Gmail backup EXCEPTION after {elapsed_hours:.2f} hours and {total_messages} messages: {str(e)}", 'ERROR')
        log_message(f"❌ Exception type: {type(e).__name__}", 'ERROR')
        log_message(traceback.format_exc(), 'ERROR')
        log_message(f"❌ This exception prevented message collection. Check the traceback above.", 'ERROR')
        
        # CRITICAL: Flush remaining SQL batches even if exception occurred
        # This ensures any emails that were processed before the exception are still inserted into MySQL
        if sql_writer and total_messages > 0:
            log_message(f"🔄 Flushing remaining SQL batches after exception to ensure processed emails are inserted into MySQL...")
            try:
                sql_writer.flush_table('backup_GW_emails')
                sql_writer.flush_table('backup_GW_email_attachments')
                log_message(f"✓ Email SQL batches flushed after exception - {total_messages} emails should now be in MySQL")
            except Exception as flush_error:
                log_message(f"❌ ERROR flushing email SQL batches after exception: {str(flush_error)}", 'ERROR')
        
        return uploaded_resources

def backup_drive(s3_client, drive_service, user_email: str, s3_config: Dict, instance_id: str, 
                receipt_handle: Optional[str] = None, 
                sqs_client_instance=None, domain: str = '', account_id: str = '', session_id: str = '',
                is_incremental: bool = False, last_backup_info: Optional[Dict] = None, log_writer=None, sql_writer=None,
                api_client=None) -> List[Dict]:
    """Backup Google Drive files to S3 - NO LIMITS, can run for hours"""
    log_message(f"Starting Drive backup for {user_email} - NO LIMITS, will process ALL files")
    
    uploaded_resources = []
    total_files = 0
    start_time = time.time()
    last_visibility_extend = time.time()
    
            # Build Drive query for incremental backup (timestamp-based filtering)
    drive_query = None
    if is_incremental and last_backup_info:
        try:
            backup_timestamp_str = last_backup_info.get('backup_timestamp', '')
            if backup_timestamp_str:
                # Parse timestamp and convert to RFC 3339 format for Drive API
                backup_time = datetime.strptime(backup_timestamp_str, '%Y-%m-%d %H:%M:%S')
                # Drive API uses RFC 3339 format: YYYY-MM-DDTHH:MM:SSZ
                drive_timestamp = backup_time.strftime('%Y-%m-%dT%H:%M:%SZ')
                # IMPORTANT: Check BOTH modifiedTime AND createdTime to catch:
                # 1. Files modified after last backup
                # 2. New files created after last backup
                drive_query = f"(modifiedTime > '{drive_timestamp}' or createdTime > '{drive_timestamp}')"
                log_message(f"🔄 INCREMENTAL: Using Drive query filter to fetch files modified OR created after {drive_timestamp}")
                log_message(f"🔄 Drive incremental backup will process files modified/created after: {backup_timestamp_str}")
        except Exception as e:
            log_message(f"Warning: Could not parse backup timestamp for Drive filter: {str(e)}", 'WARNING')
            # Fall back to S3 checking if timestamp parsing fails
    
    try:
        log_message(f"📁 ===== STARTING DRIVE BACKUP =====")
        log_message(f"📁 User: {user_email}")
        log_message(f"📁 Instance: {instance_id}")
        log_message(f"📁 Backup type: {'INCREMENTAL' if is_incremental else 'FULL'}")
        log_message(f"📁 Will backup ALL files from ALL folders (recursive)")
        log_message(f"📁 Folder structure will be preserved in S3 and MySQL")
        
        # First pass: Collect all folders to build folder path mapping
        log_message(f"📁 Step 1: Collecting all folders to build folder structure...")
        folders_map = {}  # folder_id -> folder_name
        folders_parents = {}  # folder_id -> parent_folder_id
        page_token = None
        
        while True:
            try:
                request_params = {
                    'pageSize': 1000,
                    'fields': 'nextPageToken, files(id, name, mimeType, parents)',
                    'q': "mimeType='application/vnd.google-apps.folder' and trashed=false",
                    'includeItemsFromAllDrives': True,
                    'supportsAllDrives': True,
                    'corpora': 'allDrives'
                }
                if page_token:
                    request_params['pageToken'] = page_token
                
                response = drive_service.files().list(**request_params).execute()
                folders = response.get('files', [])
                
                for folder in folders:
                    folder_id = folder['id']
                    folder_name = folder.get('name', folder_id)
                    parents = folder.get('parents', [])
                    parent_id = parents[0] if parents else None
                    
                    folders_map[folder_id] = folder_name
                    folders_parents[folder_id] = parent_id
                
                page_token = response.get('nextPageToken')
                if not page_token:
                    break
            except Exception as e:
                log_message(f"⚠️ WARNING: Error collecting folders: {str(e)}", 'WARNING')
                break
        
        log_message(f"📁 Collected {len(folders_map)} folders for structure mapping")
        
        # Function to build full folder path
        def build_folder_path(file_parent_id):
            """Build full folder path from root to parent folder"""
            if not file_parent_id or file_parent_id not in folders_map:
                return ''  # Root level
            
            path_parts = []
            current_id = file_parent_id
            visited = set()  # Prevent infinite loops
            
            while current_id and current_id in folders_map and current_id not in visited:
                visited.add(current_id)
                path_parts.insert(0, folders_map[current_id])
                current_id = folders_parents.get(current_id)
            
            return '/'.join(path_parts)
        
        # Now collect all files first, then check MySQL for already backed up files
        log_message(f"📁 Step 2: Collecting all files from Drive...")
        all_files_list = []
        page_token = None
        
        while True:
            # Extend visibility timeout for long-running jobs
            if receipt_handle and sqs_client_instance and (time.time() - last_visibility_extend) >= VISIBILITY_EXTEND_INTERVAL:
                try:
                    sqs_client_instance.change_message_visibility(
                        QueueUrl=SQS_BACKUP_QUEUE_URL,
                        ReceiptHandle=receipt_handle,
                        VisibilityTimeout=VISIBILITY_TIMEOUT
                    )
                    elapsed_hours = (time.time() - start_time) / 3600
                    log_message(f"Extended visibility timeout. Backup running for {elapsed_hours:.2f} hours. Processed {total_files} files so far...")
                    last_visibility_extend = time.time()
                except Exception as e:
                    log_message(f"Warning: Could not extend visibility timeout: {str(e)}", 'WARNING')
            
            # List files - NO LIMIT on total count
            # IMPORTANT: This will fetch ALL files from ALL folders (recursive)
            # Google Drive API lists all files regardless of folder structure
            # Get all necessary metadata fields for MySQL insertion
            request_params = {
                'pageSize': 1000,
                'fields': 'nextPageToken, files(id, name, mimeType, size, modifiedTime, createdTime, parents, shared, starred, trashed, viewedByMeTime, fileExtension)',
                'includeItemsFromAllDrives': True,  # Include files from shared drives
                'supportsAllDrives': True,  # Support shared drives
                'corpora': 'allDrives'  # Search all drives (My Drive + Shared Drives)
            }
            if page_token:
                request_params['pageToken'] = page_token
            
            # Build query for incremental backups (timestamp-based)
            # IMPORTANT: For full backup, NO query filter - fetch ALL files from ALL folders
            # For incremental, use modifiedTime filter to fetch only modified files
            query_parts = []
            if drive_query:
                query_parts.append(drive_query)
            
            # ALWAYS exclude trashed files (we don't want to backup deleted files)
            query_parts.append("trashed=false")
            
            # Combine query parts
            if query_parts:
                request_params['q'] = ' and '.join(query_parts)
                if total_files == 0:
                    log_message(f"📁 Drive query filter: {request_params['q']}")
            else:
                if total_files == 0:
                    log_message(f"📁 FULL BACKUP: No query filter - will fetch ALL files from ALL folders (recursive)")
            
            # Retry logic for API rate limits
            max_retries = 5
            retry_count = 0
            response = None
            
            while retry_count < max_retries:
                try:
                    response = drive_service.files().list(**request_params).execute()
                    break
                except HttpError as e:
                    if e.resp.status == 429:  # Rate limit
                        retry_count += 1
                        wait_time = (2 ** retry_count) * 60
                        log_message(f"Rate limit hit. Waiting {wait_time} seconds before retry {retry_count}/{max_retries}...", 'WARNING')
                        time.sleep(wait_time)
                    else:
                        raise
                except Exception as e:
                    log_message(f"Error listing files: {str(e)}", 'ERROR')
                    raise
            
            if not response:
                log_message("Failed to get files after retries", 'ERROR')
                break
            
            files = response.get('files', [])
            
            if not files:
                break
            
            # Collect all files (including folders for metadata)
            all_files_list.extend(files)
            log_message(f"📁 Collected batch of {len(files)} items (Total so far: {len(all_files_list)})")
            
            page_token = response.get('nextPageToken')
            if not page_token:
                break
        
        log_message(f"📁 Collection complete. Total items collected: {len(all_files_list)}")
        
        # For incremental backup: Check MySQL to see which files are already backed up
        if is_incremental and api_client:
            log_message(f"📁 Checking MySQL to see which of {len(all_files_list)} files are already backed up...")
            # Filter out folders, only check actual files
            file_items = [f for f in all_files_list if f.get('mimeType') != 'application/vnd.google-apps.folder']
            file_ids = [f['id'] for f in file_items]
            
            # Check in batches of 1000 (API limit)
            batch_size_check = 1000
            already_backed_up = set()
            
            for i in range(0, len(file_ids), batch_size_check):
                batch_ids = file_ids[i:i+batch_size_check]
                check_result = api_client.check_backed_up_items('drive', batch_ids)
                
                if check_result:
                    backed_up = check_result.get('backed_up_items', [])
                    new_items = check_result.get('new_items', [])
                    
                    # If new_items is empty but we have file_ids, calculate it ourselves
                    if not new_items and len(batch_ids) > 0:
                        new_items = [file_id for file_id in batch_ids if file_id not in backed_up]
                        log_message(f"📁 DEBUG: Calculated new_items from batch_ids: {len(new_items)} new files")
                    
                    already_backed_up.update(backed_up)
                    log_message(f"📁 Batch {i//batch_size_check + 1}: {len(backed_up)} already backed up, {len(new_items)} NEW (will be inserted into MySQL)")
                    if len(new_items) > 0 and i == 0:  # Log first batch's new items for debugging
                        log_message(f"📁 First batch NEW file IDs: {new_items[:5]}{'...' if len(new_items) > 5 else ''}")
                else:
                    log_message(f"⚠️ WARNING: Could not check backed up files for batch {i//batch_size_check + 1} - will process all", 'WARNING')
                    # If check fails, process all files to be safe
                    already_backed_up = set()
                    break
            
            # Filter out already backed up files
            if already_backed_up:
                new_files_list = []
                for f in all_files_list:
                    # Always include folders (for metadata), but filter files
                    if f.get('mimeType') == 'application/vnd.google-apps.folder':
                        new_files_list.append(f)
                    elif f['id'] not in already_backed_up:
                        new_files_list.append(f)
                
                log_message(f"📁 ✓ Filtered: {len(already_backed_up)} already backed up, {len(new_files_list)} new items to backup")
                all_files_list = new_files_list
            else:
                log_message(f"📁 ✓ All {len(all_files_list)} items are new (or check failed - processing all for safety)")
        
        if not all_files_list:
            log_message(f"📁 ✓ All files are already backed up - nothing to do!")
            return uploaded_resources
        
        log_message(f"📁 Step 3: Processing {len(all_files_list)} items...")
        log_message(f"📁 IMPORTANT: These {len(all_files_list)} items will be uploaded to S3 AND inserted into MySQL backup_GW_drive table")
        
        # Now process the filtered files
        for file in all_files_list:
                try:
                    mime_type = file.get('mimeType', '')
                    file_id = file['id']
                    file_name = file.get('name', file_id)
                    
                    # Google Workspace files (Docs, Sheets, Slides) need to be exported, not downloaded
                    # Check if it's a Google Workspace file
                    is_google_workspace_file = mime_type in [
                        'application/vnd.google-apps.document',  # Google Docs
                        'application/vnd.google-apps.spreadsheet',  # Google Sheets
                        'application/vnd.google-apps.presentation',  # Google Slides
                        'application/vnd.google-apps.drawing',  # Google Drawings
                        'application/vnd.google-apps.form',  # Google Forms
                        'application/vnd.google-apps.folder',  # Folders (skip)
                    ]
                    
                    # Handle folders: Save folder metadata to MySQL (for structure preservation)
                    # Folders are saved as metadata only, not as files in S3
                    if mime_type == 'application/vnd.google-apps.folder':
                        # Save folder metadata to MySQL for structure tracking
                        if sql_writer:
                            try:
                                parents = file.get('parents', [])
                                parent_folder_id = parents[0] if parents else None
                                folder_path = build_folder_path(parent_folder_id)
                                
                                # Build folder metadata SQL
                                folder_backup_date = datetime.now()
                                folder_backup_date_sql = f"'{folder_backup_date.strftime('%Y-%m-%d %H:%M:%S')}'"
                                
                                def escape_sql(s):
                                    if s is None:
                                        return 'NULL'
                                    s_str = str(s)
                                    s_str = s_str.replace("\\", "\\\\").replace("'", "''")
                                    return "'" + s_str + "'"
                                
                                # Insert folder into backup_GW_drive_folders table
                                folder_values_sql = f"({escape_sql(instance_id)}, {escape_sql(domain)}, {escape_sql(account_id)}, {escape_sql('google_workspace')}, {escape_sql(session_id)}, {escape_sql(file_id)}, {escape_sql(file_name)}, {escape_sql(parent_folder_id)}, {escape_sql(folder_path)}, {folder_backup_date_sql})"
                                sql_writer.add_insert('backup_GW_drive_folders', folder_values_sql)
                                
                                if total_files == 0:
                                    log_message(f"📁 Saved folder metadata: {file_name} (path: {folder_path if folder_path else 'root'})")
                            except Exception as e:
                                log_message(f"⚠️ WARNING: Could not save folder metadata for {file_name}: {str(e)}", 'WARNING')
                        continue  # Skip folder file download, but metadata is saved
                    
                    # Download or export file - with retry
                    max_get_retries = 3
                    get_retry = 0
                    file_content = None
                    export_mime_type = None
                    
                    # Determine export format for Google Workspace files
                    if is_google_workspace_file:
                        if mime_type == 'application/vnd.google-apps.document':
                            export_mime_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'  # .docx
                        elif mime_type == 'application/vnd.google-apps.spreadsheet':
                            export_mime_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'  # .xlsx
                        elif mime_type == 'application/vnd.google-apps.presentation':
                            export_mime_type = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'  # .pptx
                        elif mime_type == 'application/vnd.google-apps.drawing':
                            export_mime_type = 'image/png'  # PNG
                        elif mime_type == 'application/vnd.google-apps.form':
                            export_mime_type = 'application/pdf'  # PDF
                    
                    while get_retry < max_get_retries:
                        try:
                            if is_google_workspace_file and export_mime_type:
                                # Export Google Workspace file
                                request = drive_service.files().export_media(fileId=file_id, mimeType=export_mime_type)
                                file_content = request.execute()
                                # Update file extension for exported files
                                if export_mime_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                                    file_name = file_name if file_name.endswith('.docx') else f"{file_name}.docx"
                                elif export_mime_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':
                                    file_name = file_name if file_name.endswith('.xlsx') else f"{file_name}.xlsx"
                                elif export_mime_type == 'application/vnd.openxmlformats-officedocument.presentationml.presentation':
                                    file_name = file_name if file_name.endswith('.pptx') else f"{file_name}.pptx"
                                elif export_mime_type == 'image/png':
                                    file_name = file_name if file_name.endswith('.png') else f"{file_name}.png"
                                elif export_mime_type == 'application/pdf':
                                    file_name = file_name if file_name.endswith('.pdf') else f"{file_name}.pdf"
                            else:
                                # Download regular file
                                request = drive_service.files().get_media(fileId=file_id)
                                file_content = request.execute()
                            break
                        except HttpError as e:
                            if e.resp.status == 429:
                                get_retry += 1
                                wait_time = (2 ** get_retry) * 30
                                log_message(f"Rate limit downloading file {file_name}. Waiting {wait_time}s...", 'WARNING')
                                time.sleep(wait_time)
                            elif e.resp.status == 403 and 'fileNotDownloadable' in str(e):
                                # Google Workspace file that couldn't be exported - log and skip
                                log_message(f"Skipping Google Workspace file {file_name} (type: {mime_type}) - export not available", 'WARNING')
                                break
                            else:
                                raise
                    
                    if not file_content:
                        if is_google_workspace_file:
                            # Already logged, just skip
                            continue
                        log_message(f"Failed to download file {file_name} after retries", 'WARNING')
                        continue
                    
                    # Upload to S3
                    # Structure: drive/{user_email}/{date}/{folder_path}/{file_name}
                    # This preserves the exact folder structure from Google Drive
                    backup_date = datetime.now()
                    # Sanitize user_email for S3 path (replace @ with _)
                    safe_user_email = user_email.replace('@', '_at_')
                    
                    # Build folder path for S3 structure
                    parents = file.get('parents', [])
                    parent_folder_id = parents[0] if parents else None
                    folder_path = build_folder_path(parent_folder_id)
                    
                    # Sanitize folder path and file name for S3
                    safe_folder_path = folder_path.replace('\\', '/').replace('//', '/').strip('/') if folder_path else ''
                    # Sanitize each folder name in the path
                    if safe_folder_path:
                        path_parts = safe_folder_path.split('/')
                        sanitized_parts = [part.replace('/', '_').replace('\\', '_').replace(' ', '_') for part in path_parts]
                        safe_folder_path = '/'.join(sanitized_parts)
                    
                    safe_file_name = file_name.replace('/', '_').replace('\\', '_')
                    
                    # Build S3 key with folder structure preserved
                    if safe_folder_path:
                        # File is in a folder: backups/{instance_id}/drive/{user_email}/{date}/{folder_path}/{file_name}
                        s3_key = f"backups/{instance_id}/drive/{safe_user_email}/{backup_date.strftime('%Y/%m')}/{safe_folder_path}/{safe_file_name}"
                    else:
                        # File is at root: backups/{instance_id}/drive/{user_email}/{date}/{file_name}
                        s3_key = f"backups/{instance_id}/drive/{safe_user_email}/{backup_date.strftime('%Y/%m')}/{safe_file_name}"
                    
                    # Determine content type for S3
                    content_type = export_mime_type if is_google_workspace_file and export_mime_type else file.get('mimeType', 'application/octet-stream')
                    
                    # For incremental backup: check if already exists to avoid duplicates (fallback safety check)
                    # Note: Drive query filter should already exclude old files, but this is a safety net
                    if is_incremental and not drive_query and check_s3_key_exists(s3_client, s3_config['bucket'], s3_key):
                        log_message(f"Skipping duplicate file {file_name} (already backed up - fallback check)", 'INFO')
                        continue
                    
                    s3_client.put_object(
                        Bucket=s3_config['bucket'],
                        Key=s3_key,
                        Body=file_content,
                        ContentType=content_type,
                        Metadata={
                            'file_id': file_id,
                            'file_name': file_name,
                            'original_mime_type': mime_type,
                            'exported_mime_type': export_mime_type if is_google_workspace_file else '',
                            'user_email': user_email,
                            'backup_date': backup_date.isoformat()
                        }
                    )
                    
                    # Log folder path info (for debugging)
                    folder_info = f" (in folder: {folder_path})" if folder_path else " (root level)"
                    log_message(f"✓ Uploaded file {file_name} to S3: {s3_key}{folder_info}", 'INFO')
                    
                    # Extract and send Drive metadata to MySQL via API
                    # CRITICAL: File metadata is REQUIRED for MySQL insert
                    if not file:
                        log_message(f"❌ ERROR: Cannot insert file {file_id} into MySQL - file metadata is None (uploaded to S3 but not in MySQL)", 'ERROR')
                        continue
                    
                    if sql_writer:
                        try:
                            # Extract file metadata
                            file_size = int(file.get('size', 0)) if file.get('size') else 0
                            parents = file.get('parents', [])
                            parent_folder_id = parents[0] if parents else None
                            
                            # Build full folder path for MySQL storage
                            folder_path = build_folder_path(parent_folder_id)
                            
                            shared = 1 if file.get('shared', False) else 0
                            starred = 1 if file.get('starred', False) else 0
                            trashed = 1 if file.get('trashed', False) else 0
                            view_count = 0  # Not available in list, would need separate API call
                            file_extension = file.get('fileExtension', '')
                            if not file_extension and file_name:
                                # Extract extension from filename
                                if '.' in file_name:
                                    file_extension = file_name.split('.')[-1]
                            
                            # Build SQL VALUES clause
                            def escape_sql(s):
                                if s is None:
                                    return 'NULL'
                                s_str = str(s)
                                s_str = s_str.replace("\\", "\\\\").replace("'", "''")
                                return "'" + s_str + "'"
                            
                            backup_date_sql = f"'{backup_date.strftime('%Y-%m-%d %H:%M:%S')}'"
                            
                            # Determine s3_key_native and s3_key_content based on file type
                            # For Google Docs: s3_key contains the exported native format, so s3_key_native = s3_key
                            # For regular files: s3_key contains the actual file content, so s3_key_content = s3_key
                            s3_key_native_sql = 'NULL'
                            s3_key_content_sql = 'NULL'
                            
                            if is_google_workspace_file:
                                # For Google Docs, the s3_key already contains the native format (exported as DOCX/XLSX/PPTX/PDF/PNG)
                                # So we set s3_key_native to the same value to ensure it's always available for download
                                # This allows downloading readable files even after deletion from Google Drive
                                s3_key_native_sql = escape_sql(s3_key)
                                if total_files <= 10 or total_files % 100 == 0:
                                    log_message(f"📄 Google Doc {file_name}: s3_key_native set (format: {export_mime_type})")
                            else:
                                # For regular files, the s3_key contains the actual file content
                                # So we set s3_key_content to the same value
                                s3_key_content_sql = escape_sql(s3_key)
                            
                            # Include folder_path in SQL insert
                            # Column order: instance_id, domain, account_id, platform_type, session_id, file_id, file_name, 
                            # mime_type, file_size, parent_folder_id, folder_path, file_extension, shared, starred, trashed, 
                            # view_count, s3_key, s3_key_native, s3_key_content, backup_date
                            values_sql = f"({escape_sql(instance_id)}, {escape_sql(domain)}, {escape_sql(account_id)}, {escape_sql('google_workspace')}, {escape_sql(session_id)}, {escape_sql(file_id)}, {escape_sql(file_name)}, {escape_sql(mime_type)}, {file_size}, {escape_sql(parent_folder_id)}, {escape_sql(folder_path)}, {escape_sql(file_extension)}, {shared}, {starred}, {trashed}, {view_count}, {escape_sql(s3_key)}, {s3_key_native_sql}, {s3_key_content_sql}, {backup_date_sql})"
                            
                            # Add to batch
                            sql_writer.add_insert('backup_GW_drive', values_sql)
                            
                            # Log periodically for debugging
                            if total_files <= 10 or total_files % 100 == 0:
                                log_message(f"✓ Added file {file_id} ({file_name}) to SQL batch - will be inserted into MySQL backup_GW_drive table")
                            
                            # Log folder path for debugging
                            if folder_path and total_files % 100 == 0:
                                log_message(f"📁 File {file_name} saved in folder: {folder_path}")
                            
                        except Exception as e:
                            log_message(f"❌ ERROR: Could not extract Drive metadata for {file_id} ({file_name}): {str(e)}", 'ERROR')
                            log_message(f"❌ This file was uploaded to S3 but will NOT be inserted into MySQL!", 'ERROR')
                            import traceback
                            log_message(traceback.format_exc(), 'ERROR')
                    else:
                        log_message(f"❌ ERROR: sql_writer is None - file {file_id} ({file_name}) uploaded to S3 but will NOT be inserted into MySQL!", 'ERROR')
                    
                    uploaded_resources.append({
                        'type': 'drive',
                        's3_key': s3_key,
                        'resource_id': file_id,
                        'operation': 'upsert',
                        'metadata': {
                            'file_name': file_name,
                            'mime_type': mime_type,
                            'exported_mime_type': export_mime_type if is_google_workspace_file else '',
                            'user_email': user_email,
                            'backup_date': backup_date.isoformat()
                        }
                    })
                    
                    total_files += 1
                    
                    # Progress updates every 500 files for enterprise-scale
                    if total_files % 500 == 0:
                        elapsed_hours = (time.time() - start_time) / 3600
                        log_message(f"Progress: {total_files} files backed up in {elapsed_hours:.2f} hours...")
                
                except Exception as e:
                    log_message(f"Error backing up file {file.get('id', 'unknown')}: {str(e)}", 'ERROR')
                    continue
        
        elapsed_hours = (time.time() - start_time) / 3600
        if total_files > 0:
            log_message(f"✅✅✅ Drive backup completed: {total_files} files backed up in {elapsed_hours:.2f} hours")
            log_message(f"📁 All files from all folders have been backed up (including files in subfolders)")
            
            # CRITICAL: Flush any remaining SQL batches for drive files
            if sql_writer:
                log_message(f"🔄 Flushing remaining SQL batches for drive files to ensure all records are inserted into MySQL...")
                try:
                    sql_writer.flush_table('backup_GW_drive')
                    log_message(f"✓ Drive SQL batches flushed successfully")
                except Exception as e:
                    log_message(f"❌ ERROR flushing drive SQL batches: {str(e)}", 'ERROR')
                    import traceback
                    log_message(traceback.format_exc(), 'ERROR')
        else:
            log_message(f"⚠️ WARNING: Drive backup completed but NO files were backed up (0 files)", 'WARNING')
            log_message(f"⚠️ This might indicate: 1) No files in Drive, 2) API access issue, 3) Filter problem", 'WARNING')
        return uploaded_resources
        
    except Exception as e:
        elapsed_hours = (time.time() - start_time) / 3600
        log_message(f"Drive backup error after {elapsed_hours:.2f} hours and {total_files} files: {str(e)}", 'ERROR')
        log_message(traceback.format_exc(), 'ERROR')
        return uploaded_resources

def backup_calendar(s3_client, calendar_service, user_email: str, s3_config: Dict, instance_id: str,
                   receipt_handle: Optional[str] = None, 
                   sqs_client_instance=None, domain: str = '', account_id: str = '', session_id: str = '',
                   is_incremental: bool = False, last_backup_info: Optional[Dict] = None, log_writer=None, sql_writer=None,
                   api_client=None) -> List[Dict]:
    """Backup Google Calendar events to S3 - NO LIMITS, processes all events"""
    log_message(f"Starting Calendar backup for {user_email} - NO LIMITS, will process ALL events")
    
    uploaded_resources = []
    start_time = time.time()
    
    # Build Calendar updatedMin for incremental backup (timestamp-based filtering)
    # Use updatedMin instead of timeMin to filter by last modification time, not start time
    calendar_updated_min = None
    if is_incremental and last_backup_info:
        try:
            backup_timestamp_str = last_backup_info.get('backup_timestamp', '')
            if backup_timestamp_str:
                # Parse timestamp and convert to RFC 3339 format for Calendar API
                backup_time = datetime.strptime(backup_timestamp_str, '%Y-%m-%d %H:%M:%S')
                # Calendar API uses RFC 3339 format: YYYY-MM-DDTHH:MM:SSZ
                # Use updatedMin to filter by last modification time (better for incremental backups)
                calendar_updated_min = backup_time.strftime('%Y-%m-%dT%H:%M:%SZ')
                log_message(f"🔄 INCREMENTAL: Using Calendar updatedMin filter '{calendar_updated_min}' to fetch only events modified after backup")
                log_message(f"🔄 Calendar incremental backup will process events modified after: {backup_timestamp_str}")
        except Exception as e:
            log_message(f"Warning: Could not parse backup timestamp for Calendar filter: {str(e)}", 'WARNING')
            # Fall back to S3 checking if timestamp parsing fails
    
    try:
        # List calendars
        calendars = calendar_service.calendarList().list().execute()
        
        for cal in calendars.get('items', []):
            try:
                # Get ALL events - NO LIMIT, paginate through all pages
                all_events = []
                page_token = None
                
                while True:
                    request_params = {
                        'calendarId': cal['id'],
                        'maxResults': 2500  # Max per page, but we paginate
                    }
                    if page_token:
                        request_params['pageToken'] = page_token
                    # Add Calendar updatedMin filter for incremental backups (filters by last modification time)
                    if calendar_updated_min:
                        request_params['updatedMin'] = calendar_updated_min
                    
                    # Retry logic for rate limits
                    max_retries = 5
                    retry_count = 0
                    events = None
                    
                    while retry_count < max_retries:
                        try:
                            events = calendar_service.events().list(**request_params).execute()
                            break
                        except HttpError as e:
                            if e.resp.status == 429:
                                retry_count += 1
                                wait_time = (2 ** retry_count) * 60
                                log_message(f"Rate limit getting calendar events. Waiting {wait_time}s...", 'WARNING')
                                time.sleep(wait_time)
                            else:
                                raise
                    
                    if not events:
                        break
                    
                    all_events.extend(events.get('items', []))
                    page_token = events.get('nextPageToken')
                    
                    if not page_token:
                        break
                
                log_message(f"Found {len(all_events)} events in calendar: {cal.get('summary', cal['id'])}")
                
                # For incremental backup: Check MySQL to see which events are already backed up
                if is_incremental and api_client and all_events:
                    log_message(f"📅 Checking MySQL to see which of {len(all_events)} events are already backed up...")
                    event_ids = [e.get('id', '') for e in all_events if e.get('id')]
                    
                    # Check in batches of 1000 (API limit)
                    batch_size_check = 1000
                    already_backed_up = set()
                    
                    for i in range(0, len(event_ids), batch_size_check):
                        batch_ids = event_ids[i:i+batch_size_check]
                        check_result = api_client.check_backed_up_items('calendar', batch_ids)
                        
                        if check_result:
                            backed_up = check_result.get('backed_up_items', [])
                            new_items = check_result.get('new_items', [])
                            
                            # If new_items is empty but we have event_ids, calculate it ourselves
                            if not new_items and len(batch_ids) > 0:
                                new_items = [event_id for event_id in batch_ids if event_id not in backed_up]
                                log_message(f"📅 DEBUG: Calculated new_items from batch_ids: {len(new_items)} new events")
                            
                            already_backed_up.update(backed_up)
                            log_message(f"📅 Batch {i//batch_size_check + 1}: {len(backed_up)} already backed up, {len(new_items)} NEW (will be inserted into MySQL)")
                            if len(new_items) > 0 and i == 0:  # Log first batch's new items for debugging
                                log_message(f"📅 First batch NEW event IDs: {new_items[:5]}{'...' if len(new_items) > 5 else ''}")
                        else:
                            log_message(f"⚠️ WARNING: Could not check backed up events for batch {i//batch_size_check + 1} - will process all", 'WARNING')
                            # If check fails, process all events to be safe
                            already_backed_up = set()
                            break
                    
                    # Filter out already backed up events
                    if already_backed_up:
                        new_events = [e for e in all_events if e.get('id', '') not in already_backed_up]
                        log_message(f"📅 ✓ Filtered: {len(already_backed_up)} already backed up, {len(new_events)} new events to backup")
                        if new_events:
                            log_message(f"📅 ✓ NEW events to process: {[e.get('id', '') for e in new_events[:5]]}{'...' if len(new_events) > 5 else ''}")
                        all_events = new_events
                    else:
                        log_message(f"📅 ✓ All {len(all_events)} events are new (or check failed - processing all for safety)")
                
                if not all_events:
                    log_message(f"📅 ✓ All events in calendar {cal.get('summary', cal['id'])} are already backed up - skipping")
                    continue
                
                log_message(f"📅 IMPORTANT: {len(all_events)} events will be uploaded to S3 AND inserted into MySQL backup_GW_calendar table")
                
                # Upload to S3
                # Structure: calendar/{user_email}/{date}/{calendar_id}.json
                backup_date = datetime.now()
                # Sanitize user_email for S3 path (replace @ with _)
                safe_user_email = user_email.replace('@', '_at_')
                s3_key = f"backups/{instance_id}/calendar/{safe_user_email}/{backup_date.strftime('%Y/%m')}/{cal['id']}.json"
                
                # For incremental backup: check if already exists (fallback safety check)
                # Note: Calendar updatedMin filter should already exclude old events, but this is a safety net
                # However, for Calendar we backup all events in a calendar as one file, so we still check
                if is_incremental and not calendar_updated_min and check_s3_key_exists(s3_client, s3_config['bucket'], s3_key):
                    log_message(f"Skipping duplicate calendar {cal.get('summary', cal['id'])} (already backed up - fallback check)", 'INFO')
                    continue
                
                # Create events dict with all events
                events_dict = {'items': all_events}
                events_json = json.dumps(events_dict, indent=2)
                
                s3_client.put_object(
                    Bucket=s3_config['bucket'],
                    Key=s3_key,
                    Body=events_json,
                    ContentType='application/json',
                    Metadata={
                        'calendar_id': cal['id'],
                        'calendar_name': cal.get('summary', ''),
                        'user_email': user_email,
                        'backup_date': backup_date.isoformat()
                    }
                )
                
                # Calendar metadata is now handled by sql_writer via API
                # No direct database connection needed
                if all_events:
                    try:
                        for event in all_events:
                            event_id = event.get('id', '')
                            if not event_id:
                                continue
                            
                            # Parse event data
                            summary = event.get('summary', '')
                            description = event.get('description', '')
                            location = event.get('location', '')
                            start_time = None
                            end_time = None
                            timezone = None
                            all_day = False
                            
                            if 'start' in event:
                                start_data = event['start']
                                if 'dateTime' in start_data:
                                    start_time = datetime.fromisoformat(start_data['dateTime'].replace('Z', '+00:00'))
                                    timezone = start_data.get('timeZone', 'UTC')
                                elif 'date' in start_data:
                                    start_time = datetime.fromisoformat(start_data['date'])
                                    all_day = True
                            
                            if 'end' in event:
                                end_data = event['end']
                                if 'dateTime' in end_data:
                                    end_time = datetime.fromisoformat(end_data['dateTime'].replace('Z', '+00:00'))
                                elif 'date' in end_data:
                                    end_time = datetime.fromisoformat(end_data['date'])
                            
                            recurrence = json.dumps(event.get('recurrence', [])) if event.get('recurrence') else None
                            organizer = event.get('organizer', {})
                            organizer_email = organizer.get('email', '') if organizer else None
                            attendees = event.get('attendees', [])
                            attendee_count = len(attendees) if attendees else 0
                            attendees_json = json.dumps(attendees) if attendees else None
                            
                            # Extract and send Calendar metadata to MySQL via API
                            # CRITICAL: Event data is REQUIRED for MySQL insert
                            if not event:
                                log_message(f"❌ ERROR: Cannot insert event {event_id} into MySQL - event data is None (uploaded to S3 but not in MySQL)", 'ERROR')
                                continue
                            
                            if sql_writer:
                                try:
                                    if is_incremental and len([e for e in all_events if e.get('id') == event_id][:1]) <= 10:  # Log first 10 events for debugging
                                        log_message(f"📅 Processing event {event_id} for SQL insert - WILL BE INSERTED INTO MySQL backup_GW_calendar table")
                                    # Build SQL VALUES clause
                                    def escape_sql(s):
                                        if s is None:
                                            return 'NULL'
                                        s_str = str(s)
                                        s_str = s_str.replace("\\", "\\\\").replace("'", "''")
                                        return "'" + s_str + "'"
                                    
                                    # Format dates for SQL
                                    start_time_sql = f"'{start_time.strftime('%Y-%m-%d %H:%M:%S')}'" if start_time else 'NULL'
                                    end_time_sql = f"'{end_time.strftime('%Y-%m-%d %H:%M:%S')}'" if end_time else 'NULL'
                                    backup_date_sql = f"'{backup_date.strftime('%Y-%m-%d %H:%M:%S')}'"
                                    
                                    all_day_int = 1 if all_day else 0
                                    
                                    # Build SQL VALUES clause matching backup_GW_calendar table schema:
                                    # (instance_id, domain, account_id, platform_type, session_id, event_id, calendar_id, 
                                    #  calendar_name, summary, description, location, start_time, end_time, timezone, 
                                    #  all_day, recurrence, organizer_email, attendee_count, attendees_json, 
                                    #  s3_key, s3_key_ics, backup_date)
                                    values_sql = f"({escape_sql(instance_id)}, {escape_sql(domain)}, {escape_sql(account_id)}, {escape_sql('google_workspace')}, {escape_sql(session_id)}, {escape_sql(event_id)}, {escape_sql(cal['id'])}, {escape_sql(cal.get('summary', ''))}, {escape_sql(summary)}, {escape_sql(description)}, {escape_sql(location)}, {start_time_sql}, {end_time_sql}, {escape_sql(timezone)}, {all_day_int}, {escape_sql(recurrence)}, {escape_sql(organizer_email)}, {attendee_count}, {escape_sql(attendees_json)}, {escape_sql(s3_key)}, NULL, {backup_date_sql})"
                                    
                                    # Add to batch
                                    sql_writer.add_insert('backup_GW_calendar', values_sql)
                                    if is_incremental and len([e for e in all_events if e.get('id') == event_id][:1]) <= 10:  # Log first 10 for debugging
                                        log_message(f"✓ Added event {event_id} to SQL batch - will be inserted into MySQL backup_GW_calendar table")
                                    
                                except Exception as e:
                                    log_message(f"❌ ERROR: Could not extract Calendar metadata for event {event_id}: {str(e)}", 'ERROR')
                                    log_message(f"❌ This event was uploaded to S3 but will NOT be in MySQL!", 'ERROR')
                    except Exception as e:
                        log_message(f"Error processing calendar metadata: {str(e)}", 'WARNING')
                
                uploaded_resources.append({
                    'type': 'calendar',
                    's3_key': s3_key,
                    'resource_id': cal['id'],
                    'operation': 'upsert',
                    'metadata': {
                        'calendar_name': cal.get('summary', ''),
                        'user_email': user_email,
                        'backup_date': backup_date.isoformat()
                    }
                })
                
                log_message(f"Backed up calendar: {cal.get('summary', cal['id'])}")
            
            except Exception as e:
                log_message(f"Error backing up calendar {cal.get('id', 'unknown')}: {str(e)}", 'ERROR')
                continue
        
        log_message(f"✓ Calendar backup completed")
        return uploaded_resources
        
    except Exception as e:
        log_message(f"Calendar backup error: {str(e)}", 'ERROR')
        log_message(traceback.format_exc(), 'ERROR')
        return uploaded_resources

def backup_contacts(s3_client, people_service, user_email: str, s3_config: Dict, instance_id: str,
                   receipt_handle: Optional[str] = None, 
                   sqs_client_instance=None, domain: str = '', account_id: str = '', session_id: str = '',
                   is_incremental: bool = False, log_writer=None, sql_writer=None, api_client=None) -> List[Dict]:
    """Backup Google Contacts to S3 - NO LIMITS"""
    log_message(f"Starting Contacts backup for {user_email} - NO LIMITS, will process ALL contacts")
    
    uploaded_resources = []
    total_contacts = 0
    start_time = time.time()
    last_visibility_extend = time.time()
    
    try:
        # Get ALL contacts with pagination - NO LIMIT, processes all contacts
        all_connections = []
        page_token = None
        
        while True:
            # Extend visibility timeout for long-running jobs
            if receipt_handle and sqs_client_instance and (time.time() - last_visibility_extend) >= VISIBILITY_EXTEND_INTERVAL:
                try:
                    sqs_client_instance.change_message_visibility(
                        QueueUrl=SQS_BACKUP_QUEUE_URL,
                        ReceiptHandle=receipt_handle,
                        VisibilityTimeout=VISIBILITY_TIMEOUT
                    )
                    elapsed_hours = (time.time() - start_time) / 3600
                    log_message(f"Extended visibility timeout. Contacts backup running for {elapsed_hours:.2f} hours. Processed {total_contacts} contacts so far...")
                    last_visibility_extend = time.time()
                except Exception as e:
                    log_message(f"Warning: Could not extend visibility timeout: {str(e)}", 'WARNING')
            
            # List contacts with pagination
            request_params = {
                'resourceName': 'people/me',
                'personFields': 'names,emailAddresses,phoneNumbers,addresses,organizations',
                'pageSize': 1000  # Max per page
            }
            if page_token:
                request_params['pageToken'] = page_token
            
            # Retry logic for API rate limits
            max_retries = 5
            retry_count = 0
            contacts_response = None
            
            while retry_count < max_retries:
                try:
                    contacts_response = people_service.people().connections().list(**request_params).execute()
                    break
                except HttpError as e:
                    if e.resp.status == 429:  # Rate limit
                        retry_count += 1
                        wait_time = (2 ** retry_count) * 60
                        log_message(f"Rate limit getting contacts. Waiting {wait_time} seconds before retry {retry_count}/{max_retries}...", 'WARNING')
                        time.sleep(wait_time)
                    else:
                        raise
                except Exception as e:
                    log_message(f"Error listing contacts: {str(e)}", 'ERROR')
                    raise
            
            if not contacts_response:
                log_message("Failed to get contacts after retries", 'ERROR')
                break
            
            connections = contacts_response.get('connections', [])
            all_connections.extend(connections)
            total_contacts += len(connections)
            
            log_message(f"Processing batch of {len(connections)} contacts (Total so far: {total_contacts})")
            
            # Check for next page
            page_token = contacts_response.get('nextPageToken')
            if not page_token:
                break
        
        log_message(f"Total contacts retrieved: {total_contacts}")
        
        # For incremental backup: Check MySQL to see which contacts are already backed up
        if is_incremental and api_client and all_connections:
            log_message(f"👤 Checking MySQL to see which of {len(all_connections)} contacts are already backed up...")
            # Extract contact IDs (resourceName contains the contact ID)
            contact_ids = []
            for conn in all_connections:
                resource_name = conn.get('resourceName', '')
                if resource_name:
                    # Extract ID from resourceName (format: people/contact_id)
                    contact_id = resource_name.replace('people/', '') if resource_name.startswith('people/') else resource_name
                    contact_ids.append(contact_id)
            
            # Check in batches of 1000 (API limit)
            batch_size_check = 1000
            already_backed_up = set()
            
            for i in range(0, len(contact_ids), batch_size_check):
                batch_ids = contact_ids[i:i+batch_size_check]
                check_result = api_client.check_backed_up_items('contacts', batch_ids)
                
                if check_result:
                    backed_up = check_result.get('backed_up_items', [])
                    already_backed_up.update(backed_up)
                    log_message(f"👤 Batch {i//batch_size_check + 1}: {len(backed_up)} already backed up, {len(batch_ids) - len(backed_up)} new")
                else:
                    log_message(f"⚠️ WARNING: Could not check backed up contacts for batch {i//batch_size_check + 1} - will process all", 'WARNING')
                    # If check fails, process all contacts to be safe
                    already_backed_up = set()
                    break
            
            # Filter out already backed up contacts
            if already_backed_up:
                new_connections = []
                for conn in all_connections:
                    resource_name = conn.get('resourceName', '')
                    if resource_name:
                        contact_id = resource_name.replace('people/', '') if resource_name.startswith('people/') else resource_name
                        if contact_id not in already_backed_up:
                            new_connections.append(conn)
                
                log_message(f"👤 ✓ Filtered: {len(already_backed_up)} already backed up, {len(new_connections)} new contacts to backup")
                all_connections = new_connections
                total_contacts = len(all_connections)
            else:
                log_message(f"👤 ✓ All {len(all_connections)} contacts are new (or check failed - processing all for safety)")
        
        if not all_connections:
            log_message(f"👤 ✓ All contacts are already backed up - nothing to do!")
            return uploaded_resources
        
        log_message(f"👤 IMPORTANT: {len(all_connections)} contacts will be uploaded to S3 AND inserted into MySQL backup_GW_contacts table")
        
        # Upload to S3
        # Structure: contacts/{user_email}/{date}/{user_email}.json
        backup_date = datetime.now()
        # Sanitize user_email for S3 path (replace @ with _)
        safe_user_email = user_email.replace('@', '_at_')
        s3_key = f"backups/{instance_id}/contacts/{safe_user_email}/{backup_date.strftime('%Y/%m')}/{safe_user_email}.json"
        
        # For incremental backup: check if already exists
        if is_incremental and check_s3_key_exists(s3_client, s3_config['bucket'], s3_key):
            log_message(f"Skipping duplicate contacts (already backed up)", 'INFO')
            return uploaded_resources
        
        # Create contacts dict with all connections
        contacts_dict = {'connections': all_connections, 'total': total_contacts}
        contacts_json = json.dumps(contacts_dict, indent=2)
        
        s3_client.put_object(
            Bucket=s3_config['bucket'],
            Key=s3_key,
            Body=contacts_json,
            ContentType='application/json',
            Metadata={
                'user_email': user_email,
                'backup_date': backup_date.isoformat(),
                'total_contacts': str(total_contacts)
            }
        )
        
        # Extract and send contact metadata to MySQL via API
        if sql_writer:
            try:
                for person in all_connections:
                    resource_name = person.get('resourceName', '')
                    if not resource_name:
                        continue
                    
                    # Extract contact data for MySQL
                    names = person.get('names', [])
                    primary_name = names[0] if names else {}
                    display_name = primary_name.get('displayName', '')
                    given_name = primary_name.get('givenName', '')
                    family_name = primary_name.get('familyName', '')
                    middle_name = primary_name.get('middleName', '')
                    
                    emails = person.get('emailAddresses', [])
                    primary_email = emails[0].get('value', '') if emails else ''
                    emails_json = json.dumps(emails) if emails else '[]'
                    
                    phones = person.get('phoneNumbers', [])
                    primary_phone = phones[0].get('value', '') if phones else ''
                    phones_json = json.dumps(phones) if phones else '[]'
                    
                    addresses = person.get('addresses', [])
                    addresses_json = json.dumps(addresses) if addresses else '[]'
                    
                    organizations = person.get('organizations', [])
                    organization = organizations[0].get('name', '') if organizations else ''
                    job_title = organizations[0].get('title', '') if organizations else ''
                    department = organizations[0].get('department', '') if organizations else ''
                    
                    # Build SQL VALUES clause
                    def escape_sql(s):
                        if s is None:
                            return 'NULL'
                        s_str = str(s)
                        s_str = s_str.replace("\\", "\\\\").replace("'", "''")
                        return "'" + s_str + "'"
                    
                    backup_date_sql = f"'{backup_date.strftime('%Y-%m-%d %H:%M:%S')}'"
                    
                    # Extract contact_id from resourceName (format: people/xxxxxxxxxxxxx)
                    contact_id = resource_name.replace('people/', '') if resource_name.startswith('people/') else resource_name
                    
                    values_sql = f"({escape_sql(instance_id)}, {escape_sql(domain)}, {escape_sql(account_id)}, {escape_sql('google_workspace')}, {escape_sql(session_id)}, {escape_sql(contact_id)}, {escape_sql(resource_name)}, {escape_sql(display_name)}, {escape_sql(given_name)}, {escape_sql(family_name)}, {escape_sql(middle_name)}, NULL, NULL, {escape_sql(primary_email)}, {escape_sql(emails_json)}, {escape_sql(primary_phone)}, {escape_sql(phones_json)}, {escape_sql(addresses_json)}, {escape_sql(organization)}, {escape_sql(job_title)}, {escape_sql(department)}, {escape_sql(s3_key)}, NULL, {backup_date_sql})"
                    
                    # Add to batch
                    sql_writer.add_insert('backup_GW_contacts', values_sql)
                    if is_incremental and total_contacts <= 10:  # Log first 10 contacts for debugging
                        log_message(f"✓ Added contact {contact_id} to SQL batch - will be inserted into MySQL backup_GW_contacts table")
                    
            except Exception as e:
                log_message(f"❌ ERROR: Could not extract contact metadata for {contact_id}: {str(e)}", 'ERROR')
                log_message(f"❌ This contact was uploaded to S3 but will NOT be in MySQL!", 'ERROR')
        
        # Add resource entry for each contact
        for person in all_connections:
            resource_name = person.get('resourceName', '')
            if resource_name:
                contact_id = resource_name.replace('people/', '') if resource_name.startswith('people/') else resource_name
        uploaded_resources.append({
                    'type': 'contacts',
            's3_key': s3_key,
                    'resource_id': contact_id,
            'operation': 'upsert',
            'metadata': {
                'user_email': user_email,
                        'backup_date': backup_date.isoformat(),
                        'total_contacts': total_contacts
            }
        })
        
        log_message(f"✓ Contacts backup completed: {total_contacts} contacts backed up")
        return uploaded_resources
        
    except Exception as e:
        log_message(f"Contacts backup error: {str(e)}", 'ERROR')
        log_message(traceback.format_exc(), 'ERROR')
        return uploaded_resources

def insert_backup_log(db_connection, instance_id: str, platform_type: str, session_id: str, log_level: str, 
                      log_category: str, message: str, details: Dict = None, platform_data: Dict = None):
    """
    Insert log entry into backup_logs table - DEPRECATED: Use API client instead
    
    This function is deprecated and does nothing. Logs are now sent via API via log_writer.
    Kept for backward compatibility but should not be called.
    """
    # This function is deprecated - logs are now sent via API via log_writer
    # No database connection needed - all logs go through API
    pass

def insert_activity_log(db_connection, domain: str, session_id: str, instance_id: str, account_id: str, 
                       comment: str, status: str = 'instances'):
    """
    Insert activity log for user visibility - DEPRECATED: Use API client instead
    
    This function is deprecated and does nothing. Activity logs are now sent via API.
    Kept for backward compatibility but should not be called.
    """
    # This function is deprecated - activity logs are now sent via API via log_writer
    # No database connection needed - all logs go through API
    pass

def insert_email_metadata(db_connection, instance_id: str, domain: str, account_id: str, platform_type: str,
                         session_id: str, message_id: str, thread_id: str, subject: str, from_address: str,
                         to_addresses: str, cc_addresses: str, bcc_addresses: str, date_sent: datetime,
                         date_received: datetime, s3_key: str, s3_key_json: str, file_size: int,
                         mime_type: str, has_attachments: bool, attachment_count: int, backup_date: datetime):
    """Insert email metadata into backup_GW_emails table"""
    if not db_connection:
        return
    
    try:
        # Ensure table exists
        cursor = db_connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS backup_GW_emails (
                id INT AUTO_INCREMENT PRIMARY KEY,
                instance_id VARCHAR(255) NOT NULL,
                domain VARCHAR(255) NOT NULL,
                account_id VARCHAR(255) NOT NULL,
                platform_type VARCHAR(50) DEFAULT 'google_workspace',
                session_id VARCHAR(255) DEFAULT NULL,
                message_id VARCHAR(255) NOT NULL,
                thread_id VARCHAR(255) DEFAULT NULL,
                subject TEXT DEFAULT NULL,
                from_address VARCHAR(500) DEFAULT NULL,
                to_addresses TEXT DEFAULT NULL,
                cc_addresses TEXT DEFAULT NULL,
                bcc_addresses TEXT DEFAULT NULL,
                date_sent DATETIME DEFAULT NULL,
                date_received DATETIME DEFAULT NULL,
                s3_key VARCHAR(1000) NOT NULL,
                s3_key_json VARCHAR(1000) DEFAULT NULL,
                file_size BIGINT DEFAULT NULL,
                mime_type VARCHAR(255) DEFAULT NULL,
                has_attachments TINYINT(1) DEFAULT 0,
                attachment_count INT DEFAULT 0,
                backup_date DATETIME DEFAULT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_message (instance_id, message_id),
                INDEX idx_instance (instance_id),
                INDEX idx_domain (domain),
                INDEX idx_account (account_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        db_connection.commit()
        
        # Use INSERT ... ON DUPLICATE KEY UPDATE to avoid duplicates
        cursor.execute("""
            INSERT INTO backup_GW_emails 
            (instance_id, domain, account_id, platform_type, session_id, message_id, thread_id, subject,
             from_address, to_addresses, cc_addresses, bcc_addresses, date_sent, date_received,
             s3_key, s3_key_json, file_size, mime_type, has_attachments, attachment_count, backup_date, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            ON DUPLICATE KEY UPDATE
                s3_key = VALUES(s3_key),
                s3_key_json = VALUES(s3_key_json),
                file_size = VALUES(file_size),
                backup_date = VALUES(backup_date),
                updated_at = NOW()
        """, (
            instance_id, domain, account_id, platform_type, session_id, message_id, thread_id, subject,
            from_address, to_addresses, cc_addresses, bcc_addresses, date_sent, date_received,
            s3_key, s3_key_json, file_size, mime_type, has_attachments, attachment_count, backup_date
        ))
        db_connection.commit()
    except Exception as e:
        log_message(f"ERROR inserting email metadata: {str(e)}", 'ERROR')
        log_message(traceback.format_exc(), 'ERROR')

def insert_drive_metadata(db_connection, instance_id: str, domain: str, account_id: str, platform_type: str,
                         session_id: str, file_id: str, file_name: str, mime_type: str, file_size: int,
                         parent_folder_id: str, folder_path: str, file_extension: str, shared: bool,
                         starred: bool, trashed: bool, view_count: int, s3_key: str, s3_key_native: str,
                         s3_key_content: str, backup_date: datetime):
    """Insert drive file metadata into backup_GW_drive table"""
    if not db_connection:
        return
    
    try:
        # Ensure table exists
        cursor = db_connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS backup_GW_drive (
                id INT AUTO_INCREMENT PRIMARY KEY,
                instance_id VARCHAR(255) NOT NULL,
                domain VARCHAR(255) NOT NULL,
                account_id VARCHAR(255) NOT NULL,
                platform_type VARCHAR(50) DEFAULT 'google_workspace',
                session_id VARCHAR(255) DEFAULT NULL,
                file_id VARCHAR(255) NOT NULL,
                file_name VARCHAR(1000) DEFAULT NULL,
                mime_type VARCHAR(255) DEFAULT NULL,
                file_size BIGINT DEFAULT NULL,
                parent_folder_id VARCHAR(255) DEFAULT NULL,
                folder_path TEXT DEFAULT NULL,
                file_extension VARCHAR(50) DEFAULT NULL,
                shared TINYINT(1) DEFAULT 0,
                starred TINYINT(1) DEFAULT 0,
                trashed TINYINT(1) DEFAULT 0,
                view_count INT DEFAULT 0,
                s3_key VARCHAR(1000) NOT NULL,
                s3_key_native VARCHAR(1000) DEFAULT NULL,
                s3_key_content VARCHAR(1000) DEFAULT NULL,
                backup_date DATETIME DEFAULT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_file (instance_id, file_id),
                INDEX idx_instance (instance_id),
                INDEX idx_domain (domain),
                INDEX idx_account (account_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        db_connection.commit()
        
        cursor.execute("""
            INSERT INTO backup_GW_drive 
            (instance_id, domain, account_id, platform_type, session_id, file_id, file_name, mime_type,
             file_size, parent_folder_id, folder_path, file_extension, shared, starred, trashed, view_count,
             s3_key, s3_key_native, s3_key_content, backup_date, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            ON DUPLICATE KEY UPDATE
                s3_key = VALUES(s3_key),
                s3_key_native = VALUES(s3_key_native),
                s3_key_content = VALUES(s3_key_content),
                file_size = VALUES(file_size),
                backup_date = VALUES(backup_date),
                updated_at = NOW()
        """, (
            instance_id, domain, account_id, platform_type, session_id, file_id, file_name, mime_type,
            file_size, parent_folder_id, folder_path, file_extension, shared, starred, trashed, view_count,
            s3_key, s3_key_native, s3_key_content, backup_date
        ))
        db_connection.commit()
    except Exception as e:
        log_message(f"ERROR inserting drive metadata: {str(e)}", 'ERROR')
        log_message(traceback.format_exc(), 'ERROR')

def insert_calendar_metadata(db_connection, instance_id: str, domain: str, account_id: str, platform_type: str,
                           session_id: str, event_id: str, calendar_id: str, calendar_name: str,
                           summary: str, description: str, location: str, start_time: datetime, end_time: datetime,
                           timezone: str, all_day: bool, recurrence: str, organizer_email: str,
                           attendee_count: int, attendees_json: str, s3_key: str, s3_key_ics: str, backup_date: datetime):
    """Insert calendar event metadata into backup_GW_calendar table"""
    if not db_connection:
        return
    
    try:
        # Ensure table exists
        cursor = db_connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS backup_GW_calendar (
                id INT AUTO_INCREMENT PRIMARY KEY,
                instance_id VARCHAR(255) NOT NULL,
                domain VARCHAR(255) NOT NULL,
                account_id VARCHAR(255) NOT NULL,
                platform_type VARCHAR(50) DEFAULT 'google_workspace',
                session_id VARCHAR(255) DEFAULT NULL,
                event_id VARCHAR(255) NOT NULL,
                calendar_id VARCHAR(255) DEFAULT NULL,
                calendar_name VARCHAR(500) DEFAULT NULL,
                summary TEXT DEFAULT NULL,
                description TEXT DEFAULT NULL,
                location TEXT DEFAULT NULL,
                start_time DATETIME DEFAULT NULL,
                end_time DATETIME DEFAULT NULL,
                timezone VARCHAR(100) DEFAULT NULL,
                all_day TINYINT(1) DEFAULT 0,
                recurrence TEXT DEFAULT NULL,
                organizer_email VARCHAR(500) DEFAULT NULL,
                attendee_count INT DEFAULT 0,
                attendees_json TEXT DEFAULT NULL,
                s3_key VARCHAR(1000) NOT NULL,
                s3_key_ics VARCHAR(1000) DEFAULT NULL,
                backup_date DATETIME DEFAULT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_event (instance_id, event_id),
                INDEX idx_instance (instance_id),
                INDEX idx_domain (domain),
                INDEX idx_account (account_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        db_connection.commit()
        
        cursor.execute("""
            INSERT INTO backup_GW_calendar 
            (instance_id, domain, account_id, platform_type, session_id, event_id, calendar_id, calendar_name,
             summary, description, location, start_time, end_time, timezone, all_day, recurrence,
             organizer_email, attendee_count, attendees_json, s3_key, s3_key_ics, backup_date, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            ON DUPLICATE KEY UPDATE
                s3_key = VALUES(s3_key),
                s3_key_ics = VALUES(s3_key_ics),
                backup_date = VALUES(backup_date),
                updated_at = NOW()
        """, (
            instance_id, domain, account_id, platform_type, session_id, event_id, calendar_id, calendar_name,
            summary, description, location, start_time, end_time, timezone, all_day, recurrence,
            organizer_email, attendee_count, attendees_json, s3_key, s3_key_ics, backup_date
        ))
        db_connection.commit()
    except Exception as e:
        log_message(f"ERROR inserting calendar metadata: {str(e)}", 'ERROR')
        log_message(traceback.format_exc(), 'ERROR')

def insert_contact_metadata(db_connection, instance_id: str, domain: str, account_id: str, platform_type: str,
                           session_id: str, contact_id: str, resource_name: str, display_name: str,
                           given_name: str, family_name: str, middle_name: str, prefix: str, suffix: str,
                           primary_email: str, emails_json: str, primary_phone: str, phones_json: str,
                           addresses_json: str, organization: str, job_title: str, department: str,
                           s3_key: str, s3_key_vcf: str, backup_date: datetime):
    """Insert contact metadata into backup_GW_contacts table"""
    if not db_connection:
        return
    
    try:
        # Ensure table exists
        cursor = db_connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS backup_GW_contacts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                instance_id VARCHAR(255) NOT NULL,
                domain VARCHAR(255) NOT NULL,
                account_id VARCHAR(255) NOT NULL,
                platform_type VARCHAR(50) DEFAULT 'google_workspace',
                session_id VARCHAR(255) DEFAULT NULL,
                contact_id VARCHAR(255) NOT NULL,
                resource_name VARCHAR(500) DEFAULT NULL,
                display_name VARCHAR(500) DEFAULT NULL,
                given_name VARCHAR(255) DEFAULT NULL,
                family_name VARCHAR(255) DEFAULT NULL,
                middle_name VARCHAR(255) DEFAULT NULL,
                prefix VARCHAR(50) DEFAULT NULL,
                suffix VARCHAR(50) DEFAULT NULL,
                primary_email VARCHAR(500) DEFAULT NULL,
                emails_json TEXT DEFAULT NULL,
                primary_phone VARCHAR(100) DEFAULT NULL,
                phones_json TEXT DEFAULT NULL,
                addresses_json TEXT DEFAULT NULL,
                organization VARCHAR(500) DEFAULT NULL,
                job_title VARCHAR(255) DEFAULT NULL,
                department VARCHAR(255) DEFAULT NULL,
                s3_key VARCHAR(1000) NOT NULL,
                s3_key_vcf VARCHAR(1000) DEFAULT NULL,
                backup_date DATETIME DEFAULT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_contact (instance_id, contact_id),
                INDEX idx_instance (instance_id),
                INDEX idx_domain (domain),
                INDEX idx_account (account_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        db_connection.commit()
        
        cursor.execute("""
            INSERT INTO backup_GW_contacts 
            (instance_id, domain, account_id, platform_type, session_id, contact_id, resource_name, display_name,
             given_name, family_name, middle_name, prefix, suffix, primary_email, emails_json, primary_phone,
             phones_json, addresses_json, organization, job_title, department, s3_key, s3_key_vcf, backup_date, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            ON DUPLICATE KEY UPDATE
                s3_key = VALUES(s3_key),
                s3_key_vcf = VALUES(s3_key_vcf),
                backup_date = VALUES(backup_date),
                updated_at = NOW()
        """, (
            instance_id, domain, account_id, platform_type, session_id, contact_id, resource_name, display_name,
            given_name, family_name, middle_name, prefix, suffix, primary_email, emails_json, primary_phone,
            phones_json, addresses_json, organization, job_title, department, s3_key, s3_key_vcf, backup_date
        ))
        db_connection.commit()
    except Exception as e:
        log_message(f"ERROR inserting contact metadata: {str(e)}", 'ERROR')
        log_message(traceback.format_exc(), 'ERROR')

def check_s3_key_exists(s3_client, bucket: str, s3_key: str) -> bool:
    """Check if S3 key already exists (for incremental backup duplicate detection)"""
    try:
        s3_client.head_object(Bucket=bucket, Key=s3_key)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            return False
        raise

def get_last_backup_info(s3_client, bucket: str, instance_id: str, user_email: str, service_type: str) -> Optional[Dict]:
    """Get last backup info from S3 logs (for full/incremental detection)"""
    try:
        safe_user_email = user_email.replace('@', '_at_')
        prefix = f"logs_backup/{instance_id}/"
        
        # List all backup logs
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket, Prefix=prefix)
        
        latest_log = None
        latest_timestamp = None
        
        for page in pages:
            if 'Contents' not in page:
                continue
                
            for obj in page['Contents']:
                key = obj['Key']
                # Look for: logs_backup/{instance_id}/{date}/{user_email}_{service_type}.json
                if f"{safe_user_email}_{service_type}.json" in key:
                    # Extract date from path
                    parts = key.split('/')
                    if len(parts) >= 4:
                        date_str = parts[2]  # Date part
                        try:
                            # Try to parse date (format: YYYY-MM-DD or YYYY/MM/DD)
                            date_str_clean = date_str.replace('/', '-')
                            date_timestamp = time.mktime(time.strptime(date_str_clean, '%Y-%m-%d'))
                            
                            if latest_timestamp is None or date_timestamp > latest_timestamp:
                                latest_timestamp = date_timestamp
                                latest_log = key
                        except:
                            continue
        
        if latest_log:
            # Get the log content
            response = s3_client.get_object(Bucket=bucket, Key=latest_log)
            log_data = json.loads(response['Body'].read().decode('utf-8'))
            return log_data
        
        return None
        
    except Exception as e:
        log_message(f"Error getting last backup info: {str(e)}", 'WARNING')
        return None

def needs_incremental_backup(api_client, s3_client, bucket: str, instance_id: str, user_email: str, service_type: str):
    """
    Check if incremental backup is needed using precise database timestamps
    Returns: (is_incremental, last_backup_info)
    Logic: Full backup if no previous backup OR if last backup was >30 days ago
    Uses database timestamps for precise hour/minute/second comparison (not day-based)
    """
    # Try to get last backup timestamp from database via API (precise timestamp)
    last_backup_data = None
    if api_client:
        try:
            last_backup_data = api_client.get_last_backup_timestamp(user_email, service_type)
        except Exception as e:
            log_message(f"Warning: Could not get last backup timestamp from API: {str(e)} - falling back to S3 logs", 'WARNING')
    
    # Fallback to S3 logs if API call failed or no API client
    if not last_backup_data:
        last_backup = get_last_backup_info(s3_client, bucket, instance_id, user_email, service_type)
        if not last_backup:
            log_message(f"🆕 No previous backup found - FULL BACKUP needed for {service_type}")
            return (False, None)  # Full backup needed
        
        # Convert S3 log format to match API format
        backup_timestamp_str = last_backup.get('backup_timestamp', '')
        if backup_timestamp_str:
            try:
                backup_time = datetime.strptime(backup_timestamp_str, '%Y-%m-%d %H:%M:%S')
                time_since_backup = (datetime.now() - backup_time).total_seconds()
                days_since_backup = time_since_backup / 86400.0
                
                # Force full backup every 30 days
                if days_since_backup > 30:
                    log_message(f"📅 Monthly full backup required - Last backup was {round(days_since_backup, 1)} days ago for {service_type}")
                    return (False, last_backup)  # Full backup needed
                
                # Build last_backup_info dict in API format
                last_backup_data = {
                    'last_backup_timestamp': backup_timestamp_str,
                    'backup_type': 'incremental' if days_since_backup < 30 else 'full',
                    'days_since_backup': days_since_backup,
                    'timestamp_epoch': int(backup_time.timestamp())
                }
            except Exception as e:
                log_message(f"Error parsing S3 backup timestamp: {str(e)}. Defaulting to FULL backup.", 'WARNING')
                return (False, last_backup)
        else:
            log_message(f"🆕 No backup timestamp in S3 log - FULL BACKUP needed for {service_type}")
            return (False, None)
    
    # Use precise database timestamp
    backup_timestamp_str = last_backup_data.get('last_backup_timestamp', '')
    days_since_backup = last_backup_data.get('days_since_backup', 0)
    suggested_backup_type = last_backup_data.get('backup_type', 'incremental')
    
    if not backup_timestamp_str:
        log_message(f"🆕 No previous backup found - FULL BACKUP needed for {service_type}")
        return (False, None)  # Full backup needed
    
    # Force full backup every 30 days
    if days_since_backup > 30:
        log_message(f"📅 Monthly full backup required - Last backup was {round(days_since_backup, 1)} days ago for {service_type}")
        # Return last_backup_info in expected format
        last_backup_info = {
            'backup_timestamp': backup_timestamp_str,
            'stats': {'backup_type': 'full'}
        }
        return (False, last_backup_info)  # Full backup needed
    
    # Incremental backup - use precise timestamp
    hours_since_backup = days_since_backup * 24
    log_message(f"🔄 INCREMENTAL BACKUP - Last backup: {backup_timestamp_str} ({round(hours_since_backup, 2)} hours ago) for {service_type}")
    
    # Return last_backup_info in expected format
    last_backup_info = {
        'backup_timestamp': backup_timestamp_str,
        'stats': {'backup_type': suggested_backup_type},
        'timestamp_epoch': last_backup_data.get('timestamp_epoch')
    }
    return (True, last_backup_info)  # Incremental backup

def save_backup_log(s3_client, bucket: str, instance_id: str, user_email: str, service_type: str, 
                    backup_type: str, stats: Dict, backup_date: datetime) -> bool:
    """Save backup log JSON file to S3"""
    try:
        safe_user_email = user_email.replace('@', '_at_')
        date_str = backup_date.strftime('%Y-%m-%d')
        
        log_data = {
            'instance_id': instance_id,
            'user_email': user_email,
            'service_type': service_type,
            'backup_date': date_str,
            'backup_timestamp': backup_date.strftime('%Y-%m-%d %H:%M:%S'),
            'stats': {
                'backup_type': backup_type,
                **stats
            },
            'status': 'completed'
        }
        
        # S3 key: logs_backup/{instance_id}/{date}/{user_email}_{service_type}.json
        log_key = f"logs_backup/{instance_id}/{date_str}/{safe_user_email}_{service_type}.json"
        
        s3_client.put_object(
            Bucket=bucket,
            Key=log_key,
            Body=json.dumps(log_data, indent=2),
            ContentType='application/json'
        )
        
        log_message(f"✅ Backup log saved: {log_key} (Type: {backup_type})")
        return True
        
    except Exception as e:
        log_message(f"❌ Error saving backup log: {str(e)}", 'ERROR')
        return False

def send_index_messages(sqs_client, index_queue_url: str, instance_id: str, domain: str, account_id: str, uploaded_resources: List[Dict]):
    """Send index messages to SQS for each uploaded resource"""
    if not uploaded_resources:
        return
    
    log_message(f"Sending {len(uploaded_resources)} index messages to SQS...")
    
    for resource in uploaded_resources:
        try:
            index_message = {
                'instance_id': instance_id,
                'domain': domain,
                'account_id': account_id,
                'type': resource['type'],
                's3_key': resource['s3_key'],
                'resource_id': resource['resource_id'],
                'operation': resource.get('operation', 'upsert'),
                'metadata': resource.get('metadata')
            }
            
            sqs_client.send_message(
                QueueUrl=index_queue_url,
                MessageBody=json.dumps(index_message, ensure_ascii=False),
                MessageAttributes={
                    'instance_id': {
                        'DataType': 'String',
                        'StringValue': instance_id
                    },
                    'domain': {
                        'DataType': 'String',
                        'StringValue': domain
                    },
                    'type': {
                        'DataType': 'String',
                        'StringValue': resource['type']
                    }
                }
            )
        except Exception as e:
            log_message(f"Error sending index message: {str(e)}", 'ERROR')

def process_backup_job(job_data: Dict[str, Any], receipt_handle: Optional[str] = None, sqs_client_instance=None) -> bool:
    """Process a single backup job - NO TIME LIMITS, can run for 10+ hours"""
    try:
        instance = job_data.get('instance', {})
        user_email = job_data.get('user_email', '')
        instance_id = instance.get('instance_id', '')
        domain = job_data.get('domain', '')
        account_id = job_data.get('account_id', '')
        session_id = job_data.get('session_id', '')
        
        job_start_time = time.time()
        log_message(f"=== Processing backup for {user_email} ===")
        log_message(f"Instance ID: {instance_id}")
        log_message(f"Domain: {domain}")
        log_message(f"NO TIME LIMITS - Will process ALL data, can take 10+ hours for enterprise")
        
        # Decrypt S3 credentials
        s3_config = decrypt_s3_credentials(instance)
        if not s3_config['bucket']:
            log_message("ERROR: S3 bucket not configured", 'ERROR')
            return False
        
        log_message(f"S3 Bucket: {s3_config['bucket']}")
        
        # Create S3 client
        s3_client = get_s3_client(s3_config)
        
        # Decrypt Google credentials
        service_account_key = decrypt_google_credentials(instance)
        google_credentials = get_google_client(service_account_key, user_email)
        
        # Build Google API services
        gmail_service = build('gmail', 'v1', credentials=google_credentials)
        drive_service = build('drive', 'v3', credentials=google_credentials)
        calendar_service = build('calendar', 'v3', credentials=google_credentials)
        people_service = build('people', 'v1', credentials=google_credentials)
        
        # Get backup requirements
        requirements = job_data.get('backup_requirements', {})
        services = requirements.get('services', ['emails', 'drive', 'calendar', 'contacts'])
        
        # Ensure all services are included if not specified
        if not services or len(services) == 0:
            services = ['emails', 'drive', 'calendar', 'contacts']
            log_message("⚠️ No services specified in backup_requirements, defaulting to ALL services", 'WARNING')
        
        log_message(f"📋 Services to backup: {', '.join(services)}")
        log_message(f"📋 Total services: {len(services)} (emails: {'emails' in services}, drive: {'drive' in services}, calendar: {'calendar' in services}, contacts: {'contacts' in services})")
        
        # Initialize API client and file writers
        # IMPORTANT: API base URL must be https://console.neticks.com/api
        # This is hardcoded in backup_launcher.php to ensure Python worker on EC2 can contact the API
        api_key = job_data.get('api_key', '')
        api_base_url = job_data.get('api_base_url', '')
        
        if not api_key or not api_base_url:
            log_message("❌ CRITICAL WARNING: No API key or API base URL in job_data", 'ERROR')
            log_message(f"Job data keys available: {list(job_data.keys())}", 'ERROR')
            log_message("This means backup_launcher.php did not include API credentials in SQS message", 'ERROR')
            log_message(f"Expected API base URL: https://console.neticks.com/api", 'ERROR')
            raise Exception("API credentials missing from job data")
        
        # Verify API base URL is correct
        if api_base_url.rstrip('/') != 'https://console.neticks.com/api':
            log_message(f"⚠️ WARNING: API base URL is '{api_base_url}' but expected 'https://console.neticks.com/api'", 'WARNING')
        
        # Initialize API client
        api_client = BackupApiClient(
            api_base_url=api_base_url,
            api_key=api_key,
            instance_id=instance_id,
            domain=domain,
            account_id=account_id,
            session_id=session_id,
            user_email=user_email
        )
        
        # Initialize file writers
        log_dir = f"/tmp/backup_logs_{instance_id}_{session_id}"
        sql_dir = f"/tmp/backup_sql_{instance_id}_{session_id}"
        log_file = os.path.join(log_dir, "backup.log")
        
        log_writer = BackupLogWriter(log_file, api_client, batch_size=500)
        sql_writer = BackupSqlWriter(sql_dir, api_client, batch_size=500)
        
        log_message(f"✓✓✓ API client initialized - MySQL records will be sent via API")
        log_message(f"✓✓✓ File writers initialized - Logs: {log_dir}, SQL: {sql_dir}")
        
        # Send initial log
        log_writer.write('info', f"Starting backup for {user_email}", {
            'user_email': user_email,
            'services': services,
            'action': 'backup_started'
        })
        
        # Collect all uploaded resources
        all_uploaded_resources = []
        backup_date = datetime.now()
        
        # Backup each service - pass receipt_handle for visibility timeout extension
        # Determine full/incremental and save logs for each service
        # IMPORTANT: Each service is wrapped in try-except so one failure doesn't stop others
        # This ensures ALL services (emails, drive, calendar, contacts) are attempted
        
        if 'emails' in services:
            try:
                is_incremental, last_backup = needs_incremental_backup(api_client, s3_client, s3_config['bucket'], instance_id, user_email, 'emails')
                backup_type = 'incremental' if is_incremental else 'full'
                log_message(f"📧 Starting {backup_type.upper()} Gmail backup for {user_email} - NO LIMITS, will process ALL messages")
                
                log_writer.write('info', f"Starting {backup_type} Gmail backup for {user_email}", {
                    'service': 'emails',
                    'backup_type': backup_type,
                    'action': 'service_started'
                })
                
                resources = backup_gmail(s3_client, gmail_service, user_email, s3_config, instance_id, 
                                        receipt_handle, sqs_client_instance,
                                        domain, account_id, session_id, is_incremental,
                                        last_backup, log_writer, sql_writer, api_client)
                all_uploaded_resources.extend(resources)
                
                # Save backup log
                stats = {
                    'total_messages': len(resources),
                    'backup_type': backup_type
                }
                save_backup_log(s3_client, s3_config['bucket'], instance_id, user_email, 'emails', backup_type, stats, backup_date)
                
                log_message(f"✅ Gmail backup completed: {len(resources)} messages backed up")
                log_writer.write('info', f"Gmail backup completed: {len(resources)} messages", {
                    'service': 'emails',
                    'backup_type': backup_type,
                    'count': len(resources),
                    'action': 'service_completed'
                })
            except Exception as e:
                log_message(f"❌ ERROR in Gmail backup: {str(e)}", 'ERROR')
                log_message(traceback.format_exc(), 'ERROR')
                log_writer.write('error', f"Gmail backup failed: {str(e)}", {
                    'service': 'emails',
                    'error': str(e),
                    'action': 'service_failed'
                })
                # Continue with other services even if Gmail fails
        
        if 'drive' in services:
            try:
                is_incremental, last_backup = needs_incremental_backup(api_client, s3_client, s3_config['bucket'], instance_id, user_email, 'drive')
                backup_type = 'incremental' if is_incremental else 'full'
                log_message(f"📁 Starting {backup_type.upper()} Drive backup for {user_email} - NO LIMITS, will process ALL files")
                
                log_writer.write('info', f"Starting {backup_type} Drive backup for {user_email}", {
                    'service': 'drive',
                    'backup_type': backup_type,
                    'action': 'service_started'
                })
                
                resources = backup_drive(s3_client, drive_service, user_email, s3_config, instance_id, 
                                        receipt_handle, sqs_client_instance,
                                        domain, account_id, session_id, is_incremental,
                                        last_backup, log_writer, sql_writer, api_client)
                all_uploaded_resources.extend(resources)
                
                # Save backup log
                stats = {
                    'total_files': len(resources),
                    'backup_type': backup_type
                }
                save_backup_log(s3_client, s3_config['bucket'], instance_id, user_email, 'drive', backup_type, stats, backup_date)
                
                log_message(f"✅ Drive backup completed: {len(resources)} files backed up")
                log_writer.write('info', f"Drive backup completed: {len(resources)} files", {
                    'service': 'drive',
                    'backup_type': backup_type,
                    'count': len(resources),
                    'action': 'service_completed'
                })
            except Exception as e:
                log_message(f"❌ ERROR in Drive backup: {str(e)}", 'ERROR')
                log_message(traceback.format_exc(), 'ERROR')
                log_writer.write('error', f"Drive backup failed: {str(e)}", {
                    'service': 'drive',
                    'error': str(e),
                    'action': 'service_failed'
                })
                # Continue with other services even if Drive fails
        
        if 'calendar' in services:
            try:
                is_incremental, last_backup = needs_incremental_backup(api_client, s3_client, s3_config['bucket'], instance_id, user_email, 'calendar')
                backup_type = 'incremental' if is_incremental else 'full'
                log_message(f"📅 Starting {backup_type.upper()} Calendar backup for {user_email} - NO LIMITS, will process ALL events")
                
                log_writer.write('info', f"Starting {backup_type} Calendar backup for {user_email}", {
                    'service': 'calendar',
                    'backup_type': backup_type,
                    'action': 'service_started'
                })
                
                resources = backup_calendar(s3_client, calendar_service, user_email, s3_config, instance_id,
                                           receipt_handle, sqs_client_instance,
                                           domain, account_id, session_id, is_incremental,
                                           last_backup, log_writer, sql_writer, api_client)
                all_uploaded_resources.extend(resources)
                
                # Save backup log
                stats = {
                    'total_events': len(resources),
                    'backup_type': backup_type
                }
                save_backup_log(s3_client, s3_config['bucket'], instance_id, user_email, 'calendar', backup_type, stats, backup_date)
                
                log_message(f"✅ Calendar backup completed: {len(resources)} events backed up")
                log_writer.write('info', f"Calendar backup completed: {len(resources)} events", {
                    'service': 'calendar',
                    'backup_type': backup_type,
                    'count': len(resources),
                    'action': 'service_completed'
                })
            except Exception as e:
                log_message(f"❌ ERROR in Calendar backup: {str(e)}", 'ERROR')
                log_message(traceback.format_exc(), 'ERROR')
                log_writer.write('error', f"Calendar backup failed: {str(e)}", {
                    'service': 'calendar',
                    'error': str(e),
                    'action': 'service_failed'
                })
                # Continue with other services even if Calendar fails
        
        if 'contacts' in services:
            try:
                is_incremental, last_backup = needs_incremental_backup(api_client, s3_client, s3_config['bucket'], instance_id, user_email, 'contacts')
                backup_type = 'incremental' if is_incremental else 'full'
                log_message(f"👥 Starting {backup_type.upper()} Contacts backup for {user_email} - NO LIMITS, will process ALL contacts")
                
                log_writer.write('info', f"Starting {backup_type} Contacts backup for {user_email}", {
                    'service': 'contacts',
                    'backup_type': backup_type,
                    'action': 'service_started'
                })
                
                resources = backup_contacts(s3_client, people_service, user_email, s3_config, instance_id,
                                          receipt_handle, sqs_client_instance,
                                          domain, account_id, session_id, is_incremental,
                                          log_writer, sql_writer, api_client)
                all_uploaded_resources.extend(resources)
                
                # Save backup log
                stats = {
                    'total_contacts': len(resources),
                    'backup_type': backup_type
                }
                save_backup_log(s3_client, s3_config['bucket'], instance_id, user_email, 'contacts', backup_type, stats, backup_date)
                
                log_message(f"✅ Contacts backup completed: {len(resources)} contacts backed up")
                log_writer.write('info', f"Contacts backup completed: {len(resources)} contacts", {
                    'service': 'contacts',
                    'backup_type': backup_type,
                    'count': len(resources),
                    'action': 'service_completed'
                })
            except Exception as e:
                log_message(f"❌ ERROR in Contacts backup: {str(e)}", 'ERROR')
                log_message(traceback.format_exc(), 'ERROR')
                log_writer.write('error', f"Contacts backup failed: {str(e)}", {
                    'service': 'contacts',
                    'error': str(e),
                    'action': 'service_failed'
                })
                # Continue with other services even if Contacts fails
        
        # Send index messages
        if SQS_INDEX_QUEUE_URL:
            send_index_messages(sqs_client, SQS_INDEX_QUEUE_URL, instance_id, domain, account_id, all_uploaded_resources)
        
        job_elapsed_hours = (time.time() - job_start_time) / 3600
        
        # Summary of services backed up
        services_completed = []
        services_failed = []
        if 'emails' in services:
            services_completed.append('emails')
        if 'drive' in services:
            services_completed.append('drive')
        if 'calendar' in services:
            services_completed.append('calendar')
        if 'contacts' in services:
            services_completed.append('contacts')
        
        log_message("=" * 60)
        log_message(f"✓✓✓ Backup completed for {user_email}")
        log_message(f"📊 Services attempted: {', '.join(services)}")
        log_message(f"✅ Services completed: {', '.join(services_completed) if services_completed else 'None'}")
        log_message(f"📦 Total resources backed up: {len(all_uploaded_resources)}")
        log_message(f"⏱️  Total time: {job_elapsed_hours:.2f} hours")
        log_message("=" * 60)
        
        # Flush remaining logs and SQL batches
        log_writer.write('info', f"Backup completed successfully for {user_email}: {len(all_uploaded_resources)} resources in {job_elapsed_hours:.2f} hours", {
            'user_email': user_email,
            'total_resources': len(all_uploaded_resources),
            'duration_hours': round(job_elapsed_hours, 2),
            'status': 'completed',
            'action': 'backup_completed'
        })
        
        # Flush all remaining data
        log_writer.flush()
        sql_writer.flush_all()
        
        # Update activity log to completed via API (non-blocking - don't fail backup if this fails)
        try:
            completion_comment = f"Backup completed successfully for {user_email}: {len(all_uploaded_resources)} resources in {job_elapsed_hours:.2f} hours"
            api_client.update_activity_log(completion_comment, 'completed')
        except Exception as e:
            # Silently ignore - backup succeeded, activity log update is optional
            pass
        
        # Close file writers
        log_writer.close()
        sql_writer.close()
        
        return True
        
    except Exception as e:
        job_elapsed_hours = (time.time() - job_start_time) / 3600 if 'job_start_time' in locals() else 0
        log_message(f"ERROR in process_backup_job after {job_elapsed_hours:.2f} hours: {str(e)}", 'ERROR')
        log_message(traceback.format_exc(), 'ERROR')
        
        # Send error log via API
        if 'log_writer' in locals():
            try:
                log_writer.write('error', f"Backup failed for {user_email}: {str(e)}", {
                    'user_email': user_email,
                    'error': str(e),
                    'duration_hours': round(job_elapsed_hours, 2),
                    'action': 'backup_failed'
                })
                log_writer.flush()
                log_writer.close()
            except Exception as log_error:
                log_message(f"Error sending error log to API: {str(log_error)}", 'ERROR')
        
        # Update activity log to error status via API (non-blocking)
        if 'api_client' in locals():
            try:
                error_comment = f"Backup failed for {user_email}: {str(e)}"
                api_client.update_activity_log(error_comment, 'error')
            except Exception as update_error:
                # Silently ignore - error already logged above
                pass
        
        # Close SQL writer if it exists
        if 'sql_writer' in locals():
            try:
                sql_writer.close()
            except:
                pass
        
        return False

def main():
    """Main worker loop"""
    log_message("=" * 60)
    log_message("=== Python Backup Worker Starting ===")
    log_message("=" * 60)
    
    # Load configuration - use default queue URL if not set via environment variable
    global SQS_BACKUP_QUEUE_URL
    if not SQS_BACKUP_QUEUE_URL:
        # Default queue URL (hardcoded for reliability)
        SQS_BACKUP_QUEUE_URL = 'https://sqs.us-east-2.amazonaws.com/611474050854/backup_jobs'
        log_message(f"⚠️ WARNING: SQS_BACKUP_QUEUE_URL not set in environment, using default: {SQS_BACKUP_QUEUE_URL}", 'WARNING')
    else:
        log_message(f"✓ Using SQS_BACKUP_QUEUE_URL from environment: {SQS_BACKUP_QUEUE_URL}")
    
    log_message(f"Configuration:")
    log_message(f"  Region: {AWS_REGION}")
    log_message(f"  Backup Queue: {SQS_BACKUP_QUEUE_URL}")
    log_message(f"  Index Queue: {SQS_INDEX_QUEUE_URL or 'Not configured'}")
    log_message(f"  Max Workers: {MAX_WORKERS}")
    log_message(f"  Visibility Timeout: {VISIBILITY_TIMEOUT} seconds ({VISIBILITY_TIMEOUT/3600:.1f} hours)")
    log_message(f"  Visibility Extension: Every {VISIBILITY_EXTEND_INTERVAL/3600:.1f} hours")
    log_message("")
    log_message("🚀 NO LIMITS MODE:")
    log_message("  ✓ No time limits - can run for 10+ hours")
    log_message("  ✓ No message limits - processes ALL messages")
    log_message("  ✓ No file limits - processes ALL files")
    log_message("  ✓ Automatic visibility timeout extension")
    log_message("  ✓ Automatic rate limit handling")
    log_message("")
    # Test SQS connection before starting
    log_message("Testing SQS connection...")
    try:
        sqs_client.get_queue_attributes(
            QueueUrl=SQS_BACKUP_QUEUE_URL,
            AttributeNames=['QueueArn', 'ApproximateNumberOfMessages']
        )
        log_message("✓ SQS connection successful")
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        log_message(f"❌ CRITICAL: Cannot connect to SQS queue: {error_code} - {error_msg}", 'ERROR')
        log_message(f"Queue URL: {SQS_BACKUP_QUEUE_URL}", 'ERROR')
        log_message("Please check: 1) Queue exists, 2) AWS credentials/permissions, 3) Queue URL is correct", 'ERROR')
        sys.exit(1)
    except Exception as e:
        log_message(f"❌ CRITICAL: Error testing SQS connection: {str(e)}", 'ERROR')
        log_message(traceback.format_exc(), 'ERROR')
        sys.exit(1)
    
    log_message("Starting to poll SQS queue...")
    log_message("Press Ctrl+C to stop gracefully")
    log_message("")
    
    processed_count = 0
    error_count = 0
    
    # Use thread pool for concurrent processing
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while True:
            try:
                # Receive messages from SQS
                try:
                    response = sqs_client.receive_message(
                        QueueUrl=SQS_BACKUP_QUEUE_URL,
                        MaxNumberOfMessages=min(MAX_WORKERS, 10),
                        WaitTimeSeconds=POLL_WAIT_TIME,
                        VisibilityTimeout=VISIBILITY_TIMEOUT
                    )
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                    error_msg = e.response.get('Error', {}).get('Message', str(e))
                    log_message(f"❌ SQS ClientError: {error_code} - {error_msg}", 'ERROR')
                    log_message(f"Queue URL: {SQS_BACKUP_QUEUE_URL}", 'ERROR')
                    log_message("Waiting 30 seconds before retry...", 'WARNING')
                    time.sleep(30)
                    continue
                except Exception as e:
                    log_message(f"❌ Error receiving messages from SQS: {str(e)}", 'ERROR')
                    log_message(traceback.format_exc(), 'ERROR')
                    log_message("Waiting 30 seconds before retry...", 'WARNING')
                    time.sleep(30)
                    continue
                
                messages = response.get('Messages', [])
                
                if not messages:
                    log_message("No messages available. Waiting...")
                    continue
                
                log_message(f"✓ Received {len(messages)} message(s) from SQS")
                
                # Process messages concurrently
                futures = []
                for message in messages:
                    try:
                        job_data = json.loads(message['Body'])
                        receipt_handle = message['ReceiptHandle']
                        
                        # Submit job to thread pool
                        future = executor.submit(process_job_with_cleanup, job_data, receipt_handle)
                        futures.append(future)
                        
                    except json.JSONDecodeError as e:
                        log_message(f"ERROR: Invalid JSON in message: {str(e)}", 'ERROR')
                        # Delete bad message
                        try:
                            sqs_client.delete_message(
                                QueueUrl=SQS_BACKUP_QUEUE_URL,
                                ReceiptHandle=message['ReceiptHandle']
                            )
                        except:
                            pass
                    except Exception as e:
                        log_message(f"ERROR parsing message: {str(e)}", 'ERROR')
                
                # Wait for all jobs to complete
                for future in as_completed(futures):
                    try:
                        success = future.result()
                        if success:
                            processed_count += 1
                        else:
                            error_count += 1
                    except Exception as e:
                        log_message(f"ERROR in job execution: {str(e)}", 'ERROR')
                        error_count += 1
                
                log_message(f"Stats: {processed_count} processed, {error_count} errors")
                
            except KeyboardInterrupt:
                log_message("")
                log_message("Received interrupt signal. Shutting down gracefully...")
                break
            except Exception as e:
                log_message(f"ERROR in main loop: {str(e)}", 'ERROR')
                log_message(traceback.format_exc(), 'ERROR')
                time.sleep(10)
    
    log_message("")
    log_message("=" * 60)
    log_message(f"=== Worker Stopped ===")
    log_message(f"Total processed: {processed_count}")
    log_message(f"Total errors: {error_count}")
    log_message("=" * 60)

def process_job_with_cleanup(job_data: Dict, receipt_handle: str) -> bool:
    """Process job and handle message deletion - NO TIME LIMITS"""
    try:
        # Pass receipt_handle and sqs_client to process_backup_job for visibility timeout extension
        success = process_backup_job(job_data, receipt_handle, sqs_client)
        
        if success:
            # Delete message from queue
            sqs_client.delete_message(
                QueueUrl=SQS_BACKUP_QUEUE_URL,
                ReceiptHandle=receipt_handle
            )
            log_message("✓ Message deleted from queue")
        else:
            log_message("✗ Job failed. Message will be retried or sent to DLQ", 'WARNING')
        
        return success
    except Exception as e:
        log_message(f"ERROR in process_job_with_cleanup: {str(e)}", 'ERROR')
        return False

if __name__ == '__main__':
    main()

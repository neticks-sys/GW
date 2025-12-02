#!/usr/bin/env python3
"""
Backup File Writers
Handles local file writing for logs and SQL batches
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class BackupLogWriter:
    """Writes backup logs to local file and sends to API in batches"""
    
    def __init__(self, log_file_path: str, api_client, batch_size: int = 500):
        self.log_file_path = log_file_path
        self.api_client = api_client
        self.batch_size = batch_size
        self.log_buffer = []
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        
    def write(self, log_level: str, message: str, metadata: Optional[Dict] = None):
        """Write log entry to file and buffer"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'level': log_level,
            'message': message,
            'metadata': metadata or {}
        }
        
        # Write to file
        try:
            with open(self.log_file_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Error writing to log file: {str(e)}")
        
        # Add to buffer
        self.log_buffer.append(log_entry)
        
        # Send to API if buffer is full or if it's an important event
        if len(self.log_buffer) >= self.batch_size or self._is_important_event(log_level, message):
            self.flush()
    
    def _is_important_event(self, log_level: str, message: str) -> bool:
        """Check if this is an important event that should be sent immediately"""
        important_keywords = ['started', 'completed', 'failed', 'error', 'finished', 'backup running']
        return log_level in ['error', 'warning'] or any(keyword in message.lower() for keyword in important_keywords)
    
    def flush(self):
        """Send buffered logs to API and clear buffer"""
        if not self.log_buffer:
            return
        
        # Send each log entry to API
        for entry in self.log_buffer:
            self.api_client.send_log(
                entry['level'],
                entry['message'],
                entry['metadata']
            )
        
        # Clear buffer and log file
        self.log_buffer = []
        try:
            if os.path.exists(self.log_file_path):
                os.remove(self.log_file_path)
        except Exception as e:
            logger.warning(f"Could not clear log file: {str(e)}")
    
    def close(self):
        """Flush remaining logs and close"""
        self.flush()


class BackupSqlWriter:
    """Writes SQL batches to local files and sends to API"""
    
    def __init__(self, sql_dir: str, api_client, batch_size: int = 500):
        self.sql_dir = sql_dir
        self.api_client = api_client
        self.batch_size = batch_size
        self.current_batch = {}
        self.batch_counters = {}  # Track batch numbers per table
        
        # Ensure directory exists
        os.makedirs(sql_dir, exist_ok=True)
    
    def add_insert(self, table: str, values_sql: str):
        """
        Add INSERT values to batch
        
        Args:
            table: Table name
            values_sql: VALUES clause (e.g., "(val1, val2, ...), (val3, val4, ...)")
        """
        if table not in self.current_batch:
            self.current_batch[table] = []
            self.batch_counters[table] = 0
        
        self.current_batch[table].append(values_sql)
        
        # If batch is full, send it
        if len(self.current_batch[table]) >= self.batch_size:
            self.flush_table(table)
    
    def flush_table(self, table: str):
        """Flush and send SQL batch for a specific table"""
        if table not in self.current_batch or not self.current_batch[table]:
            return
        
        # Get column names for each table
        table_columns = {
            'backup_GW_emails': '(instance_id, domain, account_id, platform_type, session_id, message_id, thread_id, subject, from_address, to_addresses, cc_addresses, bcc_addresses, date_sent, date_received, s3_key, s3_key_json, file_size, mime_type, has_attachments, attachment_count, label, labels_json, attachments_json, backup_date)',
            'backup_GW_email_attachments': '(instance_id, domain, account_id, platform_type, session_id, message_id, attachment_index, attachment_filename, s3_key, content_type, file_size, backup_date)',
            'backup_GW_drive': '(instance_id, domain, account_id, platform_type, session_id, file_id, file_name, mime_type, file_size, parent_folder_id, folder_path, file_extension, shared, starred, trashed, view_count, s3_key, s3_key_native, s3_key_content, backup_date)',
            'backup_GW_drive_folders': '(instance_id, domain, account_id, platform_type, session_id, folder_id, folder_name, parent_folder_id, folder_path, backup_date)',
            'backup_GW_calendar': '(instance_id, domain, account_id, platform_type, session_id, event_id, calendar_id, calendar_name, summary, description, location, start_time, end_time, timezone, all_day, recurrence, organizer_email, attendee_count, attendees_json, s3_key, s3_key_ics, backup_date)',
            'backup_GW_contacts': '(instance_id, domain, account_id, platform_type, session_id, contact_id, resource_name, display_name, given_name, family_name, middle_name, prefix, suffix, primary_email, emails_json, primary_phone, phones_json, addresses_json, organization, job_title, department, s3_key, s3_key_vcf, backup_date)'
        }
        
        columns = table_columns.get(table, '')
        if not columns:
            logger.error(f"Unknown table: {table}")
            self.current_batch[table] = []
            return
        
        self.batch_counters[table] = self.batch_counters.get(table, 0) + 1
        batch_number = self.batch_counters[table]
        
        # Build complete INSERT statement with ON DUPLICATE KEY UPDATE
        # This handles duplicates gracefully by updating existing records instead of failing
        values_list = ', '.join(self.current_batch[table])
        
        # Define ON DUPLICATE KEY UPDATE clauses for each table
        on_duplicate_clauses = {
            'backup_GW_emails': 'ON DUPLICATE KEY UPDATE s3_key = VALUES(s3_key), s3_key_json = VALUES(s3_key_json), file_size = VALUES(file_size), backup_date = VALUES(backup_date), updated_at = NOW()',
            'backup_GW_email_attachments': 'ON DUPLICATE KEY UPDATE s3_key = VALUES(s3_key), content_type = VALUES(content_type), file_size = VALUES(file_size), backup_date = VALUES(backup_date)',
            'backup_GW_drive': 'ON DUPLICATE KEY UPDATE s3_key = VALUES(s3_key), s3_key_native = VALUES(s3_key_native), s3_key_content = VALUES(s3_key_content), file_size = VALUES(file_size), backup_date = VALUES(backup_date), updated_at = NOW()',
            'backup_GW_drive_folders': 'ON DUPLICATE KEY UPDATE folder_path = VALUES(folder_path), backup_date = VALUES(backup_date)',
            'backup_GW_calendar': 'ON DUPLICATE KEY UPDATE s3_key = VALUES(s3_key), s3_key_ics = VALUES(s3_key_ics), backup_date = VALUES(backup_date), updated_at = NOW()',
            'backup_GW_contacts': 'ON DUPLICATE KEY UPDATE s3_key = VALUES(s3_key), s3_key_vcf = VALUES(s3_key_vcf), backup_date = VALUES(backup_date), updated_at = NOW()'
        }
        
        on_duplicate = on_duplicate_clauses.get(table, '')
        if on_duplicate:
            full_sql = f"INSERT INTO {table} {columns} VALUES {values_list} {on_duplicate}"
        else:
            # Fallback to simple INSERT if table not in list
            full_sql = f"INSERT INTO {table} {columns} VALUES {values_list}"
        
        total_items = len(self.current_batch[table])
        
        # Send to API
        success = self.send_batch(table, full_sql, total_items)
        
        # Clear batch
        self.current_batch[table] = []
    
    def send_batch(self, table: str, full_sql: str, total_items: int) -> bool:
        """
        Send a complete SQL batch to API
        
        Args:
            table: Table name
            full_sql: Complete SQL INSERT statement
            total_items: Number of items in batch
            
        Returns:
            True if successful
        """
        self.batch_counters[table] = self.batch_counters.get(table, 0) + 1
        batch_number = self.batch_counters[table]
        
        # Write to file
        sql_file = os.path.join(self.sql_dir, f"{table}_batch_{batch_number}.sql")
        try:
            with open(sql_file, 'w', encoding='utf-8') as f:
                f.write(full_sql)
        except Exception as e:
            logger.error(f"Error writing SQL file: {str(e)}")
            return False
        
        # Send to API
        logger.info(f"📤 Sending SQL batch to API: table={table}, batch_number={batch_number}, total_items={total_items}")
        if table == 'backup_GW_drive':
            logger.info(f"🚨 DRIVE BATCH: About to send {total_items} drive files to MySQL via API")
            logger.info(f"🚨 DRIVE BATCH: SQL preview (first 500 chars): {full_sql[:500]}")
        
        success = self.api_client.send_sql_batch(table, full_sql, batch_number, total_items)
        
        if success:
            logger.info(f"✓ SQL batch sent successfully: {total_items} items for table {table}")
            if table == 'backup_GW_drive':
                logger.info(f"✅ DRIVE BATCH SUCCESS: {total_items} drive files sent to API - should be in MySQL now")
        else:
            logger.error(f"❌ SQL batch FAILED to send: {total_items} items for table {table}")
            if table == 'backup_GW_drive':
                logger.error(f"🚨 DRIVE BATCH FAILED: {total_items} drive files NOT sent to MySQL - check API endpoint!")
        
        # Delete file if successful
        if success and os.path.exists(sql_file):
            try:
                os.remove(sql_file)
            except Exception as e:
                logger.warning(f"Could not delete SQL file: {str(e)}")
        
        return success
    
    def flush_all(self):
        """Flush all pending batches"""
        for table in list(self.current_batch.keys()):
            if self.current_batch[table]:
                self.flush_table(table)
    
    def close(self):
        """Flush all and close"""
        self.flush_all()


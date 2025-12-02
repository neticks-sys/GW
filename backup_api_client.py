#!/usr/bin/env python3
"""
Backup API Client
Handles communication with the backup API endpoints
"""

import requests
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

class BackupApiClient:
    """
    Client for communicating with backup API endpoints
    
    IMPORTANT: API base URL must always be https://console.neticks.com/api
    This is hardcoded in backup_launcher.php to ensure Python worker on EC2 can contact the API
    """
    
    def __init__(self, api_base_url: str, api_key: str, instance_id: str, domain: str, 
                 account_id: str, session_id: str, user_email: str = ''):
        # IMPORTANT: API base URL must be https://console.neticks.com/api
        self.api_base_url = api_base_url.rstrip('/')
        self.api_key = api_key
        self.instance_id = instance_id
        self.domain = domain
        self.account_id = account_id
        self.session_id = session_id
        self.user_email = user_email
        
    def send_log(self, log_level: str, message: str, metadata: Optional[Dict] = None) -> bool:
        """
        Send log update to API
        
        Args:
            log_level: Log level (info, warning, error)
            message: Log message
            metadata: Optional metadata dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            url = f"{self.api_base_url}/google_workspace/backup_log.php"
            
            data = {
                'api_key': self.api_key,
                'instance_id': self.instance_id,
                'domain': self.domain,
                'account_id': self.account_id,
                'user_email': self.user_email,
                'session_id': self.session_id,
                'log_level': log_level,
                'message': message,
                'metadata': metadata or {}
            }
            
            response = requests.post(url, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    logger.info(f"✓ Log sent to API: {message[:50]}...")
                    return True
                else:
                    logger.error(f"API returned error: {result.get('error', 'Unknown error')}")
                    return False
            else:
                logger.error(f"API request failed with status {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending log to API: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending log: {str(e)}")
            return False
    
    def send_sql_batch(self, table: str, sql_batch: str, batch_number: int, total_items: int) -> bool:
        """
        Send SQL batch to API
        
        Args:
            table: Table name (backup_GW_emails, backup_GW_drive, etc.)
            sql_batch: SQL INSERT statement with multiple VALUES
            batch_number: Batch number for tracking
            total_items: Number of items in batch
            
        Returns:
            True if successful, False otherwise
        """
        try:
            url = f"{self.api_base_url}/google_workspace/backup_data.php"
            
            data = {
                'api_key': self.api_key,
                'instance_id': self.instance_id,
                'domain': self.domain,
                'account_id': self.account_id,
                'user_email': self.user_email,
                'session_id': self.session_id,
                'table': table,
                'sql_batch': sql_batch,
                'batch_number': batch_number,
                'total_items': total_items
            }
            
            response = requests.post(url, json=data, timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    data = result.get('data', {})
                    rows_inserted = data.get('rows_inserted', 0)
                    rows_updated = data.get('rows_updated', 0)
                    note = data.get('note', '')
                    
                    # Check if this is a duplicate update case (expected with ON DUPLICATE KEY UPDATE)
                    is_duplicate_update = ('duplicate' in note.lower() or 'updated' in note.lower()) and rows_updated > 0
                    
                    if is_duplicate_update:
                        # All rows were duplicates and updated - this is expected and OK
                        logger.info(f"✓ SQL batch {batch_number} sent to API: {rows_updated} rows updated (all were duplicates) for table {table}")
                    elif rows_inserted > 0:
                        logger.info(f"✓ SQL batch {batch_number} sent to API: {rows_inserted} rows inserted into MySQL for table {table}")
                    elif rows_inserted == 0 and total_items > 0:
                        # Only warn if it's not a duplicate update case
                        logger.warning(f"⚠️ WARNING: 0 rows inserted but {total_items} items sent - possible duplicate entries or schema issue")
                        logger.warning(f"⚠️ This means items were uploaded to S3 but may NOT be in MySQL!")
                    return True
                else:
                    error_msg = result.get('error', 'Unknown error')
                    logger.error(f"❌ API returned error sending SQL batch: {error_msg}")
                    logger.error(f"❌ This means emails were uploaded to S3 but NOT inserted into MySQL!")
                    # Check if it's a schema error (missing columns)
                    if 'Unknown column' in error_msg or 'Missing columns' in error_msg or 'schema' in error_msg.lower():
                        logger.error(f"❌ CRITICAL: Database schema mismatch detected. Please run SQL ALTER statement to add label and labels_json columns.")
                    return False
            else:
                error_text = response.text[:500]  # Limit error text length
                logger.error(f"❌ API request failed with status {response.status_code}: {error_text}")
                # Check if it's a schema error
                if 'Unknown column' in error_text or 'Missing columns' in error_text:
                    logger.error(f"❌ CRITICAL: Database schema mismatch detected. Please run SQL ALTER statement to add label and labels_json columns.")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending SQL batch to API: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending SQL batch: {str(e)}")
            return False
    
    def update_activity_log(self, comment: str, status: str = 'completed') -> bool:
        """
        Update activity log entry via API
        
        Args:
            comment: Comment/description for the activity
            status: Status ('pending', 'processing', 'completed', 'error')
            
        Returns:
            True if successful, False otherwise
        """
        try:
            url = f"{self.api_base_url}/google_workspace/update_activity_log.php"
            
            data = {
                'api_key': self.api_key,
                'instance_id': self.instance_id,
                'domain': self.domain,
                'account_id': self.account_id,
                'session_id': self.session_id,
                'comment': comment,
                'status': status
            }
            
            response = requests.post(url, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return True
                else:
                    # Silently fail - activity log update is optional
                    return False
            else:
                # Silently fail - endpoint may not exist yet, don't spam logs
                return False
                
        except requests.exceptions.RequestException as e:
            # Silently fail - activity log update is optional
            return False
        except Exception as e:
            # Silently fail - activity log update is optional
            return False
    
    def get_last_backup_timestamp(self, user_email: str, service_type: str) -> Optional[Dict]:
        """
        Get last backup timestamp from database via API
        
        Args:
            user_email: User email address
            service_type: Service type ('emails', 'drive', 'calendar', 'contacts')
            
        Returns:
            Dictionary with last_backup_timestamp, backup_type, etc., or None if error/no backup
        """
        try:
            url = f"{self.api_base_url}/google_workspace/get_last_backup_timestamp.php"
            
            data = {
                'api_key': self.api_key,
                'instance_id': self.instance_id,
                'domain': self.domain,
                'account_id': self.account_id,
                'user_email': user_email,
                'service_type': service_type
            }
            
            response = requests.post(url, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    last_backup_data = result.get('data', {})
                    if last_backup_data.get('last_backup_timestamp'):
                        return last_backup_data
                    else:
                        # No backup found
                        return None
                else:
                    logger.warning(f"API returned error getting last backup timestamp: {result.get('error', 'Unknown error')}")
                    return None
            else:
                logger.warning(f"API request failed with status {response.status_code} getting last backup timestamp")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error getting last backup timestamp from API: {str(e)}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error getting last backup timestamp: {str(e)}")
            return None
    
    def check_backed_up_items(self, service_type: str, item_ids: List[str]) -> Dict[str, List[str]]:
        """
        Check which items are already backed up in the database
        
        Args:
            service_type: Service type ('emails', 'drive', 'calendar', 'contacts')
            item_ids: List of item IDs to check (message_id, file_id, event_id, contact_id)
            
        Returns:
            Dictionary with 'backed_up_items' and 'new_items' lists
        """
        try:
            url = f"{self.api_base_url}/google_workspace/check_backed_up_items.php"
            
            data = {
                'api_key': self.api_key,
                'instance_id': self.instance_id,
                'domain': self.domain,
                'account_id': self.account_id,
                'service_type': service_type,
                'item_ids': item_ids
            }
            
            response = requests.post(url, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    data = result.get('data', {})
                    backed_up = data.get('backed_up_items', [])
                    new_items = data.get('new_items', [])
                    
                    # DEBUG: Log if new_items is empty but we have item_ids
                    if not new_items and len(item_ids) > 0 and len(backed_up) < len(item_ids):
                        logger.warning(f"API returned empty new_items but {len(item_ids)} items checked and only {len(backed_up)} backed up - calculating new_items manually")
                        # Calculate new_items ourselves as fallback
                        new_items = [item_id for item_id in item_ids if item_id not in backed_up]
                    
                    return {
                        'backed_up_items': backed_up,
                        'new_items': new_items
                    }
                else:
                    logger.warning(f"API returned error checking backed up items: {result.get('error', 'Unknown error')}")
                    return {'backed_up_items': [], 'new_items': item_ids}  # Assume all are new if API fails
            else:
                logger.warning(f"API request failed with status {response.status_code} checking backed up items")
                return {'backed_up_items': [], 'new_items': item_ids}  # Assume all are new if API fails
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error checking backed up items from API: {str(e)}")
            return {'backed_up_items': [], 'new_items': item_ids}  # Assume all are new if API fails
        except Exception as e:
            logger.warning(f"Unexpected error checking backed up items: {str(e)}")
            return {'backed_up_items': [], 'new_items': item_ids}  # Assume all are new if API fails


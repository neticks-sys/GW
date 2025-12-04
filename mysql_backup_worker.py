#!/usr/bin/env python3
"""
MySQL-based Backup Worker
Reads tasks from MySQL queue and processes them using backup_worker.py
"""

import os
import sys
import json
import time
import pymysql

# Add /opt/neticks to path for imports
sys.path.insert(0, '/opt/neticks')

# Verify backup_worker.py is available
if not os.path.exists('/opt/neticks/backup_worker.py'):
    print('CRITICAL ERROR: backup_worker.py not found at /opt/neticks/backup_worker.py')
    print('Files in /opt/neticks/:')
    try:
        import subprocess
        result = subprocess.run(['ls', '-la', '/opt/neticks/'], capture_output=True, text=True)
        print(result.stdout)
    except:
        pass
    sys.exit(1)

# Load MySQL credentials
def load_mysql_config():
    config = {}
    with open('/etc/neticks/mysql.env', 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                config[key] = value
    return config

mysql_config = load_mysql_config()
mysql_host = mysql_config.get('MYSQL_HOST', 'localhost')
mysql_user = mysql_config.get('MYSQL_USER', 'root')
mysql_password = mysql_config.get('MYSQL_PASSWORD', '')
mysql_database = mysql_config.get('MYSQL_DATABASE', 'neticks_backup')

def get_pending_tasks():
    """Get next pending task from MySQL queue (FIFO)"""
    try:
        conn = pymysql.connect(
            host=mysql_host, 
            user=mysql_user, 
            password=mysql_password, 
            database=mysql_database,
            connect_timeout=10
        )
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM backup_tasks WHERE status='pending' ORDER BY created_at ASC LIMIT 1")
        task = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if task:
            print('MySQL queue: Found pending task ' + task['task_id'] + ' for user ' + task['user_email'])
        else:
            print('MySQL queue: No pending tasks found')
        
        return task
    except Exception as e:
        print('ERROR: Failed to get pending tasks from MySQL: ' + str(e))
        return None

def update_task_status(task_id, status, error_message=None):
    """Update task status in MySQL queue"""
    try:
        conn = pymysql.connect(
            host=mysql_host, 
            user=mysql_user, 
            password=mysql_password, 
            database=mysql_database,
            connect_timeout=10
        )
        cursor = conn.cursor()
        
        if error_message:
            cursor.execute(
                "UPDATE backup_tasks SET status=%s, error_message=%s, updated_at=NOW() WHERE task_id=%s",
                (status, error_message, task_id)
            )
            print('MySQL updated: task ' + task_id + ' -> ' + status + ' (error: ' + error_message + ')')
        else:
            if status == 'processing':
                cursor.execute(
                    "UPDATE backup_tasks SET status=%s, started_at=NOW(), updated_at=NOW() WHERE task_id=%s",
                    (status, task_id)
                )
                print('MySQL updated: task ' + task_id + ' -> processing')
            elif status == 'completed':
                cursor.execute(
                    "UPDATE backup_tasks SET status=%s, completed_at=NOW(), updated_at=NOW() WHERE task_id=%s",
                    (status, task_id)
                )
                print('MySQL updated: task ' + task_id + ' -> completed')
            elif status == 'failed':
                cursor.execute(
                    "UPDATE backup_tasks SET status=%s, updated_at=NOW() WHERE task_id=%s",
                    (status, task_id)
                )
                print('MySQL updated: task ' + task_id + ' -> failed')
            else:
                cursor.execute(
                    "UPDATE backup_tasks SET status=%s, updated_at=NOW() WHERE task_id=%s",
                    (status, task_id)
                )
                print('MySQL updated: task ' + task_id + ' -> ' + status)
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print('ERROR: Failed to update task status in MySQL: ' + str(e))
        return False

# Main worker loop
print('Starting MySQL-based backup worker...')
session_id = os.getenv('SESSION_ID', '')

while True:
    task = get_pending_tasks()
    if task:
        try:
            print('Processing task: ' + task['task_id'] + ' for user: ' + task['user_email'])
            update_task_status(task['task_id'], 'processing')
            
            # Prepare job data in format expected by backup_worker.py
            job_data = {
                'instance_id': task['instance_id'],
                'domain': task['domain'],
                'account_id': task['account_id'],
                'user_email': task['user_email'],
                'scope': task['scope'],
                'mode': task['mode'],
                'source': task['source'],
                'session_id': task['session_id'],
                'job_id': task['job_id'],
                'created_at': task['created_at'].isoformat() if hasattr(task['created_at'], 'isoformat') else str(task['created_at']),
                'backup_requirements': json.loads(task['backup_requirements']) if isinstance(task['backup_requirements'], str) else task['backup_requirements'],
                'instance': json.loads(task['instance_data']) if isinstance(task['instance_data'], str) else task['instance_data'],
                'api_key': task['api_key'],
                'api_base_url': task['api_base_url']
            }
            
            # Import and call backup worker
            try:
                from backup_worker import process_backup_job
                
                # Process backup job (pass None for SQS parameters)
                result = process_backup_job(job_data, receipt_handle=None, sqs_client_instance=None)
                
                # Update task status based on result
                if result is True:
                    update_task_status(task['task_id'], 'completed')
                    print('Task ' + task['task_id'] + ' completed successfully')
                else:
                    update_task_status(task['task_id'], 'failed', 'Backup job returned False')
                    print('Task ' + task['task_id'] + ' failed')
            except ImportError as import_err:
                error_msg = 'Failed to import backup_worker: ' + str(import_err)
                update_task_status(task['task_id'], 'failed', error_msg)
                print('ERROR: ' + error_msg)
            except Exception as worker_err:
                error_msg = 'Backup worker error: ' + str(worker_err)
                update_task_status(task['task_id'], 'failed', error_msg)
                print('ERROR: ' + error_msg)
        except Exception as e:
            error_msg = str(e)
            print('Error processing task ' + task['task_id'] + ': ' + error_msg)
            update_task_status(task['task_id'], 'failed', error_msg)
    else:
        time.sleep(5)


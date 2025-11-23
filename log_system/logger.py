"""
Comprehensive logging system for IAM Protocol Testing Application.
Handles flow step tracking, HTTP logging, and error capture.
"""

import logging
import os
from datetime import datetime
from typing import Optional, Dict, Any
import json


class TestLogger:
    """
    Logger for authentication flow testing.
    Captures detailed information about each step of the flow.
    """
    
    def __init__(self, test_result_id: Optional[int] = None, db_session=None):
        """
        Initialize test logger.
        
        Args:
            test_result_id: ID of the test result to associate logs with
            db_session: Database session for storing logs
        """
        self.test_result_id = test_result_id
        self.db_session = db_session
        self.logs = []
        self.current_step = None
        
        # Set up Python logger
        self.logger = logging.getLogger(f'test_{test_result_id}')
        self.logger.setLevel(logging.DEBUG)
    
    def set_step(self, step_name: str):
        """Set the current flow step."""
        self.current_step = step_name
        self.info(f"Starting step: {step_name}")
    
    def _create_log_entry(
        self,
        level: str,
        message: str,
        details: Optional[Dict] = None,
        http_data: Optional[Dict] = None
    ) -> Dict:
        """Create a log entry dictionary."""
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': level,
            'step': self.current_step,
            'message': message,
        }
        
        if details:
            entry['details'] = details
        
        if http_data:
            entry['http'] = http_data
        
        return entry
    
    def _save_to_db(self, entry: Dict):
        """Save log entry to database."""
        if not self.db_session or not self.test_result_id:
            return
        
        from models import LogEntry
        
        log_entry = LogEntry(
            test_result_id=self.test_result_id,
            timestamp=datetime.fromisoformat(entry['timestamp']),
            level=entry['level'],
            step=entry.get('step'),
            message=entry['message'],
            details=json.dumps(entry.get('details')) if entry.get('details') else None,
        )
        
        # Add HTTP data if present
        if 'http' in entry:
            http = entry['http']
            log_entry.http_method = http.get('method')
            log_entry.http_url = http.get('url')
            log_entry.http_status = http.get('status_code')
            
            if 'request' in http:
                req = http['request']
                log_entry.http_request_headers = json.dumps(req.get('headers'))
                log_entry.http_request_body = json.dumps(req.get('body')) if req.get('body') else None
            
            if 'response' in http:
                resp = http['response']
                log_entry.http_response_headers = json.dumps(resp.get('headers'))
                log_entry.http_response_body = json.dumps(resp.get('body')) if resp.get('body') else None
        
        self.db_session.add(log_entry)
        try:
            self.db_session.commit()
        except Exception as e:
            self.logger.error(f"Failed to save log to database: {str(e)}")
            self.db_session.rollback()
    
    def debug(self, message: str, details: Optional[Dict] = None):
        """Log debug message."""
        entry = self._create_log_entry('DEBUG', message, details)
        self.logs.append(entry)
        self.logger.debug(message)
        self._save_to_db(entry)
    
    def info(self, message: str, details: Optional[Dict] = None):
        """Log info message."""
        entry = self._create_log_entry('INFO', message, details)
        self.logs.append(entry)
        self.logger.info(message)
        self._save_to_db(entry)
    
    def warning(self, message: str, details: Optional[Dict] = None):
        """Log warning message."""
        entry = self._create_log_entry('WARNING', message, details)
        self.logs.append(entry)
        self.logger.warning(message)
        self._save_to_db(entry)
    
    def error(self, message: str, details: Optional[Dict] = None):
        """Log error message."""
        entry = self._create_log_entry('ERROR', message, details)
        self.logs.append(entry)
        self.logger.error(message)
        self._save_to_db(entry)
    
    def log_http_request(self, method: str, url: str, headers: Dict, body: Any = None):
        """Log HTTP request."""
        http_data = {
            'method': method,
            'url': url,
            'request': {
                'headers': headers,
                'body': body
            }
        }
        
        entry = self._create_log_entry(
            'DEBUG',
            f'HTTP Request: {method} {url}',
            http_data=http_data
        )
        self.logs.append(entry)
        self.logger.debug(f'{method} {url}')
        self._save_to_db(entry)
    
    def log_http_response(self, status_code: int, headers: Dict, body: Any = None, url: str = ''):
        """Log HTTP response."""
        http_data = {
            'status_code': status_code,
            'url': url,
            'response': {
                'headers': headers,
                'body': body
            }
        }
        
        level = 'ERROR' if status_code >= 400 else 'DEBUG'
        entry = self._create_log_entry(
            level,
            f'HTTP Response: {status_code}',
            http_data=http_data
        )
        self.logs.append(entry)
        self.logger.debug(f'Response: {status_code}')
        self._save_to_db(entry)
    
    def log_redirect(self, from_url: str, to_url: str):
        """Log HTTP redirect."""
        self.debug(f'Redirect: {from_url} -> {to_url}', {
            'from': from_url,
            'to': to_url
        })
    
    def log_token_received(self, token_type: str, token_preview: str):
        """Log token receipt."""
        self.info(f'{token_type} received', {
            'token_type': token_type,
            'preview': token_preview
        })
    
    def log_validation_result(self, validation_type: str, result: bool, details: Dict):
        """Log validation result."""
        level = 'INFO' if result else 'WARNING'
        message = f'{validation_type}: {"PASSED" if result else "FAILED"}'
        
        if level == 'INFO':
            self.info(message, details)
        else:
            self.warning(message, details)
    
    def get_logs(self) -> list:
        """Get all log entries."""
        return self.logs
    
    def get_logs_json(self) -> str:
        """Get logs as JSON string."""
        return json.dumps(self.logs, indent=2)


def setup_application_logging(log_file: str, log_level: str = 'DEBUG'):
    """
    Set up application-wide logging configuration.
    
    Args:
        log_file: Path to log file
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    # Reduce noise from third-party libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

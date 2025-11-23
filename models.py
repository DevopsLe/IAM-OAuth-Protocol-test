"""
Database models for IAM Protocol Testing Application.
Stores test configurations, results, and logs.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import json

db = SQLAlchemy()


class TestConfiguration(db.Model):
    """Stores saved test configurations for quick reuse."""
    
    __tablename__ = 'test_configurations'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    description = db.Column(db.Text)
    provider = db.Column(db.String(50), nullable=False)  # azure, okta, generic
    flow_type = db.Column(db.String(50), nullable=False)  # authorization_code_pkce, etc.
    
    # Configuration JSON
    config_json = db.Column(db.Text, nullable=False)  # Stores full config as JSON
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    test_results = db.relationship('TestResult', backref='configuration', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'provider': self.provider,
            'flow_type': self.flow_type,
            'config': json.loads(self.config_json),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
    
    @staticmethod
    def from_dict(data):
        """Create from dictionary."""
        return TestConfiguration(
            name=data['name'],
            description=data.get('description', ''),
            provider=data['provider'],
            flow_type=data['flow_type'],
            config_json=json.dumps(data['config'])
        )


class TestResult(db.Model):
    """Stores results from authentication flow tests."""
    
    __tablename__ = 'test_results'
    
    id = db.Column(db.Integer, primary_key=True)
    configuration_id = db.Column(db.Integer, db.ForeignKey('test_configurations.id'), nullable=True)
    
    # Test metadata
    provider = db.Column(db.String(50), nullable=False)
    flow_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # success, error, warning
    
    # Tokens (stored as JSON)
    id_token = db.Column(db.Text)
    access_token = db.Column(db.Text)
    refresh_token = db.Column(db.Text)
    
    # Decoded claims (stored as JSON)
    id_token_claims = db.Column(db.Text)
    access_token_claims = db.Column(db.Text)
    
    # Validation results
    token_validation = db.Column(db.Text)  # JSON with validation details
    
    # Authorization test results
    api_test_result = db.Column(db.Text)  # JSON with API call results
    
    # Error information
    error_message = db.Column(db.Text)
    error_details = db.Column(db.Text)  # JSON with detailed error info
    
    # Timestamps
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    log_entries = db.relationship('LogEntry', backref='test_result', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'configuration_id': self.configuration_id,
            'provider': self.provider,
            'flow_type': self.flow_type,
            'status': self.status,
            'tokens': {
                'id_token': self.id_token,
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
            },
            'claims': {
                'id_token': json.loads(self.id_token_claims) if self.id_token_claims else None,
                'access_token': json.loads(self.access_token_claims) if self.access_token_claims else None,
            },
            'validation': json.loads(self.token_validation) if self.token_validation else None,
            'api_test': json.loads(self.api_test_result) if self.api_test_result else None,
            'error': {
                'message': self.error_message,
                'details': json.loads(self.error_details) if self.error_details else None,
            } if self.error_message else None,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }


class LogEntry(db.Model):
    """Stores detailed log entries for each test."""
    
    __tablename__ = 'log_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    test_result_id = db.Column(db.Integer, db.ForeignKey('test_results.id'), nullable=False)
    
    # Log metadata
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    level = db.Column(db.String(20), nullable=False)  # DEBUG, INFO, WARNING, ERROR
    step = db.Column(db.String(100))  # Flow step name
    
    # Log content
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)  # JSON with additional details
    
    # HTTP request/response data
    http_method = db.Column(db.String(10))
    http_url = db.Column(db.Text)
    http_status = db.Column(db.Integer)
    http_request_headers = db.Column(db.Text)  # JSON
    http_request_body = db.Column(db.Text)
    http_response_headers = db.Column(db.Text)  # JSON
    http_response_body = db.Column(db.Text)
    
    def to_dict(self):
        """Convert to dictionary."""
        result = {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'level': self.level,
            'step': self.step,
            'message': self.message,
            'details': json.loads(self.details) if self.details else None,
        }
        
        # Add HTTP data if present
        if self.http_method:
            result['http'] = {
                'method': self.http_method,
                'url': self.http_url,
                'status': self.http_status,
                'request': {
                    'headers': json.loads(self.http_request_headers) if self.http_request_headers else None,
                    'body': self.http_request_body,
                },
                'response': {
                    'headers': json.loads(self.http_response_headers) if self.http_response_headers else None,
                    'body': self.http_response_body,
                }
            }
        
        return result


class SavedToken(db.Model):
    """Stores tokens for later analysis or reuse."""
    
    __tablename__ = 'saved_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    
    token_type = db.Column(db.String(20), nullable=False)  # id_token, access_token
    token_value = db.Column(db.Text, nullable=False)
    claims = db.Column(db.Text)  # JSON with decoded claims
    
    provider = db.Column(db.String(50))
    issuer = db.Column(db.String(200))
    subject = db.Column(db.String(200))
    
    issued_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'token_type': self.token_type,
            'token': self.token_value,
            'claims': json.loads(self.claims) if self.claims else None,
            'provider': self.provider,
            'issuer': self.issuer,
            'subject': self.subject,
            'issued_at': self.issued_at.isoformat() if self.issued_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat(),
        }

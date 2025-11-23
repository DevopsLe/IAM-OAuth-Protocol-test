"""
Mock resource server for testing authorization with access tokens.
"""

from flask import Blueprint, request, jsonify
from typing import Dict, Optional
import logging

from tokens.decoder import JWTDecoder
from tokens.validator import TokenValidator
from tokens.claims_analyzer import ClaimsAnalyzer

logger = logging.getLogger(__name__)

# Create Blueprint
resource_api = Blueprint('resource_api', __name__, url_prefix='/api')


class PermissionEngine:
    """Engine for validating permissions based on token claims."""
    
    # Define mock API endpoints and their required permissions
    ENDPOINTS = {
        '/api/public': {
            'name': 'Public Endpoint',
            'required_scopes': [],
            'required_roles': [],
            'description': 'Publicly accessible endpoint'
        },
        '/api/profile': {
            'name': 'User Profile',
            'required_scopes': ['profile'],
            'required_roles': [],
            'description': 'Requires profile scope'
        },
        '/api/email': {
            'name': 'User Email',
            'required_scopes': ['email'],
            'required_roles': [],
            'description': 'Requires email scope'
        },
        '/api/admin': {
            'name': 'Admin Endpoint',
            'required_scopes': [],
            'required_roles': ['Admin', 'Administrator'],
            'description': 'Requires admin role'
        },
        '/api/data/read': {
            'name': 'Read Data',
            'required_scopes': ['data.read'],
            'required_roles': [],
            'description': 'Requires data.read scope'
        },
        '/api/data/write': {
            'name': 'Write Data',
            'required_scopes': ['data.write'],
            'required_roles': [],
            'description': 'Requires data.write scope'
        },
    }
    
    @classmethod
    def check_permission(cls, endpoint: str, token_claims: Dict) -> Dict:
        """
        Check if token claims satisfy endpoint requirements.
        
        Args:
            endpoint: API endpoint path
            token_claims: Decoded token claims
            
        Returns:
            Dictionary with permission check results
        """
        endpoint_config = cls.ENDPOINTS.get(endpoint, {})
        
        if not endpoint_config:
            return {
                'allowed': False,
                'reason': 'Unknown endpoint',
                'endpoint': endpoint
            }
        
        # Extract scopes and roles from token
        token_scopes = ClaimsAnalyzer.extract_scopes(token_claims)
        token_roles = ClaimsAnalyzer.extract_roles(token_claims)
        
        # Check required scopes
        required_scopes = endpoint_config.get('required_scopes', [])
        missing_scopes = [scope for scope in required_scopes if scope not in token_scopes]
        
        # Check required roles
        required_roles = endpoint_config.get('required_roles', [])
        has_required_role = any(role in token_roles for role in required_roles) if required_roles else True
        
        # Determine if access is allowed
        allowed = len(missing_scopes) == 0 and has_required_role
        
        result = {
            'allowed': allowed,
            'endpoint': endpoint,
            'endpoint_name': endpoint_config.get('name'),
            'description': endpoint_config.get('description'),
            'required_scopes': required_scopes,
            'token_scopes': token_scopes,
            'missing_scopes': missing_scopes,
            'required_roles': required_roles,
            'token_roles': token_roles,
            'has_required_role': has_required_role,
        }
        
        if not allowed:
            if missing_scopes:
                result['reason'] = f"Missing required scopes: {', '.join(missing_scopes)}"
            elif not has_required_role:
                result['reason'] = f"Missing required role (one of: {', '.join(required_roles)})"
        
        return result


def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    """
    Extract bearer token from Authorization header.
    
    Args:
        auth_header: Authorization header value
        
    Returns:
        Token string or None
    """
    if not auth_header:
        return None
    
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    
    return parts[1]


def validate_request_token(required_scopes: list = None, required_roles: list = None):
    """
    Decorator to validate access token for API endpoints.
    
    Args:
        required_scopes: List of required scopes
        required_roles: List of required roles (user needs at least one)
    """
    def decorator(f):
        def wrapped(*args, **kwargs):
            # Extract token from Authorization header
            auth_header = request.headers.get('Authorization')
            token = extract_bearer_token(auth_header)
            
            if not token:
                return jsonify({
                    'error': 'unauthorized',
                    'message': 'Missing or invalid Authorization header',
                    'expected_format': 'Authorization: Bearer <token>'
                }), 401
            
            try:
                # Decode token
                decoded = JWTDecoder.decode(token)
                claims = decoded['payload']
                
                # Check scopes
                if required_scopes:
                    token_scopes = ClaimsAnalyzer.extract_scopes(claims)
                    missing_scopes = [s for s in required_scopes if s not in token_scopes]
                    
                    if missing_scopes:
                        return jsonify({
                            'error': 'forbidden',
                            'message': 'Insufficient permissions',
                            'required_scopes': required_scopes,
                            'token_scopes': token_scopes,
                            'missing_scopes': missing_scopes
                        }), 403
                
                # Check roles
                if required_roles:
                    token_roles = ClaimsAnalyzer.extract_roles(claims)
                    has_role = any(role in token_roles for role in required_roles)
                    
                    if not has_role:
                        return jsonify({
                            'error': 'forbidden',
                            'message': 'Insufficient permissions',
                            'required_roles': required_roles,
                            'token_roles': token_roles
                        }), 403
                
                # Add claims to request context
                request.token_claims = claims
                
                return f(*args, **kwargs)
                
            except Exception as e:
                return jsonify({
                    'error': 'invalid_token',
                    'message': f'Token validation failed: {str(e)}'
                }), 401
        
        wrapped.__name__ = f.__name__
        return wrapped
    
    return decorator


# Mock API Endpoints

@resource_api.route('/public', methods=['GET'])
def public_endpoint():
    """Public endpoint - no authentication required."""
    return jsonify({
        'message': 'This is a public endpoint',
        'data': 'Anyone can access this',
        'authenticated': False
    })


@resource_api.route('/profile', methods=['GET'])
@validate_request_token(required_scopes=['profile'])
def profile_endpoint():
    """Profile endpoint - requires 'profile' scope."""
    return jsonify({
        'message': 'Profile data retrieved successfully',
        'data': {
            'name': request.token_claims.get('name', 'Unknown'),
            'email': request.token_claims.get('email', 'Not provided'),
            'sub': request.token_claims.get('sub')
        },
        'authenticated': True,
        'scopes': ClaimsAnalyzer.extract_scopes(request.token_claims)
    })


@resource_api.route('/email', methods=['GET'])
@validate_request_token(required_scopes=['email'])
def email_endpoint():
    """Email endpoint - requires 'email' scope."""
    return jsonify({
        'message': 'Email data retrieved successfully',
        'data': {
            'email': request.token_claims.get('email', 'Not provided'),
            'email_verified': request.token_claims.get('email_verified', False)
        },
        'authenticated': True
    })


@resource_api.route('/admin', methods=['GET'])
@validate_request_token(required_roles=['Admin', 'Administrator'])
def admin_endpoint():
    """Admin endpoint - requires admin role."""
    return jsonify({
        'message': 'Admin access granted',
        'data': {
            'admin_data': 'Sensitive administrative information',
            'user': request.token_claims.get('name', 'Unknown')
        },
        'authenticated': True,
        'roles': ClaimsAnalyzer.extract_roles(request.token_claims)
    })


@resource_api.route('/data/read', methods=['GET'])
@validate_request_token(required_scopes=['data.read'])
def data_read_endpoint():
    """Data read endpoint - requires 'data.read' scope."""
    return jsonify({
        'message': 'Data retrieved successfully',
        'data': [
            {'id': 1, 'value': 'Sample data 1'},
            {'id': 2, 'value': 'Sample data 2'},
            {'id': 3, 'value': 'Sample data 3'}
        ],
        'authenticated': True
    })


@resource_api.route('/data/write', methods=['POST'])
@validate_request_token(required_scopes=['data.write'])
def data_write_endpoint():
    """Data write endpoint - requires 'data.write' scope."""
    data = request.get_json() or {}
    
    return jsonify({
        'message': 'Data written successfully',
        'written_data': data,
        'authenticated': True
    })


@resource_api.route('/test-token', methods=['POST'])
def test_token_endpoint():
    """
    Test endpoint to validate a token and check permissions.
    Accepts a token and endpoint path, returns permission check results.
    """
    data = request.get_json() or {}
    token = data.get('token')
    endpoint = data.get('endpoint', '/api/public')
    
    if not token:
        return jsonify({
            'error': 'missing_token',
            'message': 'Token is required'
        }), 400
    
    try:
        # Decode token
        decoded = JWTDecoder.decode(token)
        claims = decoded['payload']
        
        # Check permissions for requested endpoint
        permission_result = PermissionEngine.check_permission(endpoint, claims)
        
        return jsonify({
            'token_valid': True,
            'claims': claims,
            'permission_check': permission_result,
            'available_endpoints': list(PermissionEngine.ENDPOINTS.keys())
        })
        
    except Exception as e:
        return jsonify({
            'error': 'invalid_token',
            'message': f'Token validation failed: {str(e)}'
        }), 400

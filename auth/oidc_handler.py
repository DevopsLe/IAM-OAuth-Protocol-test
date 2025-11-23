"""
OIDC (OpenID Connect) handler for Authorization Code Flow with PKCE.
"""

import requests
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode, parse_qs, urlparse
import logging

from utils.crypto import generate_code_verifier, generate_code_challenge, generate_state, generate_nonce
from utils.http_client import HTTPClient

logger = logging.getLogger(__name__)


class OIDCHandler:
    """Handler for OIDC authentication flows."""
    
    def __init__(self, config: Dict, test_logger=None):
        """
        Initialize OIDC handler.
        
        Args:
            config: Provider configuration
            test_logger: Optional TestLogger instance
        """
        self.config = config
        self.test_logger = test_logger
        self.http_client = HTTPClient(log_callback=self._http_log_callback)
        
        # Flow state
        self.state = None
        self.nonce = None
        self.code_verifier = None
        self.code_challenge = None
        
        # Discovery document
        self.discovery_doc = None
    
    def _http_log_callback(self, event_type: str, data: Dict):
        """Callback for HTTP client logging."""
        if self.test_logger:
            if event_type == 'request':
                self.test_logger.log_http_request(
                    data['method'],
                    data['url'],
                    data.get('headers', {}),
                    data.get('body')
                )
            elif event_type == 'response':
                resp = data['response']
                self.test_logger.log_http_response(
                    resp['status_code'],
                    resp.get('headers', {}),
                    resp.get('body'),
                    resp.get('url', '')
                )
    
    def discover_endpoints(self) -> Dict:
        """
        Fetch and parse the OIDC discovery document.
        
        Returns:
            Discovery document dictionary
        """
        if self.test_logger:
            self.test_logger.set_step('Discovery')
            self.test_logger.info('Fetching OIDC discovery document')
        
        discovery_url = self.config.get('discovery_endpoint')
        
        if not discovery_url:
            # Construct from individual endpoints
            if self.test_logger:
                self.test_logger.warning('No discovery endpoint provided, using manual configuration')
            
            self.discovery_doc = {
                'authorization_endpoint': self.config.get('authorization_endpoint'),
                'token_endpoint': self.config.get('token_endpoint'),
                'userinfo_endpoint': self.config.get('userinfo_endpoint'),
                'jwks_uri': self.config.get('jwks_uri'),
                'issuer': self.config.get('issuer'),
            }
            return self.discovery_doc
        
        try:
            # Format discovery URL with template variables
            discovery_url = discovery_url.format(**self.config)
            
            response = self.http_client.get(discovery_url)
            self.discovery_doc = response.json()
            
            if self.test_logger:
                self.test_logger.info('Discovery document retrieved successfully', {
                    'issuer': self.discovery_doc.get('issuer'),
                    'authorization_endpoint': self.discovery_doc.get('authorization_endpoint'),
                    'token_endpoint': self.discovery_doc.get('token_endpoint'),
                })
            
            return self.discovery_doc
            
        except Exception as e:
            if self.test_logger:
                self.test_logger.error(f'Failed to fetch discovery document: {str(e)}')
            raise
    
    def build_authorization_url(
        self,
        redirect_uri: str,
        scopes: list,
        use_pkce: bool = True,
        response_type: str = 'code',
        extra_params: Optional[Dict] = None
    ) -> Tuple[str, Dict]:
        """
        Build the authorization URL for the OIDC flow.
        
        Args:
            redirect_uri: Redirect URI for callback
            scopes: List of requested scopes
            use_pkce: Whether to use PKCE
            response_type: Response type (default: 'code')
            extra_params: Additional query parameters
            
        Returns:
            Tuple of (authorization_url, flow_state)
        """
        if self.test_logger:
            self.test_logger.set_step('Authorization Request')
        
        # Ensure discovery has been performed
        if not self.discovery_doc:
            self.discover_endpoints()
        
        # Generate flow parameters
        self.state = generate_state()
        self.nonce = generate_nonce()
        
        if use_pkce:
            self.code_verifier = generate_code_verifier()
            self.code_challenge = generate_code_challenge(self.code_verifier)
        
        # Build authorization parameters
        auth_params = {
            'client_id': self.config['client_id'],
            'response_type': response_type,
            'redirect_uri': redirect_uri,
            'scope': ' '.join(scopes),
            'state': self.state,
            'nonce': self.nonce,
        }
        
        if use_pkce:
            auth_params['code_challenge'] = self.code_challenge
            auth_params['code_challenge_method'] = 'S256'
        
        # Add extra parameters
        if extra_params:
            auth_params.update(extra_params)
        
        # Build URL
        auth_endpoint = self.discovery_doc['authorization_endpoint']
        # Format endpoint with template variables if needed
        auth_endpoint = auth_endpoint.format(**self.config)
        
        authorization_url = f"{auth_endpoint}?{urlencode(auth_params)}"
        
        # Store flow state
        flow_state = {
            'state': self.state,
            'nonce': self.nonce,
            'code_verifier': self.code_verifier,
            'redirect_uri': redirect_uri,
        }
        
        if self.test_logger:
            self.test_logger.info('Authorization URL built', {
                'url': authorization_url,
                'scopes': scopes,
                'use_pkce': use_pkce,
                'state': self.state,
            })
        
        return authorization_url, flow_state
    
    def exchange_code_for_tokens(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None
    ) -> Dict:
        """
        Exchange authorization code for tokens.
        
        Args:
            code: Authorization code
            redirect_uri: Redirect URI (must match authorization request)
            code_verifier: PKCE code verifier
            
        Returns:
            Token response dictionary
        """
        if self.test_logger:
            self.test_logger.set_step('Token Exchange')
            self.test_logger.info('Exchanging authorization code for tokens')
        
        # Ensure discovery has been performed
        if not self.discovery_doc:
            self.discover_endpoints()
        
        token_endpoint = self.discovery_doc['token_endpoint']
        # Format endpoint with template variables if needed
        token_endpoint = token_endpoint.format(**self.config)
        
        # Build token request
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self.config['client_id'],
        }
        
        # Add client secret if provided
        if self.config.get('client_secret'):
            token_data['client_secret'] = self.config['client_secret']
        
        # Add PKCE verifier if provided
        if code_verifier:
            token_data['code_verifier'] = code_verifier
        
        try:
            response = self.http_client.post(
                token_endpoint,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            token_response = response.json()
            
            if self.test_logger:
                # Log tokens received (with preview only)
                if 'id_token' in token_response:
                    from tokens.decoder import JWTDecoder
                    preview = JWTDecoder.get_token_preview(token_response['id_token'])
                    self.test_logger.log_token_received('ID Token', preview)
                
                if 'access_token' in token_response:
                    from tokens.decoder import JWTDecoder
                    preview = JWTDecoder.get_token_preview(token_response['access_token'])
                    self.test_logger.log_token_received('Access Token', preview)
                
                self.test_logger.info('Tokens received successfully', {
                    'token_type': token_response.get('token_type'),
                    'expires_in': token_response.get('expires_in'),
                    'scope': token_response.get('scope'),
                })
            
            return token_response
            
        except Exception as e:
            if self.test_logger:
                self.test_logger.error(f'Token exchange failed: {str(e)}')
            raise
    
    def get_userinfo(self, access_token: str) -> Dict:
        """
        Fetch user information from the userinfo endpoint.
        
        Args:
            access_token: Access token
            
        Returns:
            User information dictionary
        """
        if self.test_logger:
            self.test_logger.set_step('UserInfo Request')
            self.test_logger.info('Fetching user information')
        
        # Ensure discovery has been performed
        if not self.discovery_doc:
            self.discover_endpoints()
        
        userinfo_endpoint = self.discovery_doc.get('userinfo_endpoint')
        if not userinfo_endpoint:
            if self.test_logger:
                self.test_logger.warning('UserInfo endpoint not available')
            return {}
        
        # Format endpoint with template variables if needed
        userinfo_endpoint = userinfo_endpoint.format(**self.config)
        
        try:
            response = self.http_client.get(
                userinfo_endpoint,
                headers={'Authorization': f'Bearer {access_token}'}
            )
            
            userinfo = response.json()
            
            if self.test_logger:
                self.test_logger.info('UserInfo retrieved successfully', {
                    'sub': userinfo.get('sub'),
                    'claims_count': len(userinfo)
                })
            
            return userinfo
            
        except Exception as e:
            if self.test_logger:
                self.test_logger.error(f'UserInfo request failed: {str(e)}')
            raise
    
    def parse_callback_url(self, callback_url: str) -> Dict:
        """
        Parse the callback URL to extract code and state.
        
        Args:
            callback_url: Full callback URL
            
        Returns:
            Dictionary with code, state, and any errors
        """
        parsed = urlparse(callback_url)
        params = parse_qs(parsed.query)
        
        result = {
            'code': params.get('code', [None])[0],
            'state': params.get('state', [None])[0],
            'error': params.get('error', [None])[0],
            'error_description': params.get('error_description', [None])[0],
        }
        
        if self.test_logger:
            if result['error']:
                self.test_logger.error(f"Authorization error: {result['error']}", {
                    'error_description': result['error_description']
                })
            else:
                self.test_logger.info('Authorization callback received', {
                    'has_code': bool(result['code']),
                    'state_matches': result['state'] == self.state
                })
        
        return result
    
    def validate_state(self, received_state: str) -> bool:
        """
        Validate the state parameter from callback.
        
        Args:
            received_state: State from callback
            
        Returns:
            True if state is valid
        """
        valid = received_state == self.state
        
        if self.test_logger:
            self.test_logger.log_validation_result(
                'State Validation',
                valid,
                {'expected': self.state, 'received': received_state}
            )
        
        return valid
    
    def close(self):
        """Close HTTP client."""
        self.http_client.close()

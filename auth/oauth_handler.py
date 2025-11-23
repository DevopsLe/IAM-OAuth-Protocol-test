"""
OAuth 2.0 handler for various OAuth flows.
"""

import requests
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode
import logging

from utils.crypto import generate_state
from utils.http_client import HTTPClient

logger = logging.getLogger(__name__)


class OAuthHandler:
    """Handler for OAuth 2.0 authentication flows."""
    
    def __init__(self, config: Dict, test_logger=None):
        """
        Initialize OAuth handler.
        
        Args:
            config: Provider configuration
            test_logger: Optional TestLogger instance
        """
        self.config = config
        self.test_logger = test_logger
        self.http_client = HTTPClient(log_callback=self._http_log_callback)
        
        # Flow state
        self.state = None
    
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
    
    def client_credentials_flow(self, scopes: Optional[list] = None) -> Dict:
        """
        Execute the Client Credentials flow (machine-to-machine).
        
        Args:
            scopes: Optional list of scopes to request
            
        Returns:
            Token response dictionary
        """
        if self.test_logger:
            self.test_logger.set_step('Client Credentials Flow')
            self.test_logger.info('Executing Client Credentials flow')
        
        token_endpoint = self.config.get('token_endpoint', '')
        # Format endpoint with template variables if needed
        token_endpoint = token_endpoint.format(**self.config)
        
        # Build token request
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret'],
        }
        
        if scopes:
            token_data['scope'] = ' '.join(scopes)
        
        try:
            response = self.http_client.post(
                token_endpoint,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            token_response = response.json()
            
            if self.test_logger:
                if 'access_token' in token_response:
                    from tokens.decoder import JWTDecoder
                    preview = JWTDecoder.get_token_preview(token_response['access_token'])
                    self.test_logger.log_token_received('Access Token', preview)
                
                self.test_logger.info('Access token received', {
                    'token_type': token_response.get('token_type'),
                    'expires_in': token_response.get('expires_in'),
                    'scope': token_response.get('scope'),
                })
            
            return token_response
            
        except Exception as e:
            if self.test_logger:
                self.test_logger.error(f'Client credentials flow failed: {str(e)}')
            raise
    
    def refresh_token_flow(self, refresh_token: str, scopes: Optional[list] = None) -> Dict:
        """
        Use a refresh token to get a new access token.
        
        Args:
            refresh_token: Refresh token
            scopes: Optional list of scopes (must be subset of original)
            
        Returns:
            Token response dictionary
        """
        if self.test_logger:
            self.test_logger.set_step('Refresh Token Flow')
            self.test_logger.info('Refreshing access token')
        
        token_endpoint = self.config.get('token_endpoint', '')
        # Format endpoint with template variables if needed
        token_endpoint = token_endpoint.format(**self.config)
        
        # Build token request
        token_data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.config['client_id'],
        }
        
        # Add client secret if provided
        if self.config.get('client_secret'):
            token_data['client_secret'] = self.config['client_secret']
        
        if scopes:
            token_data['scope'] = ' '.join(scopes)
        
        try:
            response = self.http_client.post(
                token_endpoint,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            token_response = response.json()
            
            if self.test_logger:
                if 'access_token' in token_response:
                    from tokens.decoder import JWTDecoder
                    preview = JWTDecoder.get_token_preview(token_response['access_token'])
                    self.test_logger.log_token_received('New Access Token', preview)
                
                self.test_logger.info('Token refreshed successfully', {
                    'token_type': token_response.get('token_type'),
                    'expires_in': token_response.get('expires_in'),
                })
            
            return token_response
            
        except Exception as e:
            if self.test_logger:
                self.test_logger.error(f'Token refresh failed: {str(e)}')
            raise
    
    def introspect_token(self, token: str, token_type_hint: Optional[str] = None) -> Dict:
        """
        Introspect a token to get its metadata.
        
        Args:
            token: Token to introspect
            token_type_hint: Optional hint about token type ('access_token' or 'refresh_token')
            
        Returns:
            Introspection response dictionary
        """
        if self.test_logger:
            self.test_logger.set_step('Token Introspection')
            self.test_logger.info('Introspecting token')
        
        introspection_endpoint = self.config.get('introspection_endpoint', '')
        if not introspection_endpoint:
            if self.test_logger:
                self.test_logger.warning('Introspection endpoint not configured')
            return {}
        
        # Format endpoint with template variables if needed
        introspection_endpoint = introspection_endpoint.format(**self.config)
        
        # Build introspection request
        introspection_data = {
            'token': token,
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret'],
        }
        
        if token_type_hint:
            introspection_data['token_type_hint'] = token_type_hint
        
        try:
            response = self.http_client.post(
                introspection_endpoint,
                data=introspection_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            introspection_response = response.json()
            
            if self.test_logger:
                self.test_logger.info('Token introspection completed', {
                    'active': introspection_response.get('active'),
                    'scope': introspection_response.get('scope'),
                })
            
            return introspection_response
            
        except Exception as e:
            if self.test_logger:
                self.test_logger.error(f'Token introspection failed: {str(e)}')
            raise
    
    def revoke_token(self, token: str, token_type_hint: Optional[str] = None) -> bool:
        """
        Revoke a token.
        
        Args:
            token: Token to revoke
            token_type_hint: Optional hint about token type
            
        Returns:
            True if revocation was successful
        """
        if self.test_logger:
            self.test_logger.set_step('Token Revocation')
            self.test_logger.info('Revoking token')
        
        revocation_endpoint = self.config.get('revocation_endpoint', '')
        if not revocation_endpoint:
            if self.test_logger:
                self.test_logger.warning('Revocation endpoint not configured')
            return False
        
        # Format endpoint with template variables if needed
        revocation_endpoint = revocation_endpoint.format(**self.config)
        
        # Build revocation request
        revocation_data = {
            'token': token,
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret'],
        }
        
        if token_type_hint:
            revocation_data['token_type_hint'] = token_type_hint
        
        try:
            response = self.http_client.post(
                revocation_endpoint,
                data=revocation_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            # Revocation endpoint typically returns 200 with empty body on success
            success = response.status_code == 200
            
            if self.test_logger:
                if success:
                    self.test_logger.info('Token revoked successfully')
                else:
                    self.test_logger.error(f'Token revocation failed with status {response.status_code}')
            
            return success
            
        except Exception as e:
            if self.test_logger:
                self.test_logger.error(f'Token revocation failed: {str(e)}')
            return False
    
    def close(self):
        """Close HTTP client."""
        self.http_client.close()

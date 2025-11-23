"""
Dynamic Client Registration for identity providers.
Supports automatic application creation in Azure and Okta.
"""

import requests
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class AzureClientRegistration:
    """Dynamic client registration for Azure/Microsoft Entra ID."""
    
    def __init__(self, tenant_id: str, access_token: str):
        """
        Initialize Azure client registration.
        
        Args:
            tenant_id: Azure tenant ID
            access_token: Admin access token with Application.ReadWrite.All permission
        """
        self.tenant_id = tenant_id
        self.access_token = access_token
        self.graph_endpoint = "https://graph.microsoft.com/v1.0"
    
    def register_application(
        self,
        app_name: str,
        redirect_uris: list,
        scopes: Optional[list] = None
    ) -> Dict:
        """
        Register a new application in Azure AD.
        
        Args:
            app_name: Application display name
            redirect_uris: List of redirect URIs
            scopes: Optional list of API permissions
            
        Returns:
            Dictionary with client_id, client_secret, and app details
        """
        logger.info(f"Registering application '{app_name}' in Azure AD")
        
        # Create application
        app_data = {
            "displayName": app_name,
            "signInAudience": "AzureADMyOrg",
            "web": {
                "redirectUris": redirect_uris,
                "implicitGrantSettings": {
                    "enableIdTokenIssuance": True,
                    "enableAccessTokenIssuance": False
                }
            },
            "requiredResourceAccess": self._build_api_permissions(scopes or [])
        }
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            # Create application
            response = requests.post(
                f"{self.graph_endpoint}/applications",
                headers=headers,
                json=app_data,
                timeout=30
            )
            response.raise_for_status()
            app = response.json()
            
            app_id = app['id']
            client_id = app['appId']
            
            logger.info(f"Application created with Client ID: {client_id}")
            
            # Create service principal
            sp_response = requests.post(
                f"{self.graph_endpoint}/servicePrincipals",
                headers=headers,
                json={"appId": client_id},
                timeout=30
            )
            sp_response.raise_for_status()
            
            # Create client secret
            secret_response = requests.post(
                f"{self.graph_endpoint}/applications/{app_id}/addPassword",
                headers=headers,
                json={
                    "passwordCredential": {
                        "displayName": "Auto-generated secret for IAM testing"
                    }
                },
                timeout=30
            )
            secret_response.raise_for_status()
            secret_data = secret_response.json()
            
            return {
                'success': True,
                'client_id': client_id,
                'client_secret': secret_data['secretText'],
                'tenant_id': self.tenant_id,
                'app_id': app_id,
                'app_name': app_name,
                'redirect_uris': redirect_uris,
                'message': 'Application registered successfully in Azure AD'
            }
            
        except requests.RequestException as e:
            logger.error(f"Failed to register application: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to register application in Azure AD'
            }
    
    def _build_api_permissions(self, scopes: list) -> list:
        """Build API permissions configuration."""
        # Microsoft Graph API ID
        graph_api_id = "00000003-0000-0000-c000-000000000000"
        
        # Common permission IDs
        permission_map = {
            'User.Read': 'e1fe6dd8-ba31-4d61-89e7-88639da4683d',
            'profile': '14dad69e-099b-42c9-810b-d002981feec1',
            'email': '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0',
            'openid': '37f7f235-527c-4136-accd-4a02d197296e',
        }
        
        resource_access = []
        for scope in scopes:
            if scope in permission_map:
                resource_access.append({
                    "id": permission_map[scope],
                    "type": "Scope"
                })
        
        if resource_access:
            return [{
                "resourceAppId": graph_api_id,
                "resourceAccess": resource_access
            }]
        
        return []
    
    def delete_application(self, app_id: str) -> bool:
        """Delete an application from Azure AD."""
        headers = {
            "Authorization": f"Bearer {self.access_token}",
        }
        
        try:
            response = requests.delete(
                f"{self.graph_endpoint}/applications/{app_id}",
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            logger.info(f"Application {app_id} deleted successfully")
            return True
        except requests.RequestException as e:
            logger.error(f"Failed to delete application: {str(e)}")
            return False


class OktaClientRegistration:
    """Dynamic client registration for Okta."""
    
    def __init__(self, domain: str, api_token: str):
        """
        Initialize Okta client registration.
        
        Args:
            domain: Okta domain (e.g., your-domain.okta.com)
            api_token: Okta API token with OAuth application management permissions
        """
        # Strip protocol if provided
        domain = domain.replace('https://', '').replace('http://', '').strip()
        # Remove trailing slash if present
        domain = domain.rstrip('/')
        
        # Clean up the API token (remove whitespace)
        api_token = api_token.strip()
        
        self.domain = domain
        self.api_token = api_token
        self.base_url = f"https://{domain}"
        
        logger.info(f"Initialized Okta registration for domain: {domain}")
    
    def register_application(
        self,
        app_name: str,
        redirect_uris: list,
        grant_types: Optional[list] = None
    ) -> Dict:
        """
        Register a new application in Okta.
        
        Args:
            app_name: Application name
            redirect_uris: List of redirect URIs
            grant_types: OAuth grant types (default: authorization_code)
            
        Returns:
            Dictionary with client_id, client_secret, and app details
        """
        logger.info(f"Registering application '{app_name}' in Okta")
        
        if grant_types is None:
            grant_types = ["authorization_code", "refresh_token"]
        
        app_data = {
            "name": "oidc_client",
            "label": app_name,
            "signOnMode": "OPENID_CONNECT",
            "credentials": {
                "oauthClient": {
                    "token_endpoint_auth_method": "client_secret_post"
                }
            },
            "settings": {
                "oauthClient": {
                    "client_uri": None,
                    "logo_uri": None,
                    "redirect_uris": redirect_uris,
                    "post_logout_redirect_uris": [],
                    "response_types": ["code"],
                    "grant_types": grant_types,
                    "application_type": "web",
                    "consent_method": "REQUIRED",
                    "issuer_mode": "ORG_URL"
                }
            }
        }
        
        headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/apps",
                headers=headers,
                json=app_data,
                timeout=30
            )
            response.raise_for_status()
            app = response.json()
            
            client_id = app['credentials']['oauthClient']['client_id']
            client_secret = app['credentials']['oauthClient']['client_secret']
            
            logger.info(f"Application created with Client ID: {client_id}")
            
            return {
                'success': True,
                'client_id': client_id,
                'client_secret': client_secret,
                'domain': self.domain,
                'app_id': app['id'],
                'app_name': app_name,
                'redirect_uris': redirect_uris,
                'message': 'Application registered successfully in Okta'
            }
            
        except requests.RequestException as e:
            logger.error(f"Failed to register application: {str(e)}")
            
            # Extract detailed error information
            error_detail = {
                'message': str(e),
                'type': type(e).__name__
            }
            
            # Try to get response details
            if hasattr(e, 'response') and e.response is not None:
                error_detail['status_code'] = e.response.status_code
                error_detail['status_text'] = e.response.reason
                
                try:
                    # Try to parse JSON error response
                    error_json = e.response.json()
                    error_detail['okta_error'] = error_json
                    
                    # Extract specific error messages
                    if 'errorSummary' in error_json:
                        error_detail['summary'] = error_json['errorSummary']
                    if 'errorCauses' in error_json:
                        error_detail['causes'] = error_json['errorCauses']
                except:
                    # If not JSON, get text response
                    error_detail['response_text'] = e.response.text[:500]
            
            return {
                'success': False,
                'error': error_detail,
                'message': f'Failed to register application in Okta: {error_detail.get("summary", str(e))}'
            }
    
    def delete_application(self, app_id: str) -> bool:
        """Delete an application from Okta."""
        headers = {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json"
        }
        
        try:
            # Deactivate first
            requests.post(
                f"{self.base_url}/api/v1/apps/{app_id}/lifecycle/deactivate",
                headers=headers,
                timeout=30
            )
            
            # Then delete
            response = requests.delete(
                f"{self.base_url}/api/v1/apps/{app_id}",
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            logger.info(f"Application {app_id} deleted successfully")
            return True
        except requests.RequestException as e:
            logger.error(f"Failed to delete application: {str(e)}")
            return False


class GenericOIDCRegistration:
    """Generic OIDC Dynamic Client Registration (RFC 7591)."""
    
    def __init__(self, registration_endpoint: str, access_token: Optional[str] = None):
        """
        Initialize generic OIDC client registration.
        
        Args:
            registration_endpoint: OIDC dynamic client registration endpoint
            access_token: Optional initial access token
        """
        self.registration_endpoint = registration_endpoint
        self.access_token = access_token
    
    def register_application(
        self,
        app_name: str,
        redirect_uris: list,
        grant_types: Optional[list] = None,
        response_types: Optional[list] = None
    ) -> Dict:
        """
        Register a new client using OIDC Dynamic Client Registration.
        
        Args:
            app_name: Client name
            redirect_uris: List of redirect URIs
            grant_types: OAuth grant types
            response_types: OAuth response types
            
        Returns:
            Dictionary with client_id, client_secret, and registration details
        """
        logger.info(f"Registering client '{app_name}' via OIDC DCR")
        
        if grant_types is None:
            grant_types = ["authorization_code", "refresh_token"]
        
        if response_types is None:
            response_types = ["code"]
        
        registration_data = {
            "client_name": app_name,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_post"
        }
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        
        try:
            response = requests.post(
                self.registration_endpoint,
                headers=headers,
                json=registration_data,
                timeout=30
            )
            response.raise_for_status()
            registration = response.json()
            
            return {
                'success': True,
                'client_id': registration.get('client_id'),
                'client_secret': registration.get('client_secret'),
                'registration_data': registration,
                'message': 'Client registered successfully via OIDC DCR'
            }
            
        except requests.RequestException as e:
            logger.error(f"Failed to register client: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to register client via OIDC DCR'
            }

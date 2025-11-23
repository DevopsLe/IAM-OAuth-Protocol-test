"""
Configuration management for IAM Protocol Testing Application.
Handles environment-specific settings and provider templates.
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Base configuration class."""
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    
    # Application settings
    APP_HOST = os.getenv('APP_HOST', 'localhost')
    APP_PORT = int(os.getenv('APP_PORT', 5000))
    REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:5000/callback')
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///iam_testing.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Logging settings
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/iam_testing.log')
    
    # AI Diagnostics
    ENABLE_AI_DIAGNOSTICS = os.getenv('ENABLE_AI_DIAGNOSTICS', 'False').lower() == 'true'
    GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '')
    
    # Session settings
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour


class ProviderConfig:
    """Provider-specific configuration templates."""
    
    AZURE = {
        'name': 'Azure / Microsoft Entra ID',
        'type': 'oidc',
        'discovery_endpoint': 'https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration',
        'authorization_endpoint': 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize',
        'token_endpoint': 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
        'userinfo_endpoint': 'https://graph.microsoft.com/oidc/userinfo',
        'jwks_uri': 'https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys',
        'scopes': ['openid', 'profile', 'email', 'User.Read'],
        'response_type': 'code',
        'response_mode': 'query',
        'tenant_id': os.getenv('AZURE_TENANT_ID', ''),
        'client_id': os.getenv('AZURE_CLIENT_ID', ''),
        'client_secret': os.getenv('AZURE_CLIENT_SECRET', ''),
    }
    
    AZURE_B2C = {
        'name': 'Azure AD B2C',
        'type': 'oidc',
        'discovery_endpoint': 'https://{tenant_name}.b2clogin.com/{tenant_name}.onmicrosoft.com/{policy}/v2.0/.well-known/openid-configuration',
        'scopes': ['openid', 'profile', 'email'],
        'response_type': 'code',
        'response_mode': 'query',
    }
    
    OKTA = {
        'name': 'Okta',
        'type': 'oidc',
        'discovery_endpoint': 'https://{domain}/.well-known/openid-configuration',
        'authorization_endpoint': 'https://{domain}/oauth2/v1/authorize',
        'token_endpoint': 'https://{domain}/oauth2/v1/token',
        'userinfo_endpoint': 'https://{domain}/oauth2/v1/userinfo',
        'jwks_uri': 'https://{domain}/oauth2/v1/keys',
        'scopes': ['openid', 'profile', 'email'],
        'response_type': 'code',
        'domain': os.getenv('OKTA_DOMAIN', ''),
        'client_id': os.getenv('OKTA_CLIENT_ID', ''),
        'client_secret': os.getenv('OKTA_CLIENT_SECRET', ''),
    }
    
    OKTA_CUSTOM_AUTH_SERVER = {
        'name': 'Okta (Custom Authorization Server)',
        'type': 'oidc',
        'discovery_endpoint': 'https://{domain}/oauth2/{auth_server_id}/.well-known/openid-configuration',
        'authorization_endpoint': 'https://{domain}/oauth2/{auth_server_id}/v1/authorize',
        'token_endpoint': 'https://{domain}/oauth2/{auth_server_id}/v1/token',
        'userinfo_endpoint': 'https://{domain}/oauth2/{auth_server_id}/v1/userinfo',
        'jwks_uri': 'https://{domain}/oauth2/{auth_server_id}/v1/keys',
        'scopes': ['openid', 'profile', 'email'],
        'response_type': 'code',
    }
    
    GENERIC_OIDC = {
        'name': 'Generic OIDC Provider',
        'type': 'oidc',
        'discovery_endpoint': '',  # User must provide
        'scopes': ['openid', 'profile', 'email'],
        'response_type': 'code',
        'client_id': '',
        'client_secret': '',
    }
    
    @classmethod
    def get_provider_template(cls, provider_name):
        """Get configuration template for a specific provider."""
        templates = {
            'azure': cls.AZURE,
            'azure_b2c': cls.AZURE_B2C,
            'okta': cls.OKTA,
            'okta_custom': cls.OKTA_CUSTOM_AUTH_SERVER,
            'generic': cls.GENERIC_OIDC,
        }
        return templates.get(provider_name.lower(), cls.GENERIC_OIDC)
    
    @classmethod
    def list_providers(cls):
        """List all available provider templates."""
        return [
            {'id': 'azure', 'name': 'Azure / Microsoft Entra ID'},
            {'id': 'azure_b2c', 'name': 'Azure AD B2C'},
            {'id': 'okta', 'name': 'Okta'},
            {'id': 'okta_custom', 'name': 'Okta (Custom Authorization Server)'},
            {'id': 'generic', 'name': 'Generic OIDC Provider'},
        ]


class FlowConfig:
    """Authentication flow configurations."""
    
    FLOWS = {
        'authorization_code_pkce': {
            'name': 'Authorization Code Flow with PKCE',
            'description': 'Secure flow for web and mobile applications',
            'protocols': ['oidc', 'oauth'],
            'requires_pkce': True,
            'requires_client_secret': False,  # Optional with PKCE
        },
        'authorization_code': {
            'name': 'Authorization Code Flow',
            'description': 'Traditional server-side flow',
            'protocols': ['oidc', 'oauth'],
            'requires_pkce': False,
            'requires_client_secret': True,
        },
        'client_credentials': {
            'name': 'Client Credentials Flow',
            'description': 'Machine-to-machine authentication',
            'protocols': ['oauth'],
            'requires_pkce': False,
            'requires_client_secret': True,
        },
        'implicit': {
            'name': 'Implicit Flow (Legacy)',
            'description': 'Legacy flow - not recommended',
            'protocols': ['oidc', 'oauth'],
            'requires_pkce': False,
            'requires_client_secret': False,
            'deprecated': True,
        },
    }
    
    @classmethod
    def get_flow_config(cls, flow_name):
        """Get configuration for a specific flow."""
        return cls.FLOWS.get(flow_name, cls.FLOWS['authorization_code_pkce'])
    
    @classmethod
    def list_flows(cls, protocol='oidc'):
        """List available flows for a protocol."""
        return [
            {'id': flow_id, **flow_config}
            for flow_id, flow_config in cls.FLOWS.items()
            if protocol in flow_config['protocols']
        ]

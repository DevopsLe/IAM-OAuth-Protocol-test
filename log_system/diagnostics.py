"""
Diagnostic analyzer for identifying common error patterns and providing troubleshooting suggestions.
"""

import re
from typing import Dict, List, Optional, Tuple


class DiagnosticAnalyzer:
    """Analyzes test results and logs to identify issues and provide recommendations."""
    
    # Common error patterns and their explanations
    ERROR_PATTERNS = {
        'invalid_client': {
            'title': 'Invalid Client Credentials',
            'explanation': 'The client_id or client_secret is incorrect or the application is not properly configured in the identity provider.',
            'suggestions': [
                'Verify the client_id matches the application registration',
                'Check that the client_secret is correct and not expired',
                'Ensure the application is enabled in the identity provider',
                'For Azure: Check the application exists in the correct tenant',
                'For Okta: Verify the client ID matches the application in your Okta org'
            ]
        },
        'invalid_scope': {
            'title': 'Invalid Scope Requested',
            'explanation': 'One or more requested scopes are not configured or allowed for this application.',
            'suggestions': [
                'Check that all requested scopes are configured in the application registration',
                'Verify scope names are spelled correctly (case-sensitive)',
                'For Azure: Ensure API permissions are granted and admin consent is provided if required',
                'For Okta: Check that scopes are defined in the Authorization Server',
                'Remove any custom scopes that are not configured'
            ]
        },
        'unauthorized_client': {
            'title': 'Unauthorized Client',
            'explanation': 'The client is not authorized to use the requested grant type or flow.',
            'suggestions': [
                'Verify the application is configured to allow the requested flow type',
                'For Authorization Code flow: Enable "Authorization Code" grant type',
                'For Client Credentials: Enable "Client Credentials" grant type',
                'Check that the redirect_uri is registered in the application',
                'Ensure the application type matches the flow (Web, SPA, Native)'
            ]
        },
        'access_denied': {
            'title': 'Access Denied',
            'explanation': 'The user or administrator denied the consent request, or the user does not have permission.',
            'suggestions': [
                'Check if user consent is required and was denied',
                'Verify the user has the necessary permissions/roles',
                'For Azure: Check if admin consent is required for the requested scopes',
                'Review conditional access policies that might be blocking access',
                'Check if the user account is active and not locked'
            ]
        },
        'invalid_grant': {
            'title': 'Invalid Authorization Grant',
            'explanation': 'The authorization code or refresh token is invalid, expired, or has already been used.',
            'suggestions': [
                'Authorization codes can only be used once - ensure you\'re not reusing a code',
                'Check that the code hasn\'t expired (typically valid for 5-10 minutes)',
                'Verify the redirect_uri matches exactly what was used in the authorization request',
                'For refresh tokens: Check if the token has been revoked or expired',
                'Ensure the code_verifier matches the code_challenge (for PKCE)'
            ]
        },
        'token_expired': {
            'title': 'Token Expired',
            'explanation': 'The token has passed its expiration time and is no longer valid.',
            'suggestions': [
                'Use a refresh token to obtain a new access token',
                'Implement token refresh logic before expiration',
                'Check the "exp" claim to determine when the token expires',
                'For testing: Request a new token by re-authenticating'
            ]
        },
        'invalid_token': {
            'title': 'Invalid Token',
            'explanation': 'The token signature is invalid, the token is malformed, or the token is not from the expected issuer.',
            'suggestions': [
                'Verify the token signature using the provider\'s JWKS',
                'Check that the "iss" (issuer) claim matches the expected identity provider',
                'Ensure the "aud" (audience) claim matches your application',
                'Verify the token hasn\'t been tampered with',
                'Check that you\'re using the correct token (ID token vs Access token)'
            ]
        },
        'insufficient_scope': {
            'title': 'Insufficient Scope',
            'explanation': 'The access token does not contain the required scopes to access the resource.',
            'suggestions': [
                'Request the necessary scopes during the authorization request',
                'Check the "scope" or "scp" claim in the access token',
                'Verify the API/resource requires the scopes you have',
                'For Azure: Ensure API permissions are granted in the app registration',
                'Re-authenticate with the correct scopes'
            ]
        },
        'redirect_uri_mismatch': {
            'title': 'Redirect URI Mismatch',
            'explanation': 'The redirect_uri in the request does not match any registered redirect URIs for the application.',
            'suggestions': [
                'Ensure the redirect_uri is registered in the application configuration',
                'Check for exact match including protocol (http/https), port, and path',
                'Avoid trailing slashes unless they are in the registered URI',
                'For Azure: Add the redirect URI in "Authentication" section',
                'For Okta: Add the redirect URI in "Sign-in redirect URIs"'
            ]
        },
        'consent_required': {
            'title': 'Consent Required',
            'explanation': 'User consent is required but was not provided or the consent prompt was suppressed.',
            'suggestions': [
                'Remove "prompt=none" from the authorization request to allow consent',
                'For Azure: Grant admin consent for the required permissions',
                'Ensure the user can see and approve the consent screen',
                'Check if incremental consent is supported for additional scopes'
            ]
        }
    }
    
    @classmethod
    def analyze_error(cls, error_code: str, error_description: str = '', logs: List[Dict] = None) -> Dict:
        """
        Analyze an error and provide diagnostic information.
        
        Args:
            error_code: OAuth/OIDC error code
            error_description: Error description from the provider
            logs: Optional list of log entries for additional context
            
        Returns:
            Dictionary with diagnostic information
        """
        # Find matching error pattern
        pattern = cls.ERROR_PATTERNS.get(error_code.lower())
        
        if pattern:
            result = {
                'error_code': error_code,
                'title': pattern['title'],
                'explanation': pattern['explanation'],
                'suggestions': pattern['suggestions'],
                'severity': 'error'
            }
        else:
            result = {
                'error_code': error_code,
                'title': f'Error: {error_code}',
                'explanation': error_description or 'An error occurred during the authentication flow.',
                'suggestions': [
                    'Check the error description for more details',
                    'Review the identity provider documentation for this error code',
                    'Examine the request/response logs for additional context'
                ],
                'severity': 'error'
            }
        
        # Add provider-specific context if available from logs
        if logs:
            result['context'] = cls._extract_context_from_logs(logs)
        
        return result
    
    @classmethod
    def analyze_token_validation(cls, validation_results: Dict) -> Dict:
        """
        Analyze token validation results and provide recommendations.
        
        Args:
            validation_results: Dictionary with validation results
            
        Returns:
            Dictionary with diagnostic information
        """
        issues = []
        warnings = []
        
        # Check signature validation
        if not validation_results.get('signature_valid', True):
            issues.append({
                'type': 'signature_invalid',
                'message': 'Token signature validation failed',
                'suggestions': [
                    'Verify the token was issued by the expected identity provider',
                    'Check that the JWKS endpoint is accessible',
                    'Ensure the token hasn\'t been modified',
                    'Verify you\'re using the correct public key'
                ]
            })
        
        # Check expiration
        if validation_results.get('expired', False):
            issues.append({
                'type': 'token_expired',
                'message': 'Token has expired',
                'suggestions': [
                    'Use a refresh token to get a new access token',
                    'Re-authenticate to get a fresh token',
                    'Implement automatic token refresh before expiration'
                ]
            })
        
        # Check audience
        if not validation_results.get('audience_valid', True):
            issues.append({
                'type': 'audience_mismatch',
                'message': 'Token audience does not match expected value',
                'suggestions': [
                    'Verify the "aud" claim matches your client_id or API identifier',
                    'Check the application configuration in the identity provider',
                    'Ensure you\'re validating the correct token type (ID vs Access)'
                ]
            })
        
        # Check issuer
        if not validation_results.get('issuer_valid', True):
            issues.append({
                'type': 'issuer_mismatch',
                'message': 'Token issuer does not match expected value',
                'suggestions': [
                    'Verify the "iss" claim matches your identity provider',
                    'Check for correct tenant ID in Azure tokens',
                    'Ensure you\'re using the correct authorization server in Okta'
                ]
            })
        
        # Check for missing required claims
        required_claims = validation_results.get('missing_required_claims', [])
        if required_claims:
            warnings.append({
                'type': 'missing_claims',
                'message': f'Missing required claims: {", ".join(required_claims)}',
                'suggestions': [
                    'Request the necessary scopes to get these claims',
                    'Check if optional claims need to be configured',
                    'Verify the token type contains the expected claims'
                ]
            })
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings,
            'severity': 'error' if issues else ('warning' if warnings else 'success')
        }
    
    @classmethod
    def analyze_api_response(cls, status_code: int, response_body: Dict, token_claims: Dict) -> Dict:
        """
        Analyze API response and correlate with token claims.
        
        Args:
            status_code: HTTP status code
            response_body: Response body
            token_claims: Claims from the access token
            
        Returns:
            Dictionary with diagnostic information
        """
        if status_code == 401:
            return {
                'status': 'unauthorized',
                'message': 'Authentication failed',
                'suggestions': [
                    'Verify the access token is included in the Authorization header',
                    'Check that the token hasn\'t expired',
                    'Ensure the token is valid and properly formatted',
                    'Verify the API endpoint expects Bearer token authentication'
                ],
                'severity': 'error'
            }
        
        elif status_code == 403:
            # Analyze token claims for permission issues
            scopes = token_claims.get('scp', '') or token_claims.get('scope', '')
            roles = token_claims.get('roles', [])
            
            return {
                'status': 'forbidden',
                'message': 'Insufficient permissions to access the resource',
                'token_scopes': scopes.split() if isinstance(scopes, str) else scopes,
                'token_roles': roles,
                'suggestions': [
                    'Check the "scp" or "scope" claim in the access token',
                    'Verify the required scopes/permissions for this API endpoint',
                    'Request additional scopes during authentication if needed',
                    'Check if the user has the necessary roles assigned',
                    'Review the API\'s authorization requirements'
                ],
                'severity': 'error'
            }
        
        elif status_code >= 200 and status_code < 300:
            return {
                'status': 'success',
                'message': 'API request successful',
                'severity': 'success'
            }
        
        else:
            return {
                'status': 'error',
                'message': f'API request failed with status {status_code}',
                'suggestions': [
                    'Check the API response for error details',
                    'Verify the API endpoint is correct',
                    'Review the API documentation for this endpoint'
                ],
                'severity': 'error'
            }
    
    @classmethod
    def _extract_context_from_logs(cls, logs: List[Dict]) -> Dict:
        """Extract relevant context from log entries."""
        context = {
            'provider': None,
            'flow_type': None,
            'error_responses': []
        }
        
        for log in logs:
            # Extract provider information
            if 'microsoft' in log.get('message', '').lower() or 'azure' in log.get('message', '').lower():
                context['provider'] = 'Azure'
            elif 'okta' in log.get('message', '').lower():
                context['provider'] = 'Okta'
            
            # Extract error responses
            if log.get('level') == 'ERROR' and 'http' in log:
                context['error_responses'].append({
                    'url': log['http'].get('url'),
                    'status': log['http'].get('status_code'),
                    'body': log['http'].get('response', {}).get('body')
                })
        
        return context
    
    @classmethod
    def generate_diagnostic_report(cls, test_result: Dict) -> Dict:
        """
        Generate a comprehensive diagnostic report for a test result.
        
        Args:
            test_result: Test result dictionary
            
        Returns:
            Diagnostic report
        """
        report = {
            'test_id': test_result.get('id'),
            'status': test_result.get('status'),
            'provider': test_result.get('provider'),
            'flow_type': test_result.get('flow_type'),
            'diagnostics': []
        }
        
        # Analyze errors
        if test_result.get('error'):
            error = test_result['error']
            error_diagnostic = cls.analyze_error(
                error.get('code', 'unknown_error'),
                error.get('message', ''),
                test_result.get('logs', [])
            )
            report['diagnostics'].append(error_diagnostic)
        
        # Analyze token validation
        if test_result.get('validation'):
            validation_diagnostic = cls.analyze_token_validation(test_result['validation'])
            if validation_diagnostic['severity'] != 'success':
                report['diagnostics'].append(validation_diagnostic)
        
        # Analyze API test results
        if test_result.get('api_test'):
            api_test = test_result['api_test']
            api_diagnostic = cls.analyze_api_response(
                api_test.get('status_code'),
                api_test.get('response', {}),
                test_result.get('claims', {}).get('access_token', {})
            )
            if api_diagnostic['severity'] != 'success':
                report['diagnostics'].append(api_diagnostic)
        
        return report

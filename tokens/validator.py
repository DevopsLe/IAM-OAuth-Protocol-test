"""
Token validator for verifying JWT signatures and claims.
"""

import jwt
import requests
from typing import Dict, Optional, List
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class TokenValidator:
    """Validator for JWT tokens with signature and claims verification."""
    
    def __init__(self, jwks_uri: Optional[str] = None, issuer: Optional[str] = None, audience: Optional[str] = None):
        """
        Initialize token validator.
        
        Args:
            jwks_uri: URI to fetch JSON Web Key Set
            issuer: Expected token issuer
            audience: Expected token audience
        """
        self.jwks_uri = jwks_uri
        self.issuer = issuer
        self.audience = audience
        self.jwks_client = None
        
        if jwks_uri:
            self.jwks_client = jwt.PyJWKClient(jwks_uri)
    
    def validate(self, token: str, verify_signature: bool = True) -> Dict:
        """
        Validate a JWT token.
        
        Args:
            token: JWT string
            verify_signature: Whether to verify the token signature
            
        Returns:
            Dictionary with validation results
        """
        results = {
            'valid': True,
            'signature_valid': None,
            'expired': False,
            'not_yet_valid': False,
            'issuer_valid': None,
            'audience_valid': None,
            'errors': [],
            'warnings': [],
            'claims': {}
        }
        
        try:
            # Decode without verification first to get claims
            unverified_claims = jwt.decode(token, options={"verify_signature": False})
            results['claims'] = unverified_claims
            
            # Verify signature if requested
            if verify_signature:
                try:
                    if self.jwks_client:
                        signing_key = self.jwks_client.get_signing_key_from_jwt(token)
                        verified_claims = jwt.decode(
                            token,
                            signing_key.key,
                            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                            options={"verify_signature": True}
                        )
                        results['signature_valid'] = True
                    else:
                        results['warnings'].append("JWKS URI not provided - signature verification skipped")
                        results['signature_valid'] = None
                except jwt.InvalidSignatureError:
                    results['valid'] = False
                    results['signature_valid'] = False
                    results['errors'].append("Invalid token signature")
                except Exception as e:
                    results['valid'] = False
                    results['signature_valid'] = False
                    results['errors'].append(f"Signature verification failed: {str(e)}")
            
            # Check expiration
            if 'exp' in unverified_claims:
                exp_datetime = datetime.fromtimestamp(unverified_claims['exp'])
                if datetime.utcnow() > exp_datetime:
                    results['valid'] = False
                    results['expired'] = True
                    results['errors'].append(f"Token expired at {exp_datetime.isoformat()}")
            
            # Check not before
            if 'nbf' in unverified_claims:
                nbf_datetime = datetime.fromtimestamp(unverified_claims['nbf'])
                if datetime.utcnow() < nbf_datetime:
                    results['valid'] = False
                    results['not_yet_valid'] = True
                    results['errors'].append(f"Token not valid until {nbf_datetime.isoformat()}")
            
            # Check issuer
            if self.issuer:
                token_issuer = unverified_claims.get('iss')
                if token_issuer != self.issuer:
                    results['valid'] = False
                    results['issuer_valid'] = False
                    results['errors'].append(f"Invalid issuer: expected '{self.issuer}', got '{token_issuer}'")
                else:
                    results['issuer_valid'] = True
            
            # Check audience
            if self.audience:
                token_audience = unverified_claims.get('aud')
                # Audience can be a string or list
                if isinstance(token_audience, list):
                    audience_valid = self.audience in token_audience
                else:
                    audience_valid = token_audience == self.audience
                
                if not audience_valid:
                    results['valid'] = False
                    results['audience_valid'] = False
                    results['errors'].append(f"Invalid audience: expected '{self.audience}', got '{token_audience}'")
                else:
                    results['audience_valid'] = True
            
            # Check for required OIDC claims
            required_oidc_claims = ['iss', 'sub', 'aud', 'exp', 'iat']
            missing_claims = [claim for claim in required_oidc_claims if claim not in unverified_claims]
            
            if missing_claims:
                results['warnings'].append(f"Missing standard OIDC claims: {', '.join(missing_claims)}")
                results['missing_required_claims'] = missing_claims
            
        except jwt.DecodeError as e:
            results['valid'] = False
            results['errors'].append(f"Failed to decode token: {str(e)}")
        except Exception as e:
            results['valid'] = False
            results['errors'].append(f"Validation error: {str(e)}")
        
        return results
    
    def validate_id_token(self, id_token: str, nonce: Optional[str] = None) -> Dict:
        """
        Validate an OIDC ID token with additional ID token-specific checks.
        
        Args:
            id_token: ID token string
            nonce: Expected nonce value
            
        Returns:
            Dictionary with validation results
        """
        results = self.validate(id_token, verify_signature=True)
        
        # Check nonce if provided
        if nonce:
            token_nonce = results['claims'].get('nonce')
            if token_nonce != nonce:
                results['valid'] = False
                results['errors'].append(f"Invalid nonce: expected '{nonce}', got '{token_nonce}'")
        
        # Check for ID token specific claims
        if 'sub' not in results['claims']:
            results['valid'] = False
            results['errors'].append("Missing required 'sub' claim for ID token")
        
        return results
    
    def validate_access_token(self, access_token: str, required_scopes: Optional[List[str]] = None) -> Dict:
        """
        Validate an access token with scope checking.
        
        Args:
            access_token: Access token string
            required_scopes: List of required scopes
            
        Returns:
            Dictionary with validation results
        """
        results = self.validate(access_token, verify_signature=True)
        
        # Check scopes if required
        if required_scopes:
            token_scopes = self._extract_scopes(results['claims'])
            missing_scopes = [scope for scope in required_scopes if scope not in token_scopes]
            
            if missing_scopes:
                results['valid'] = False
                results['errors'].append(f"Missing required scopes: {', '.join(missing_scopes)}")
                results['missing_scopes'] = missing_scopes
            
            results['token_scopes'] = token_scopes
        
        return results
    
    @staticmethod
    def _extract_scopes(claims: Dict) -> List[str]:
        """
        Extract scopes from token claims.
        
        Args:
            claims: Token claims
            
        Returns:
            List of scopes
        """
        # Scopes can be in 'scope' (space-separated string) or 'scp' (array)
        if 'scp' in claims:
            return claims['scp'] if isinstance(claims['scp'], list) else [claims['scp']]
        elif 'scope' in claims:
            scope_str = claims['scope']
            return scope_str.split() if isinstance(scope_str, str) else scope_str
        else:
            return []
    
    @staticmethod
    def fetch_jwks(jwks_uri: str) -> Dict:
        """
        Fetch JWKS from a URI.
        
        Args:
            jwks_uri: JWKS endpoint URI
            
        Returns:
            JWKS dictionary
        """
        try:
            response = requests.get(jwks_uri, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to fetch JWKS from {jwks_uri}: {str(e)}")
            raise
    
    def update_jwks_uri(self, jwks_uri: str):
        """Update the JWKS URI and reinitialize the client."""
        self.jwks_uri = jwks_uri
        self.jwks_client = jwt.PyJWKClient(jwks_uri)
    
    def update_expected_values(self, issuer: Optional[str] = None, audience: Optional[str] = None):
        """Update expected issuer and audience values."""
        if issuer is not None:
            self.issuer = issuer
        if audience is not None:
            self.audience = audience

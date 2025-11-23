"""
JWT decoder for parsing and extracting token information.
"""

import json
import base64
from typing import Dict, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class JWTDecoder:
    """Decoder for JSON Web Tokens (JWT)."""
    
    @staticmethod
    def decode(token: str) -> Dict:
        """
        Decode a JWT without verification.
        
        Args:
            token: JWT string
            
        Returns:
            Dictionary with header, payload, and signature
            
        Raises:
            ValueError: If token is malformed
        """
        try:
            # Split token into parts
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
            
            header_encoded, payload_encoded, signature_encoded = parts
            
            # Decode header
            header = JWTDecoder._decode_part(header_encoded)
            
            # Decode payload
            payload = JWTDecoder._decode_part(payload_encoded)
            
            # Parse timestamps
            payload = JWTDecoder._parse_timestamps(payload)
            
            return {
                'header': header,
                'payload': payload,
                'signature': signature_encoded,
                'raw': token
            }
            
        except Exception as e:
            logger.error(f"Failed to decode JWT: {str(e)}")
            raise ValueError(f"Failed to decode JWT: {str(e)}")
    
    @staticmethod
    def _decode_part(encoded: str) -> Dict:
        """
        Decode a base64-URL encoded JWT part.
        
        Args:
            encoded: Base64-URL encoded string
            
        Returns:
            Decoded dictionary
        """
        # Add padding if necessary
        padding = 4 - (len(encoded) % 4)
        if padding != 4:
            encoded += '=' * padding
        
        # Decode base64
        decoded_bytes = base64.urlsafe_b64decode(encoded)
        
        # Parse JSON
        return json.loads(decoded_bytes.decode('utf-8'))
    
    @staticmethod
    def _parse_timestamps(payload: Dict) -> Dict:
        """
        Parse timestamp claims and add human-readable versions.
        
        Args:
            payload: Token payload
            
        Returns:
            Payload with parsed timestamps
        """
        timestamp_claims = ['exp', 'iat', 'nbf', 'auth_time']
        
        for claim in timestamp_claims:
            if claim in payload and isinstance(payload[claim], (int, float)):
                try:
                    dt = datetime.fromtimestamp(payload[claim])
                    payload[f'{claim}_datetime'] = dt.isoformat()
                    payload[f'{claim}_readable'] = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                except:
                    pass
        
        return payload
    
    @staticmethod
    def get_token_preview(token: str, length: int = 20) -> str:
        """
        Get a preview of the token for logging.
        
        Args:
            token: JWT string
            length: Number of characters to show from start and end
            
        Returns:
            Token preview string
        """
        if len(token) <= length * 2:
            return token
        
        return f"{token[:length]}...{token[-length:]}"
    
    @staticmethod
    def extract_claim(token: str, claim_name: str) -> Optional[any]:
        """
        Extract a specific claim from a token.
        
        Args:
            token: JWT string
            claim_name: Name of the claim to extract
            
        Returns:
            Claim value or None if not found
        """
        try:
            decoded = JWTDecoder.decode(token)
            return decoded['payload'].get(claim_name)
        except:
            return None
    
    @staticmethod
    def is_expired(token: str) -> Tuple[bool, Optional[datetime]]:
        """
        Check if a token is expired.
        
        Args:
            token: JWT string
            
        Returns:
            Tuple of (is_expired, expiration_datetime)
        """
        try:
            decoded = JWTDecoder.decode(token)
            exp = decoded['payload'].get('exp')
            
            if exp is None:
                return (False, None)  # No expiration claim
            
            exp_datetime = datetime.fromtimestamp(exp)
            is_expired = datetime.utcnow() > exp_datetime
            
            return (is_expired, exp_datetime)
            
        except:
            return (True, None)  # Assume expired if we can't decode
    
    @staticmethod
    def get_time_until_expiry(token: str) -> Optional[float]:
        """
        Get the time in seconds until token expiry.
        
        Args:
            token: JWT string
            
        Returns:
            Seconds until expiry, or None if no expiration
        """
        is_expired, exp_datetime = JWTDecoder.is_expired(token)
        
        if exp_datetime is None:
            return None
        
        if is_expired:
            return 0
        
        delta = exp_datetime - datetime.utcnow()
        return delta.total_seconds()
    
    @staticmethod
    def format_token_info(decoded: Dict) -> str:
        """
        Format decoded token information for display.
        
        Args:
            decoded: Decoded token dictionary
            
        Returns:
            Formatted string
        """
        lines = []
        
        # Header
        lines.append("=== TOKEN HEADER ===")
        lines.append(json.dumps(decoded['header'], indent=2))
        lines.append("")
        
        # Payload
        lines.append("=== TOKEN PAYLOAD ===")
        lines.append(json.dumps(decoded['payload'], indent=2))
        lines.append("")
        
        # Key claims
        payload = decoded['payload']
        lines.append("=== KEY CLAIMS ===")
        
        if 'iss' in payload:
            lines.append(f"Issuer (iss): {payload['iss']}")
        if 'sub' in payload:
            lines.append(f"Subject (sub): {payload['sub']}")
        if 'aud' in payload:
            lines.append(f"Audience (aud): {payload['aud']}")
        if 'exp_readable' in payload:
            lines.append(f"Expires (exp): {payload['exp_readable']}")
        if 'iat_readable' in payload:
            lines.append(f"Issued At (iat): {payload['iat_readable']}")
        
        return '\n'.join(lines)

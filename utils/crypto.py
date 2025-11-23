"""
Cryptographic utilities for PKCE, state generation, and token verification.
"""

import hashlib
import base64
import secrets
import os


def generate_code_verifier(length=128):
    """
    Generate a cryptographically random code verifier for PKCE.
    
    Args:
        length: Length of the verifier (43-128 characters)
        
    Returns:
        Base64-URL encoded random string
    """
    if length < 43 or length > 128:
        raise ValueError("Code verifier length must be between 43 and 128")
    
    # Generate random bytes
    random_bytes = secrets.token_bytes(length)
    
    # Base64-URL encode without padding
    verifier = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
    verifier = verifier.rstrip('=')
    
    # Truncate to requested length
    return verifier[:length]


def generate_code_challenge(verifier, method='S256'):
    """
    Generate a code challenge from a code verifier.
    
    Args:
        verifier: The code verifier string
        method: Challenge method ('S256' or 'plain')
        
    Returns:
        Code challenge string
    """
    if method == 'plain':
        return verifier
    elif method == 'S256':
        # SHA256 hash
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        # Base64-URL encode without padding
        challenge = base64.urlsafe_b64encode(digest).decode('utf-8')
        return challenge.rstrip('=')
    else:
        raise ValueError(f"Unsupported challenge method: {method}")


def generate_state(length=32):
    """
    Generate a random state parameter for CSRF protection.
    
    Args:
        length: Length of the state string
        
    Returns:
        Random state string
    """
    return secrets.token_urlsafe(length)


def generate_nonce(length=32):
    """
    Generate a random nonce for OIDC requests.
    
    Args:
        length: Length of the nonce string
        
    Returns:
        Random nonce string
    """
    return secrets.token_urlsafe(length)


def base64url_decode(input_str):
    """
    Decode a Base64-URL encoded string.
    
    Args:
        input_str: Base64-URL encoded string
        
    Returns:
        Decoded bytes
    """
    # Add padding if necessary
    padding = 4 - (len(input_str) % 4)
    if padding != 4:
        input_str += '=' * padding
    
    return base64.urlsafe_b64decode(input_str)


def base64url_encode(input_bytes):
    """
    Encode bytes to Base64-URL format.
    
    Args:
        input_bytes: Bytes to encode
        
    Returns:
        Base64-URL encoded string without padding
    """
    encoded = base64.urlsafe_b64encode(input_bytes).decode('utf-8')
    return encoded.rstrip('=')


def generate_session_id():
    """
    Generate a unique session ID.
    
    Returns:
        Random session ID
    """
    return secrets.token_hex(16)

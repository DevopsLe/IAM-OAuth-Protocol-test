"""
Claims analyzer for categorizing and analyzing JWT claims.
"""

from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class ClaimsAnalyzer:
    """Analyzer for JWT claims with categorization and role/permission extraction."""
    
    # Standard OIDC claims
    STANDARD_OIDC_CLAIMS = {
        'iss': 'Issuer - Identity provider that issued the token',
        'sub': 'Subject - Unique identifier for the user',
        'aud': 'Audience - Intended recipient of the token',
        'exp': 'Expiration Time - When the token expires',
        'iat': 'Issued At - When the token was issued',
        'nbf': 'Not Before - Token is not valid before this time',
        'auth_time': 'Authentication Time - When the user authenticated',
        'nonce': 'Nonce - Value used to associate a client session with an ID token',
        'acr': 'Authentication Context Class Reference - How the user authenticated',
        'amr': 'Authentication Methods References - Methods used to authenticate',
        'azp': 'Authorized Party - Party to which the ID token was issued',
    }
    
    # Standard profile claims
    PROFILE_CLAIMS = {
        'name': 'Full name',
        'given_name': 'Given name(s) or first name(s)',
        'family_name': 'Surname(s) or last name(s)',
        'middle_name': 'Middle name(s)',
        'nickname': 'Casual name',
        'preferred_username': 'Shorthand name',
        'profile': 'Profile page URL',
        'picture': 'Profile picture URL',
        'website': 'Web page or blog URL',
        'email': 'Email address',
        'email_verified': 'Email address verified',
        'gender': 'Gender',
        'birthdate': 'Birthday',
        'zoneinfo': 'Time zone',
        'locale': 'Locale',
        'phone_number': 'Phone number',
        'phone_number_verified': 'Phone number verified',
        'address': 'Postal address',
        'updated_at': 'Time the information was last updated',
    }
    
    # Authorization-related claims
    AUTHORIZATION_CLAIMS = {
        'scope': 'OAuth scopes',
        'scp': 'Scopes (Azure format)',
        'roles': 'User roles',
        'groups': 'User groups',
        'permissions': 'User permissions',
    }
    
    @classmethod
    def analyze(cls, claims: Dict) -> Dict:
        """
        Analyze and categorize token claims.
        
        Args:
            claims: Token claims dictionary
            
        Returns:
            Dictionary with categorized claims
        """
        analysis = {
            'standard_oidc': {},
            'profile': {},
            'authorization': {},
            'custom': {},
            'all_claims': claims,
            'claim_count': len(claims),
        }
        
        for claim_name, claim_value in claims.items():
            # Skip internal parsed claims (like exp_datetime)
            if claim_name.endswith('_datetime') or claim_name.endswith('_readable'):
                continue
            
            if claim_name in cls.STANDARD_OIDC_CLAIMS:
                analysis['standard_oidc'][claim_name] = {
                    'value': claim_value,
                    'description': cls.STANDARD_OIDC_CLAIMS[claim_name]
                }
            elif claim_name in cls.PROFILE_CLAIMS:
                analysis['profile'][claim_name] = {
                    'value': claim_value,
                    'description': cls.PROFILE_CLAIMS[claim_name]
                }
            elif claim_name in cls.AUTHORIZATION_CLAIMS:
                analysis['authorization'][claim_name] = {
                    'value': claim_value,
                    'description': cls.AUTHORIZATION_CLAIMS[claim_name]
                }
            else:
                # Custom claim
                analysis['custom'][claim_name] = claim_value
        
        # Extract roles and permissions
        analysis['roles'] = cls.extract_roles(claims)
        analysis['permissions'] = cls.extract_permissions(claims)
        analysis['scopes'] = cls.extract_scopes(claims)
        
        return analysis
    
    @classmethod
    def extract_roles(cls, claims: Dict) -> List[str]:
        """
        Extract user roles from claims.
        
        Args:
            claims: Token claims
            
        Returns:
            List of roles
        """
        roles = []
        
        # Check common role claim names
        role_claims = ['roles', 'role', 'groups', 'group']
        
        for claim_name in role_claims:
            if claim_name in claims:
                value = claims[claim_name]
                if isinstance(value, list):
                    roles.extend(value)
                elif isinstance(value, str):
                    roles.append(value)
        
        # Azure-specific: roles in extension claims
        for claim_name, claim_value in claims.items():
            if 'roles' in claim_name.lower() and isinstance(claim_value, list):
                roles.extend(claim_value)
        
        return list(set(roles))  # Remove duplicates
    
    @classmethod
    def extract_permissions(cls, claims: Dict) -> List[str]:
        """
        Extract permissions from claims.
        
        Args:
            claims: Token claims
            
        Returns:
            List of permissions
        """
        permissions = []
        
        # Check common permission claim names
        permission_claims = ['permissions', 'permission', 'perms']
        
        for claim_name in permission_claims:
            if claim_name in claims:
                value = claims[claim_name]
                if isinstance(value, list):
                    permissions.extend(value)
                elif isinstance(value, str):
                    permissions.append(value)
        
        return list(set(permissions))
    
    @classmethod
    def extract_scopes(cls, claims: Dict) -> List[str]:
        """
        Extract scopes from claims.
        
        Args:
            claims: Token claims
            
        Returns:
            List of scopes
        """
        scopes = []
        
        # Check 'scp' claim (Azure format - array)
        if 'scp' in claims:
            value = claims['scp']
            if isinstance(value, list):
                scopes.extend(value)
            elif isinstance(value, str):
                scopes.extend(value.split())
        
        # Check 'scope' claim (standard format - space-separated string)
        if 'scope' in claims:
            value = claims['scope']
            if isinstance(value, str):
                scopes.extend(value.split())
            elif isinstance(value, list):
                scopes.extend(value)
        
        return list(set(scopes))
    
    @classmethod
    def has_scope(cls, claims: Dict, required_scope: str) -> bool:
        """
        Check if claims contain a specific scope.
        
        Args:
            claims: Token claims
            required_scope: Scope to check for
            
        Returns:
            True if scope is present
        """
        scopes = cls.extract_scopes(claims)
        return required_scope in scopes
    
    @classmethod
    def has_role(cls, claims: Dict, required_role: str) -> bool:
        """
        Check if claims contain a specific role.
        
        Args:
            claims: Token claims
            required_role: Role to check for
            
        Returns:
            True if role is present
        """
        roles = cls.extract_roles(claims)
        return required_role in roles
    
    @classmethod
    def format_analysis(cls, analysis: Dict) -> str:
        """
        Format claims analysis for display.
        
        Args:
            analysis: Claims analysis dictionary
            
        Returns:
            Formatted string
        """
        lines = []
        
        lines.append(f"=== CLAIMS ANALYSIS ({analysis['claim_count']} claims) ===\n")
        
        # Standard OIDC claims
        if analysis['standard_oidc']:
            lines.append("--- Standard OIDC Claims ---")
            for claim_name, claim_info in analysis['standard_oidc'].items():
                lines.append(f"{claim_name}: {claim_info['value']}")
                lines.append(f"  → {claim_info['description']}")
            lines.append("")
        
        # Profile claims
        if analysis['profile']:
            lines.append("--- Profile Claims ---")
            for claim_name, claim_info in analysis['profile'].items():
                lines.append(f"{claim_name}: {claim_info['value']}")
                lines.append(f"  → {claim_info['description']}")
            lines.append("")
        
        # Authorization claims
        if analysis['authorization']:
            lines.append("--- Authorization Claims ---")
            for claim_name, claim_info in analysis['authorization'].items():
                lines.append(f"{claim_name}: {claim_info['value']}")
                lines.append(f"  → {claim_info['description']}")
            lines.append("")
        
        # Extracted roles and permissions
        if analysis['roles']:
            lines.append("--- Roles ---")
            for role in analysis['roles']:
                lines.append(f"  • {role}")
            lines.append("")
        
        if analysis['permissions']:
            lines.append("--- Permissions ---")
            for perm in analysis['permissions']:
                lines.append(f"  • {perm}")
            lines.append("")
        
        if analysis['scopes']:
            lines.append("--- Scopes ---")
            for scope in analysis['scopes']:
                lines.append(f"  • {scope}")
            lines.append("")
        
        # Custom claims
        if analysis['custom']:
            lines.append("--- Custom Claims ---")
            for claim_name, claim_value in analysis['custom'].items():
                lines.append(f"{claim_name}: {claim_value}")
            lines.append("")
        
        return '\n'.join(lines)
    
    @classmethod
    def compare_claims(cls, claims1: Dict, claims2: Dict) -> Dict:
        """
        Compare two sets of claims (e.g., ID token vs Access token).
        
        Args:
            claims1: First set of claims
            claims2: Second set of claims
            
        Returns:
            Dictionary with comparison results
        """
        all_claims = set(claims1.keys()) | set(claims2.keys())
        
        comparison = {
            'only_in_first': {},
            'only_in_second': {},
            'in_both': {},
            'different_values': {}
        }
        
        for claim in all_claims:
            if claim in claims1 and claim in claims2:
                if claims1[claim] == claims2[claim]:
                    comparison['in_both'][claim] = claims1[claim]
                else:
                    comparison['different_values'][claim] = {
                        'first': claims1[claim],
                        'second': claims2[claim]
                    }
            elif claim in claims1:
                comparison['only_in_first'][claim] = claims1[claim]
            else:
                comparison['only_in_second'][claim] = claims2[claim]
        
        return comparison

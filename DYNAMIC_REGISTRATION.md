# Dynamic Client Registration Feature

## Overview

The IAM Protocol Testing Application now supports **automatic application registration** with identity providers. Instead of manually creating applications in Azure or Okta and copying Client IDs, you can now register applications programmatically directly from the testing interface.

## Supported Providers

### 1. Azure / Microsoft Entra ID
- Uses Microsoft Graph API for application registration
- Requires an access token with `Application.ReadWrite.All` permission
- Automatically creates:
  - Application registration
  - Service principal
  - Client secret
  - API permissions (User.Read, profile, email, openid)

### 2. Okta
- Uses Okta Management API for application registration
- Requires an API token with application management permissions
- Automatically creates:
  - OIDC web application
  - Client ID and secret
  - Redirect URI configuration
  - Grant type configuration

### 3. Generic OIDC (RFC 7591)
- Uses OIDC Dynamic Client Registration standard
- Works with any RFC 7591 compliant provider
- Optional initial access token support

## How to Use

### Azure Registration

1. **Get Access Token**:
   ```bash
   az account get-access-token --resource https://graph.microsoft.com
   ```

2. **In the Application**:
   - Select Azure as provider
   - Click "✨ Auto-Register New App" button
   - Paste your access token
   - Enter application name (optional)
   - Click "Register Application"

3. **Result**:
   - Client ID and Secret are automatically generated
   - Credentials are auto-filled in the form
   - Application is ready for testing

### Okta Registration

1. **Get API Token**:
   - Go to Okta Admin Console
   - Security → API → Tokens
   - Create new token with application management permissions

2. **In the Application**:
   - Select Okta as provider
   - Enter your Okta domain
   - Click "✨ Auto-Register New App" button
   - Paste your API token
   - Enter application name (optional)
   - Click "Register Application"

3. **Result**:
   - Client ID and Secret are automatically generated
   - Credentials are auto-filled in the form
   - Application is ready for testing

## API Endpoints

### POST /api/register/azure
Register a new application in Azure AD.

**Request Body**:
```json
{
  "tenant_id": "your-tenant-id",
  "access_token": "eyJ0eXAi...",
  "app_name": "IAM Protocol Tester",
  "redirect_uris": ["http://localhost:5000/callback"],
  "scopes": ["User.Read", "profile", "email", "openid"]
}
```

**Response**:
```json
{
  "success": true,
  "client_id": "abc123...",
  "client_secret": "xyz789...",
  "tenant_id": "your-tenant-id",
  "app_id": "internal-app-id",
  "message": "Application registered successfully in Azure AD"
}
```

### POST /api/register/okta
Register a new application in Okta.

**Request Body**:
```json
{
  "domain": "your-domain.okta.com",
  "api_token": "00abc...",
  "app_name": "IAM Protocol Tester",
  "redirect_uris": ["http://localhost:5000/callback"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

**Response**:
```json
{
  "success": true,
  "client_id": "0oa123...",
  "client_secret": "secret123...",
  "domain": "your-domain.okta.com",
  "app_id": "0oa123...",
  "message": "Application registered successfully in Okta"
}
```

### POST /api/register/generic
Register a client using OIDC Dynamic Client Registration (RFC 7591).

**Request Body**:
```json
{
  "registration_endpoint": "https://idp.example.com/register",
  "access_token": "optional-initial-token",
  "app_name": "IAM Protocol Tester",
  "redirect_uris": ["http://localhost:5000/callback"]
}
```

## Implementation Details

### Backend Components

**File**: `providers/client_registration.py`

Contains three main classes:

1. **AzureClientRegistration**
   - `register_application()`: Creates app registration, service principal, and client secret
   - `delete_application()`: Removes application from Azure AD
   - Uses Microsoft Graph API v1.0

2. **OktaClientRegistration**
   - `register_application()`: Creates OIDC web application
   - `delete_application()`: Deactivates and deletes application
   - Uses Okta Management API v1

3. **GenericOIDCRegistration**
   - `register_application()`: Uses RFC 7591 standard
   - Works with any compliant OIDC provider

### Frontend Components

**Modal Dialog**: Displays registration form with provider-specific fields
**Auto-fill**: Automatically populates Client ID and Secret after successful registration
**Session Storage**: Stores registration details for easy access

## Security Considerations

⚠️ **Important**:
- Access tokens and API tokens are sensitive - never commit them to version control
- Tokens are only used for the registration request and not stored
- Generated client secrets should be rotated regularly
- Use separate test applications for development and production
- Review and limit API permissions to minimum required

## Benefits

✅ **Faster Testing**: No manual application creation required
✅ **Consistency**: Standardized application configuration
✅ **Automation**: Enables scripted testing workflows
✅ **Convenience**: One-click setup for new tests
✅ **Error Reduction**: Eliminates manual copy-paste errors

## Limitations

- Azure requires admin-level access token
- Okta requires API token with application management permissions
- Generic OIDC depends on provider support for RFC 7591
- Some providers may require additional manual configuration (e.g., admin consent in Azure)

## Future Enhancements

- [ ] Support for SAML application registration
- [ ] Automatic cleanup of test applications
- [ ] Batch registration for multiple configurations
- [ ] Integration with CI/CD pipelines
- [ ] Support for additional identity providers (Auth0, Keycloak, etc.)

## Troubleshooting

**"Insufficient privileges" error (Azure)**:
- Ensure your access token has `Application.ReadWrite.All` permission
- You may need Global Administrator or Application Administrator role

**"Forbidden" error (Okta)**:
- Verify your API token has application management permissions
- Check that the token hasn't expired

**"Invalid redirect_uri" error**:
- Ensure the redirect URI matches your application's running port
- Include protocol (http/https) and full path

## Example Workflow

1. Open IAM Protocol Tester dashboard
2. Select "Azure" as provider
3. Select "Authorization Code with PKCE" as flow
4. Click "✨ Auto-Register New App"
5. Paste Azure access token
6. Click "Register Application"
7. Credentials are auto-filled
8. Click "🚀 Start Test"
9. Complete authentication flow
10. View detailed results

---

This feature significantly streamlines the testing process by eliminating manual application setup steps!

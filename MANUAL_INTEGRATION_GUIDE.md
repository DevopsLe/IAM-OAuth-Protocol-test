# Manual Integration Guide

Complete guide for manually configuring applications in supported identity providers for testing with the IAM Protocol Testing Application.

---

## Table of Contents

- [Azure / Microsoft Entra ID](#azure--microsoft-entra-id)
- [Okta](#okta)
- [Generic OIDC Provider](#generic-oidc-provider)
- [Supported OAuth Flows](#supported-oauth-flows)
- [Testing Your Integration](#testing-your-integration)

---

## Azure / Microsoft Entra ID

### Prerequisites
- Azure account with application registration permissions
- Access to Azure Portal or Azure CLI

### Step 1: Register Application

#### Using Azure Portal

1. **Navigate to Azure Portal**
   - Go to [portal.azure.com](https://portal.azure.com)
   - Navigate to **Azure Active Directory** (or **Microsoft Entra ID**)

2. **Create App Registration**
   - Click **App registrations** in the left menu
   - Click **+ New registration**
   - Enter application details:
     - **Name**: `IAM Protocol Tester`
     - **Supported account types**: Choose based on your needs
       - Single tenant (recommended for testing)
       - Multi-tenant
     - **Redirect URI**: 
       - Platform: **Web**
       - URI: `http://localhost:5000/callback`
   - Click **Register**

3. **Note Your Credentials**
   - **Application (client) ID**: Copy this value
   - **Directory (tenant) ID**: Copy this value

4. **Create Client Secret**
   - In your app registration, go to **Certificates & secrets**
   - Click **+ New client secret**
   - Add description: `IAM Testing`
   - Choose expiration period
   - Click **Add**
   - **Copy the secret value immediately** (it won't be shown again)

5. **Configure API Permissions** (Optional)
   - Go to **API permissions**
   - Click **+ Add a permission**
   - Select **Microsoft Graph**
   - Select **Delegated permissions**
   - Add permissions:
     - `User.Read`
     - `profile`
     - `email`
     - `openid`
   - Click **Add permissions**
   - (Optional) Click **Grant admin consent**

#### Using Azure CLI

```bash
# Login to Azure
az login

# Create app registration
az ad app create \
  --display-name "IAM Protocol Tester" \
  --sign-in-audience AzureADMyOrg \
  --web-redirect-uris "http://localhost:5000/callback"

# Note the appId from the output

# Create service principal
az ad sp create --id <APP_ID>

# Create client secret
az ad app credential reset --id <APP_ID> --append
```

### Step 2: Configure in IAM Protocol Tester

1. Open `http://localhost:5000`
2. Select **Azure / Microsoft Entra ID** as provider
3. Select your desired flow
4. Enter configuration:
   - **Client ID**: Your Application (client) ID
   - **Client Secret**: Your client secret
   - **Tenant ID**: Your Directory (tenant) ID
   - **Scopes**: `openid profile email User.Read`
   - **Redirect URI**: `http://localhost:5000/callback`

---

## Okta

### Prerequisites
- Okta account (free developer account available at [developer.okta.com](https://developer.okta.com))
- Admin access to Okta organization

### Step 1: Create Application

1. **Login to Okta Admin Console**
   - Go to `https://your-domain.okta.com/admin`
   - Replace `your-domain` with your actual Okta domain

2. **Create App Integration**
   - Navigate to **Applications** → **Applications**
   - Click **Create App Integration**
   - Select integration type:
     - **Sign-in method**: **OIDC - OpenID Connect**
     - **Application type**: **Web Application**
   - Click **Next**

3. **Configure Application Settings**
   - **App integration name**: `IAM Protocol Tester`
   - **Grant type**: Check the following:
     - ✅ **Authorization Code**
     - ✅ **Refresh Token**
     - ✅ **Implicit (Hybrid)** (optional, for implicit flow testing)
   - **Sign-in redirect URIs**: 
     - Add: `http://localhost:5000/callback`
   - **Sign-out redirect URIs**: (optional)
   - **Controlled access**: 
     - Select **Allow everyone in your organization to access**
     - Or assign specific groups/users
   - Click **Save**

4. **Note Your Credentials**
   - **Client ID**: Displayed on the application page
   - **Client secret**: Click to reveal and copy

5. **Assign Users** (if not allowing everyone)
   - Go to **Assignments** tab
   - Click **Assign** → **Assign to People** or **Assign to Groups**
   - Select users/groups and click **Assign**

### Step 2: Configure in IAM Protocol Tester

1. Open `http://localhost:5000`
2. Select **Okta** as provider
3. Select your desired flow
4. Enter configuration:
   - **Client ID**: Your Okta client ID
   - **Client Secret**: Your Okta client secret
   - **Okta Domain**: `your-domain.okta.com` (without https://)
   - **Scopes**: `openid profile email`
   - **Redirect URI**: `http://localhost:5000/callback`

### Okta Custom Authorization Server

For testing with a custom authorization server:

1. **Create Authorization Server**
   - Go to **Security** → **API** → **Authorization Servers**
   - Click **Add Authorization Server**
   - Configure server details

2. **Configure in Tester**
   - Select **Okta (Custom Authorization Server)** as provider
   - **Auth Server ID**: Your authorization server ID
   - Other settings same as above

---

## Generic OIDC Provider

For any OIDC-compliant identity provider not specifically listed.

### Prerequisites
- OIDC-compliant identity provider
- Application registration capability
- Discovery document endpoint

### Step 1: Register Application

The exact steps vary by provider, but generally:

1. **Create OAuth/OIDC Application**
   - Login to your identity provider's admin console
   - Navigate to application/client registration
   - Create new application with these settings:
     - **Application type**: Web application
     - **Grant types**: Authorization Code, Refresh Token
     - **Redirect URI**: `http://localhost:5000/callback`

2. **Note Credentials**
   - **Client ID**
   - **Client Secret**
   - **Discovery Endpoint**: Usually `https://your-idp.com/.well-known/openid-configuration`

### Step 2: Configure in IAM Protocol Tester

1. Open `http://localhost:5000`
2. Select **Generic OIDC Provider**
3. Select your desired flow
4. Enter configuration:
   - **Client ID**: Your client ID
   - **Client Secret**: Your client secret
   - **Discovery Endpoint**: Your OIDC discovery URL
   - **Scopes**: `openid profile email`
   - **Redirect URI**: `http://localhost:5000/callback`

---

## Supported OAuth Flows

### 1. Authorization Code Flow with PKCE

**Best for**: Web applications, mobile apps, SPAs

**Security**: Highest (recommended)

**Configuration**:
- **Requires Client Secret**: No (but can be used)
- **Uses PKCE**: Yes
- **Recommended Scopes**: `openid profile email`

**When to Use**:
- Modern web applications
- Single-page applications (SPAs)
- Mobile applications
- Any application that can't securely store client secrets

### 2. Authorization Code Flow

**Best for**: Traditional server-side web applications

**Security**: High

**Configuration**:
- **Requires Client Secret**: Yes
- **Uses PKCE**: No
- **Recommended Scopes**: `openid profile email`

**When to Use**:
- Traditional server-side applications
- Applications that can securely store client secrets
- Legacy integrations

### 3. Client Credentials Flow

**Best for**: Machine-to-machine authentication

**Security**: High (for M2M scenarios)

**Configuration**:
- **Requires Client Secret**: Yes
- **Uses PKCE**: No
- **No User Interaction**: Fully automated
- **Recommended Scopes**: API-specific scopes

**When to Use**:
- Backend services
- API-to-API communication
- Automated processes
- No user context needed

### 4. Implicit Flow (Legacy)

**Best for**: Legacy SPAs (not recommended)

**Security**: Lower (deprecated)

**Configuration**:
- **Requires Client Secret**: No
- **Uses PKCE**: No
- **Tokens in URL**: Yes (security concern)

**When to Use**:
- **Not recommended** - use Authorization Code Flow with PKCE instead
- Only for legacy applications that cannot be updated

---

## Testing Your Integration

### Quick Test Steps

1. **Start the Application**
   ```bash
   python app.py
   ```

2. **Open Browser**
   - Navigate to `http://localhost:5000`

3. **Configure Test**
   - Select your identity provider
   - Select authentication flow
   - Enter credentials (Client ID, Secret, etc.)
   - Click **🚀 Start Test**

4. **Authenticate**
   - You'll be redirected to your identity provider
   - Login with your credentials
   - Consent to permissions (if prompted)

5. **View Results**
   - After successful authentication, you'll see:
     - ✅ Decoded ID Token with all claims
     - ✅ Decoded Access Token
     - ✅ Token validation results
     - ✅ API access test results
     - ✅ Complete flow diagnostics

### What to Verify

#### ID Token Claims
- `iss` (Issuer): Should match your IdP
- `sub` (Subject): User identifier
- `aud` (Audience): Should match your client ID
- `exp` (Expiration): Token expiry time
- `iat` (Issued At): Token issue time
- `nonce`: Should match the request (if used)

#### Access Token
- Valid JWT format (if JWT-based)
- Appropriate scopes
- Valid signature
- Not expired

#### Token Validation
- Signature verification
- Expiration check
- Issuer validation
- Audience validation
- Nonce validation (for ID tokens)

---

## Common Issues and Solutions

### Issue: Redirect URI Mismatch

**Error**: `redirect_uri_mismatch` or similar

**Solution**:
- Ensure redirect URI in IdP exactly matches: `http://localhost:5000/callback`
- No trailing slashes
- Exact protocol (http vs https)
- Exact port number

### Issue: Invalid Client

**Error**: `invalid_client`

**Solution**:
- Verify Client ID is correct
- Verify Client Secret is correct (if required)
- Check if client secret has expired
- Ensure application is enabled in IdP

### Issue: Insufficient Scopes

**Error**: `insufficient_scope` or `access_denied`

**Solution**:
- Add required scopes in IdP application configuration
- Grant admin consent (Azure)
- Ensure user has necessary permissions

### Issue: Token Validation Failed

**Error**: Signature verification failed

**Solution**:
- Check JWKS URI is correct
- Verify issuer matches expected value
- Ensure token hasn't expired
- Check audience claim

---

## Security Best Practices

### For Production Use

1. **Use HTTPS**
   - Never use `http://` in production
   - Update redirect URI to `https://your-domain.com/callback`

2. **Secure Client Secrets**
   - Store in environment variables
   - Never commit to source control
   - Rotate regularly
   - Use secret management systems

3. **Validate Tokens**
   - Always validate signature
   - Check expiration
   - Verify issuer and audience
   - Validate nonce (for ID tokens)

4. **Use PKCE**
   - Always use PKCE for public clients
   - Recommended even for confidential clients

5. **Limit Scopes**
   - Request only necessary scopes
   - Follow principle of least privilege

6. **Monitor and Log**
   - Log authentication attempts
   - Monitor for suspicious activity
   - Set up alerts for failures

---

## Additional Resources

### Azure / Microsoft Entra ID
- [Microsoft Identity Platform Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
- [App Registration Guide](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)

### Okta
- [Okta Developer Documentation](https://developer.okta.com/docs/)
- [OIDC & OAuth 2.0 API](https://developer.okta.com/docs/reference/api/oidc/)

### OAuth 2.0 & OIDC
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)

---

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review application logs in `logs/iam_testing.log`
3. Check test results for detailed error messages
4. Refer to your identity provider's documentation

---

**Last Updated**: November 2025

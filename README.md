# 🛡️ IAM Protocol Testing Application

A comprehensive, protocol-agnostic testing platform for validating IAM authentication and authorization flows against major identity providers like Azure and Okta.

## Features

### 🔐 Protocol Support
- **OpenID Connect (OIDC)**: Authorization Code Flow with PKCE
- **OAuth 2.0**: Client Credentials, Authorization Code, Refresh Token flows
- **SAML 2.0**: Coming soon

### 🌐 Identity Provider Integration
- **Azure / Microsoft Entra ID**: Full support with tenant configuration
- **Okta**: Standard and custom authorization servers
- **Generic OIDC**: Any standards-compliant identity provider

### 🔍 Comprehensive Analysis
- **JWT Decoder**: Automatic decoding and parsing of ID and Access tokens
- **Token Validation**: Signature verification, expiration checking, issuer/audience validation
- **Claims Analysis**: Categorization of standard OIDC, profile, and authorization claims
- **Scope & Role Extraction**: Automatic identification of permissions and roles

### 🧪 Authorization Testing
- **Mock Resource Server**: Test API endpoints with different permission requirements
- **Permission Validation**: Verify scope and role-based access control
- **API Response Analysis**: Detailed diagnostics for 401/403 errors

### 📊 Diagnostics & Logging
- **End-to-End Tracing**: Complete flow execution logs with HTTP request/response details
- **Error Analysis**: Pattern matching for common OAuth/OIDC errors with actionable suggestions
- **Validation Reports**: Comprehensive token validation results

### 🎨 Premium UI
- **Dark Mode Design**: Modern, professional interface with glassmorphism effects
- **Interactive Dashboard**: Easy provider and flow selection
- **Real-time Results**: Live token decoding and claims visualization
- **Execution Logs**: Detailed step-by-step flow tracking

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. **Clone or navigate to the application directory**
   ```bash
   cd d:\Scripting\Application
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   # Copy the example file
   copy .env.example .env
   
   # Edit .env and add your configuration
   ```

5. **Initialize the database**
   ```bash
   python app.py
   # Or use Flask CLI
   flask init-db
   ```

6. **Run the application**
   ```bash
   python app.py
   ```

The application will be available at `http://localhost:5000`

## Configuration

### Environment Variables

Edit the `.env` file to configure the application:

```env
# Flask Configuration
SECRET_KEY=your-secret-key-here
DEBUG=True

# Database
DATABASE_URL=sqlite:///iam_testing.db

# Application Settings
APP_HOST=localhost
APP_PORT=5000
REDIRECT_URI=http://localhost:5000/callback

# Azure Configuration (Optional)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# Okta Configuration (Optional)
OKTA_DOMAIN=your-domain.okta.com
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret
```

### Identity Provider Setup

#### Azure / Microsoft Entra ID

1. Go to [Azure Portal](https://portal.azure.com) → Azure Active Directory → App registrations
2. Click "New registration"
3. Configure:
   - **Name**: IAM Protocol Tester
   - **Redirect URI**: `http://localhost:5000/callback` (Web)
4. After creation:
   - Note the **Application (client) ID**
   - Note the **Directory (tenant) ID**
   - Go to "Certificates & secrets" → Create a new client secret
   - Go to "API permissions" → Add permissions (e.g., User.Read, profile, email)
   - Grant admin consent if required

#### Okta

1. Go to [Okta Admin Console](https://your-domain.okta.com/admin)
2. Applications → Create App Integration
3. Configure:
   - **Sign-in method**: OIDC
   - **Application type**: Web Application
4. Settings:
   - **Sign-in redirect URIs**: `http://localhost:5000/callback`
   - **Assignments**: Assign users/groups
5. Note the **Client ID** and **Client secret**

## Usage

### Running a Test

1. **Open the application** at `http://localhost:5000`

2. **Select Identity Provider**
   - Choose from Azure, Okta, or Generic OIDC

3. **Select Authentication Flow**
   - Authorization Code Flow with PKCE (recommended for web/mobile)
   - Client Credentials Flow (for machine-to-machine)

4. **Configure Parameters**
   - Enter Client ID and Client Secret
   - Specify scopes (e.g., `openid profile email`)
   - Add provider-specific details (Tenant ID for Azure, Domain for Okta)

5. **Start Test**
   - Click "Start Test" to initiate the flow
   - You'll be redirected to the identity provider for authentication
   - After successful authentication, view detailed results

### Viewing Results

The results page displays:

- **Test Summary**: Provider, flow type, status
- **Tokens**: ID Token, Access Token, Refresh Token (with copy functionality)
- **Decoded Claims**: All claims categorized by type (standard OIDC, profile, authorization)
- **Token Validation**: Signature, expiration, issuer, audience checks
- **API Test Results**: Permission validation for mock endpoints
- **Execution Logs**: Complete flow trace with HTTP requests/responses

### API Testing

The application includes a mock resource server with several endpoints:

- `/api/public` - No authentication required
- `/api/profile` - Requires `profile` scope
- `/api/email` - Requires `email` scope
- `/api/admin` - Requires `Admin` or `Administrator` role
- `/api/data/read` - Requires `data.read` scope
- `/api/data/write` - Requires `data.write` scope

## Project Structure

```
Application/
├── app.py                      # Main Flask application
├── config.py                   # Configuration management
├── models.py                   # Database models
├── requirements.txt            # Python dependencies
├── .env.example               # Environment variables template
│
├── auth/                      # Authentication handlers
│   ├── oidc_handler.py       # OIDC flow implementation
│   └── oauth_handler.py      # OAuth 2.0 flows
│
├── tokens/                    # Token management
│   ├── decoder.py            # JWT decoder
│   ├── validator.py          # Token validator
│   └── claims_analyzer.py    # Claims analysis
│
├── resource_server/           # Mock API
│   └── mock_api.py           # Resource server endpoints
│
├── logging/                   # Logging & diagnostics
│   ├── logger.py             # Test logger
│   └── diagnostics.py        # Error analysis
│
├── utils/                     # Utilities
│   ├── crypto.py             # PKCE & cryptographic functions
│   └── http_client.py        # HTTP client wrapper
│
├── static/                    # Frontend assets
│   └── css/
│       └── style.css         # Premium dark mode styles
│
└── templates/                 # HTML templates
    ├── index.html            # Dashboard
    └── results.html          # Results page
```

## Troubleshooting

### Common Issues

**"Invalid redirect_uri"**
- Ensure the redirect URI in your test matches exactly what's registered in the IdP
- Include protocol (http/https), port, and path
- No trailing slashes unless registered with one

**"Invalid client credentials"**
- Verify Client ID and Client Secret are correct
- Check that the application is enabled in the IdP
- For Azure: Ensure you're using the correct tenant ID

**"Invalid scope"**
- Verify all requested scopes are configured in the application
- For Azure: Check API permissions and admin consent
- For Okta: Verify scopes in the Authorization Server

**Token signature validation fails**
- Ensure JWKS URI is accessible
- Check that the token issuer matches your IdP
- Verify you're using the correct public key

**403 Forbidden on API endpoints**
- Check the access token contains required scopes
- Verify user has necessary roles assigned
- Review the permission check results in the test output

## Advanced Features

### Custom Scopes

Add custom scopes in the configuration form:
```
openid profile email custom.scope.read custom.scope.write
```

### Token Analysis

Use the standalone token decoder:
```bash
POST /api/token/decode
{
  "token": "eyJhbGc..."
}
```

### Saved Configurations

Test configurations are automatically saved and can be reused from the dashboard.

## Security Considerations

⚠️ **Important Security Notes**:

- This is a **testing tool** - do not use in production environments
- Never commit `.env` file with real credentials
- Use separate test applications in your IdP
- Rotate client secrets regularly
- Review and limit API permissions to minimum required
- Use HTTPS in production deployments

## Contributing

This application is designed for internal testing and validation. To extend functionality:

1. Add new provider templates in `config.py`
2. Implement additional flows in `auth/` handlers
3. Add custom diagnostic patterns in `logging/diagnostics.py`
4. Extend the mock API in `resource_server/mock_api.py`

## License

Internal use only.

## Support

For issues or questions:
- Review the execution logs in the test results
- Check the diagnostics section for error explanations
- Consult the identity provider documentation
- Review OAuth 2.0 and OIDC specifications

---

**Built with ❤️ for comprehensive IAM testing**

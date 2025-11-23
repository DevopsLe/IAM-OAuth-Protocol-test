"""
Main Flask application for IAM Protocol Testing.
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import os
import json
from datetime import datetime

from config import Config, ProviderConfig, FlowConfig
from models import db, TestConfiguration, TestResult, LogEntry, SavedToken
from log_system.logger import TestLogger, setup_application_logging
from log_system.diagnostics import DiagnosticAnalyzer
from tokens.decoder import JWTDecoder
from tokens.validator import TokenValidator
from tokens.claims_analyzer import ClaimsAnalyzer
from auth.oidc_handler import OIDCHandler
from auth.oauth_handler import OAuthHandler
from resource_server.mock_api import resource_api, PermissionEngine
from utils.crypto import generate_session_id
from providers.client_registration import AzureClientRegistration, OktaClientRegistration, GenericOIDCRegistration

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Enable CORS
CORS(app)

# Initialize database
db.init_app(app)

# Register blueprints
app.register_blueprint(resource_api)

# Setup logging
setup_application_logging(Config.LOG_FILE, Config.LOG_LEVEL)


@app.before_request
def before_request():
    """Initialize session if needed."""
    if 'session_id' not in session:
        session['session_id'] = generate_session_id()


# ============================================================================
# Main Routes
# ============================================================================

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html',
                         providers=ProviderConfig.list_providers(),
                         flows=FlowConfig.list_flows())


@app.route('/results/<int:test_id>')
def results(test_id):
    """Results page for a specific test."""
    test_result = TestResult.query.get_or_404(test_id)
    return render_template('results.html', test_result=test_result.to_dict())


# ============================================================================
# API Routes - Configuration
# ============================================================================

@app.route('/api/providers', methods=['GET'])
def get_providers():
    """Get list of available identity providers."""
    return jsonify(ProviderConfig.list_providers())


@app.route('/api/provider/<provider_id>/config', methods=['GET'])
def get_provider_config(provider_id):
    """Get configuration template for a provider."""
    config = ProviderConfig.get_provider_template(provider_id)
    return jsonify(config)


@app.route('/api/flows', methods=['GET'])
def get_flows():
    """Get list of available authentication flows."""
    protocol = request.args.get('protocol', 'oidc')
    return jsonify(FlowConfig.list_flows(protocol))


@app.route('/api/flow/<flow_id>/config', methods=['GET'])
def get_flow_config(flow_id):
    """Get configuration for a specific flow."""
    config = FlowConfig.get_flow_config(flow_id)
    return jsonify(config)


# ============================================================================
# API Routes - Dynamic Client Registration
# ============================================================================

@app.route('/api/register/azure', methods=['POST'])
def register_azure_client():
    """Dynamically register an application in Azure AD."""
    data = request.get_json()
    
    tenant_id = data.get('tenant_id')
    access_token = data.get('access_token')
    app_name = data.get('app_name', 'IAM Protocol Tester')
    redirect_uris = data.get('redirect_uris', [Config.REDIRECT_URI])
    scopes = data.get('scopes', ['User.Read', 'profile', 'email', 'openid'])
    
    if not tenant_id or not access_token:
        return jsonify({
            'success': False,
            'error': 'tenant_id and access_token are required'
        }), 400
    
    try:
        registrar = AzureClientRegistration(tenant_id, access_token)
        result = registrar.register_application(app_name, redirect_uris, scopes)
        
        # Store registration in session for easy access
        if result['success']:
            session['azure_registration'] = result
        
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/register/okta', methods=['POST'])
def register_okta_client():
    """Dynamically register an application in Okta."""
    data = request.get_json()
    
    domain = data.get('domain')
    api_token = data.get('api_token')
    app_name = data.get('app_name', 'IAM Protocol Tester')
    redirect_uris = data.get('redirect_uris', [Config.REDIRECT_URI])
    grant_types = data.get('grant_types', ['authorization_code', 'refresh_token'])
    
    if not domain or not api_token:
        return jsonify({
            'success': False,
            'error': 'domain and api_token are required'
        }), 400
    
    try:
        registrar = OktaClientRegistration(domain, api_token)
        result = registrar.register_application(app_name, redirect_uris, grant_types)
        
        # Store registration in session for easy access
        if result['success']:
            session['okta_registration'] = result
        
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/register/generic', methods=['POST'])
def register_generic_client():
    """Dynamically register a client using OIDC Dynamic Client Registration."""
    data = request.get_json()
    
    registration_endpoint = data.get('registration_endpoint')
    access_token = data.get('access_token')
    app_name = data.get('app_name', 'IAM Protocol Tester')
    redirect_uris = data.get('redirect_uris', [Config.REDIRECT_URI])
    
    if not registration_endpoint:
        return jsonify({
            'success': False,
            'error': 'registration_endpoint is required'
        }), 400
    
    try:
        registrar = GenericOIDCRegistration(registration_endpoint, access_token)
        result = registrar.register_application(app_name, redirect_uris)
        
        # Store registration in session for easy access
        if result['success']:
            session['generic_registration'] = result
        
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/register/status', methods=['GET'])
def get_registration_status():
    """Get current registration status from session."""
    return jsonify({
        'azure': session.get('azure_registration'),
        'okta': session.get('okta_registration'),
        'generic': session.get('generic_registration')
    })


# ============================================================================
# API Routes - Test Execution
# ============================================================================

@app.route('/api/test/oidc/start', methods=['POST'])
def start_oidc_test():
    """Start an OIDC authentication flow test."""
    data = request.get_json()
    
    # Extract configuration
    provider_id = data.get('provider')
    flow_type = data.get('flow_type', 'authorization_code_pkce')
    scopes = data.get('scopes', ['openid', 'profile', 'email'])
    redirect_uri = data.get('redirect_uri', Config.REDIRECT_URI)
    
    # Get provider config and merge with user overrides
    provider_config = ProviderConfig.get_provider_template(provider_id)
    provider_config.update(data.get('config', {}))
    
    # Create test result record
    test_result = TestResult(
        provider=provider_id,
        flow_type=flow_type,
        status='in_progress',
        started_at=datetime.utcnow()
    )
    db.session.add(test_result)
    db.session.commit()
    
    # Create logger
    test_logger = TestLogger(test_result.id, db.session)
    test_logger.set_step('Initialization')
    test_logger.info(f'Starting {flow_type} test with {provider_id}')
    
    try:
        # Initialize OIDC handler
        oidc = OIDCHandler(provider_config, test_logger)
        
        # Build authorization URL
        use_pkce = 'pkce' in flow_type
        
        # Build authorization URL with custom state that includes test_id
        auth_url, flow_state = oidc.build_authorization_url(
            redirect_uri=redirect_uri,
            scopes=scopes,
            use_pkce=use_pkce,
            extra_params={'state': f"{flow_state.get('state', '')}_{test_result.id}"} if oidc.state else None
        )
        
        # Update flow_state with the modified state that includes test_id
        if oidc.state:
            flow_state['state'] = f"{oidc.state}_{test_result.id}"
        
        # Store flow state and test_id in session
        session[f'flow_state_{test_result.id}'] = flow_state
        session[f'provider_config_{test_result.id}'] = provider_config
        session['current_test_id'] = test_result.id  # Store current test ID for callback
        
        test_logger.info('Authorization URL generated', {
            'url': auth_url,
            'test_id': test_result.id
        })
        
        return jsonify({
            'success': True,
            'test_id': test_result.id,
            'authorization_url': auth_url,
            'flow_state': flow_state
        })
        
    except Exception as e:
        test_result.status = 'error'
        test_result.error_message = str(e)
        test_result.completed_at = datetime.utcnow()
        db.session.commit()
        
        test_logger.error(f'Failed to start test: {str(e)}')
        
        return jsonify({
            'success': False,
            'error': str(e),
            'test_id': test_result.id
        }), 500


@app.route('/callback')
def oauth_callback():
    """Handle OAuth/OIDC callback."""
    # Try to get test_id from session first
    test_id = session.get('current_test_id')
    
    # If not in session, try to extract from state parameter
    if not test_id:
        state = request.args.get('state', '')
        if '_' in state:
            # State format: {random_state}_{test_id}
            try:
                test_id = int(state.split('_')[-1])
            except (ValueError, IndexError):
                pass
    
    if not test_id:
        return jsonify({'error': 'Session expired. Please start a new test.'}), 400
    
    test_id = int(test_id)
    test_result = TestResult.query.get_or_404(test_id)
    
    # Get flow state from session
    flow_state = session.get(f'flow_state_{test_id}')
    provider_config = session.get(f'provider_config_{test_id}')
    
    if not flow_state or not provider_config:
        return jsonify({'error': 'Session expired or invalid'}), 400
    
    # Create logger
    test_logger = TestLogger(test_id, db.session)
    test_logger.set_step('Callback Processing')
    
    try:
        # Initialize OIDC handler
        oidc = OIDCHandler(provider_config, test_logger)
        oidc.state = flow_state['state']
        oidc.nonce = flow_state['nonce']
        
        # Parse callback
        callback_url = request.url
        callback_data = oidc.parse_callback_url(callback_url)
        
        # Check for errors
        if callback_data['error']:
            test_result.status = 'error'
            test_result.error_message = f"{callback_data['error']}: {callback_data['error_description']}"
            test_result.completed_at = datetime.utcnow()
            db.session.commit()
            return redirect(f'/results/{test_id}')
        
        # Skip state validation for now - just log it
        test_logger.info('State received', {'state': callback_data['state']})
        
        # Exchange code for tokens
        token_response = oidc.exchange_code_for_tokens(
            code=callback_data['code'],
            redirect_uri=flow_state['redirect_uri'],
            code_verifier=flow_state.get('code_verifier')
        )
        
        # Store tokens
        test_result.id_token = token_response.get('id_token')
        test_result.access_token = token_response.get('access_token')
        test_result.refresh_token = token_response.get('refresh_token')
        
        # Decode and validate tokens
        if test_result.id_token:
            decoded_id = JWTDecoder.decode(test_result.id_token)
            test_result.id_token_claims = json.dumps(decoded_id['payload'])
            
            # Validate ID token
            validator = TokenValidator(
                jwks_uri=provider_config.get('jwks_uri', '').format(**provider_config),
                issuer=decoded_id['payload'].get('iss'),
                audience=provider_config['client_id']
            )
            validation = validator.validate_id_token(test_result.id_token, flow_state['nonce'])
            test_result.token_validation = json.dumps(validation)
        
        if test_result.access_token:
            try:
                decoded_access = JWTDecoder.decode(test_result.access_token)
                test_result.access_token_claims = json.dumps(decoded_access['payload'])
            except:
                # Access token might not be a JWT
                test_logger.warning('Access token is not a JWT')
        
        # Test API access
        if test_result.access_token:
            api_test_result = test_api_access(test_result.access_token, test_logger)
            test_result.api_test_result = json.dumps(api_test_result)
        
        test_result.status = 'success'
        test_result.completed_at = datetime.utcnow()
        db.session.commit()
        
        test_logger.info('Test completed successfully')
        
        return redirect(url_for('results', test_id=test_id))
        
    except Exception as e:
        test_result.status = 'error'
        test_result.error_message = str(e)
        test_result.completed_at = datetime.utcnow()
        db.session.commit()
        
        test_logger.error(f'Callback processing failed: {str(e)}')
        
        return redirect(url_for('results', test_id=test_id))


@app.route('/api/test/oauth/client-credentials', methods=['POST'])
def test_client_credentials():
    """Test OAuth Client Credentials flow."""
    data = request.get_json()
    
    provider_id = data.get('provider')
    scopes = data.get('scopes', [])
    
    # Get provider config and merge with user overrides
    provider_config = ProviderConfig.get_provider_template(provider_id)
    provider_config.update(data.get('config', {}))
    
    # Create test result
    test_result = TestResult(
        provider=provider_id,
        flow_type='client_credentials',
        status='in_progress',
        started_at=datetime.utcnow()
    )
    db.session.add(test_result)
    db.session.commit()
    
    # Create logger
    test_logger = TestLogger(test_result.id, db.session)
    test_logger.set_step('Client Credentials Flow')
    
    try:
        # Initialize OAuth handler
        oauth = OAuthHandler(provider_config, test_logger)
        
        # Execute flow
        token_response = oauth.client_credentials_flow(scopes)
        
        # Store tokens
        test_result.access_token = token_response.get('access_token')
        
        # Decode token
        if test_result.access_token:
            try:
                decoded = JWTDecoder.decode(test_result.access_token)
                test_result.access_token_claims = json.dumps(decoded['payload'])
                
                # Validate token
                validator = TokenValidator(
                    jwks_uri=provider_config.get('jwks_uri', '').format(**provider_config)
                )
                validation = validator.validate_access_token(test_result.access_token)
                test_result.token_validation = json.dumps(validation)
            except:
                test_logger.warning('Access token is not a JWT')
        
        # Test API access
        if test_result.access_token:
            api_test_result = test_api_access(test_result.access_token, test_logger)
            test_result.api_test_result = json.dumps(api_test_result)
        
        test_result.status = 'success'
        test_result.completed_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'test_id': test_result.id,
            'redirect_url': url_for('results', test_id=test_result.id)
        })
        
    except Exception as e:
        test_result.status = 'error'
        test_result.error_message = str(e)
        test_result.completed_at = datetime.utcnow()
        db.session.commit()
        
        test_logger.error(f'Client credentials flow failed: {str(e)}')
        
        return jsonify({
            'success': False,
            'error': str(e),
            'test_id': test_result.id
        }), 500


def test_api_access(access_token: str, test_logger):
    """Test API access with the access token."""
    test_logger.set_step('API Access Test')
    
    # Try accessing different endpoints
    endpoints_to_test = ['/api/public', '/api/profile', '/api/email']
    results = []
    
    for endpoint in endpoints_to_test:
        try:
            # Decode token to get claims
            decoded = JWTDecoder.decode(access_token)
            claims = decoded['payload']
            
            # Check permissions
            permission_check = PermissionEngine.check_permission(endpoint, claims)
            
            results.append({
                'endpoint': endpoint,
                'permission_check': permission_check,
                'tested': True
            })
            
            test_logger.info(f'Tested endpoint {endpoint}', permission_check)
            
        except Exception as e:
            results.append({
                'endpoint': endpoint,
                'error': str(e),
                'tested': False
            })
    
    return {
        'endpoints_tested': results,
        'summary': {
            'total': len(endpoints_to_test),
            'allowed': sum(1 for r in results if r.get('permission_check', {}).get('allowed', False))
        }
    }


# ============================================================================
# API Routes - Token Analysis
# ============================================================================

@app.route('/api/token/decode', methods=['POST'])
def decode_token():
    """Decode a JWT token."""
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Token is required'}), 400
    
    try:
        decoded = JWTDecoder.decode(token)
        analysis = ClaimsAnalyzer.analyze(decoded['payload'])
        
        return jsonify({
            'success': True,
            'decoded': decoded,
            'analysis': analysis
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@app.route('/api/token/validate', methods=['POST'])
def validate_token():
    """Validate a JWT token."""
    data = request.get_json()
    token = data.get('token')
    jwks_uri = data.get('jwks_uri')
    issuer = data.get('issuer')
    audience = data.get('audience')
    
    if not token:
        return jsonify({'error': 'Token is required'}), 400
    
    try:
        validator = TokenValidator(jwks_uri, issuer, audience)
        validation = validator.validate(token, verify_signature=bool(jwks_uri))
        
        return jsonify({
            'success': True,
            'validation': validation
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


# ============================================================================
# API Routes - Test Results
# ============================================================================

@app.route('/api/test/<int:test_id>', methods=['GET'])
def get_test_result(test_id):
    """Get test result by ID."""
    test_result = TestResult.query.get_or_404(test_id)
    result_dict = test_result.to_dict()
    
    # Add logs
    logs = LogEntry.query.filter_by(test_result_id=test_id).order_by(LogEntry.timestamp).all()
    result_dict['logs'] = [log.to_dict() for log in logs]
    
    # Add diagnostic analysis
    if test_result.status == 'error' or test_result.error_message:
        diagnostic = DiagnosticAnalyzer.generate_diagnostic_report(result_dict)
        result_dict['diagnostics'] = diagnostic
    
    return jsonify(result_dict)


@app.route('/api/tests', methods=['GET'])
def list_tests():
    """List all test results."""
    tests = TestResult.query.order_by(TestResult.started_at.desc()).limit(50).all()
    return jsonify([test.to_dict() for test in tests])


# ============================================================================
# Database Initialization
# ============================================================================

@app.cli.command()
def init_db():
    """Initialize the database."""
    db.create_all()
    print('Database initialized successfully!')


if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Run application
    app.run(
        host=Config.APP_HOST,
        port=Config.APP_PORT,
        debug=Config.DEBUG
    )

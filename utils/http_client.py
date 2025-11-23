"""
HTTP client wrapper with comprehensive logging and error handling.
"""

import requests
import json
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class HTTPClient:
    """HTTP client with built-in logging and error handling."""
    
    def __init__(self, log_callback=None):
        """
        Initialize HTTP client.
        
        Args:
            log_callback: Optional callback function for logging HTTP requests/responses
        """
        self.session = requests.Session()
        self.log_callback = log_callback
    
    def _log_request(self, method, url, headers=None, data=None, params=None):
        """Log HTTP request details."""
        log_data = {
            'method': method,
            'url': url,
            'headers': dict(headers) if headers else {},
            'params': params,
        }
        
        if data:
            # Try to parse as JSON for better logging
            try:
                if isinstance(data, str):
                    log_data['body'] = json.loads(data)
                elif isinstance(data, dict):
                    log_data['body'] = data
                else:
                    log_data['body'] = str(data)
            except:
                log_data['body'] = str(data)
        
        logger.debug(f"HTTP Request: {method} {url}")
        logger.debug(f"Request details: {json.dumps(log_data, indent=2)}")
        
        if self.log_callback:
            self.log_callback('request', log_data)
        
        return log_data
    
    def _log_response(self, response, request_log_data):
        """Log HTTP response details."""
        log_data = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'url': response.url,
        }
        
        # Try to parse response body
        try:
            log_data['body'] = response.json()
        except:
            log_data['body'] = response.text
        
        logger.debug(f"HTTP Response: {response.status_code}")
        logger.debug(f"Response details: {json.dumps(log_data, indent=2)}")
        
        if self.log_callback:
            self.log_callback('response', {
                'request': request_log_data,
                'response': log_data
            })
        
        return log_data
    
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        timeout: int = 30,
        allow_redirects: bool = True,
    ) -> requests.Response:
        """
        Make an HTTP request with logging.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            headers: Request headers
            data: Request body (form data or string)
            json_data: Request body as JSON
            params: Query parameters
            timeout: Request timeout in seconds
            allow_redirects: Whether to follow redirects
            
        Returns:
            Response object
            
        Raises:
            requests.RequestException: On request failure
        """
        # Log request
        request_log = self._log_request(method, url, headers, data or json_data, params)
        
        try:
            # Make request
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                json=json_data,
                params=params,
                timeout=timeout,
                allow_redirects=allow_redirects,
            )
            
            # Log response
            self._log_response(response, request_log)
            
            # Raise for error status codes
            response.raise_for_status()
            
            return response
            
        except requests.RequestException as e:
            logger.error(f"HTTP request failed: {str(e)}")
            if self.log_callback:
                self.log_callback('error', {
                    'request': request_log,
                    'error': str(e)
                })
            raise
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """Make a GET request."""
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """Make a POST request."""
        return self.request('POST', url, **kwargs)
    
    def put(self, url: str, **kwargs) -> requests.Response:
        """Make a PUT request."""
        return self.request('PUT', url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        """Make a DELETE request."""
        return self.request('DELETE', url, **kwargs)
    
    def close(self):
        """Close the session."""
        self.session.close()

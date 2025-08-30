"""
Authentication utilities for Flask backend
"""
from functools import wraps
from flask import request, jsonify
from utils.db import get_supabase_client
import jwt
from jwt import PyJWKClient
import os
import time

def require_auth(f):
    """Decorator to require authentication for API endpoints

    Verifies JWTs issued by Supabase. Supports:
    - HS256 (shared secret) via SUPABASE_JWT_SECRET
    - RS256 (public key) via Supabase JWKS if configured
    Also enforces issuer/audience and standard time claims with a small leeway.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Short-circuit CORS preflight with explicit CORS headers
        if request.method == 'OPTIONS':
            from flask import make_response
            origin = request.headers.get('Origin', '*')
            resp = make_response('', 204)
            # Mirror origin to support credentials
            resp.headers['Access-Control-Allow-Origin'] = origin
            resp.headers['Vary'] = 'Origin'
            resp.headers['Access-Control-Allow-Credentials'] = 'true'
            resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            req_headers = request.headers.get('Access-Control-Request-Headers', 'Authorization, Content-Type, X-Requested-With, Accept, Origin')
            resp.headers['Access-Control-Allow-Headers'] = req_headers
            resp.headers['Access-Control-Max-Age'] = '86400'
            return resp

        # Get the authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'No authorization header provided'}), 401

        # Extract the token
        try:
            token = auth_header.split(' ')[1]  # Bearer <token>
        except IndexError:
            return jsonify({'error': 'Invalid authorization header format'}), 401

        # Verify the token
        try:
            # Unverified header to determine alg and kid
            unverified_header = jwt.get_unverified_header(token)
            alg = unverified_header.get('alg')
            if not alg:
                return jsonify({'error': 'Invalid token header'}), 401

            # Expected issuer and audience
            supabase_url = os.environ.get('SUPABASE_URL', '').rstrip('/')
            expected_iss = os.environ.get('SUPABASE_JWT_ISS') or (supabase_url + '/auth/v1' if supabase_url else None)
            expected_aud = os.environ.get('SUPABASE_JWT_AUD', 'authenticated')

            # allow small clock skew
            leeway_seconds = int(os.environ.get('JWT_LEEWAY_SECONDS', '60'))

            decoded_token = None

            if alg.startswith('RS') or os.environ.get('SUPABASE_JWKS_URL'):
                # RS256 path using JWKS
                jwks_url = os.environ.get('SUPABASE_JWKS_URL') or (supabase_url + '/auth/v1/.well-known/jwks.json' if supabase_url else None)
                if not jwks_url:
                    return jsonify({'error': 'Server misconfiguration'}), 500
                jwk_client = PyJWKClient(jwks_url)
                signing_key = jwk_client.get_signing_key_from_jwt(token)
                decoded_token = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=[alg],
                    audience=expected_aud,
                    issuer=expected_iss,
                    options={'require': ['exp', 'iat', 'sub']},
                    leeway=leeway_seconds,
                )
            else:
                # HS256 path using shared secret
                hs_secret = os.environ.get('SUPABASE_JWT_SECRET')
                if not hs_secret:
                    # If secret not provided, fail closed rather than skipping verification
                    return jsonify({'error': 'Server misconfiguration'}), 500
                decoded_token = jwt.decode(
                    token,
                    hs_secret,
                    algorithms=[alg],
                    audience=expected_aud,
                    issuer=expected_iss,
                    options={'require': ['exp', 'iat', 'sub']},
                    leeway=leeway_seconds,
                )

            user_id = decoded_token.get('sub')
            if not user_id:
                return jsonify({'error': 'Invalid token'}), 401

            # Set request context claims
            request.user_id = user_id
            request.user_email = decoded_token.get('email')
            request.token_claims = decoded_token

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception:
            # Avoid leaking verification details
            return jsonify({'error': 'Authentication failed'}), 401

        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Decorator to require admin role for API endpoints"""
    @wraps(f)
    @require_auth
    def decorated_function(*args, **kwargs):
        # Check if user is an admin
        try:
            supabase = get_supabase_client()
            
            result = supabase.table('admins').select('role').eq('auth_id', request.user_id).single().execute()
            
            if not result.data:
                return jsonify({'error': 'Access denied: Admin role required'}), 403
            
            # Store admin role in request context
            request.user_role = result.data['role']
            
        except Exception as e:
            print(f"Admin check error: {e}")
            return jsonify({'error': 'Access denied'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def require_superadmin(f):
    """Deprecated: Superadmin merged into admin. Use require_admin semantics."""
    @wraps(f)
    @require_admin
    def decorated_function(*args, **kwargs):
        # Single admin role now has full privileges
        return f(*args, **kwargs)
    return decorated_function
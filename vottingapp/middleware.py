
from django.conf import settings

def get_frontend_url():
    """
    Returns the appropriate frontend URL based on environment
    """
    # Check if we're in production (using the deployment settings)
    if hasattr(settings, 'FRONTEND_URL'):
        return settings.FRONTEND_URL
    
    # Default to localhost for development
    return 'http://localhost:3000'
class CorsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.method == "OPTIONS":
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken'
            response['Access-Control-Allow-Methods'] = 'POST, PUT, PATCH, GET, DELETE, OPTIONS'
        else:
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
        return response
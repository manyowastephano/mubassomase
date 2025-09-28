import os
import json
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from django.conf import settings

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def get_gmail_service():
    """Get Gmail service instance with proper redirect URI"""
    creds = None
    
    # Get redirect URI from settings
    redirect_uri = getattr(settings, 'GOOGLE_OAUTH2_REDIRECT_URI', 'http://localhost:8000/oauth2callback/')
    
    # Check environment variables first
    credentials_json = os.environ.get('GMAIL_CREDENTIALS')
    
    if credentials_json:
        # Use environment variables
        credentials_info = json.loads(credentials_json)
        token_json = os.environ.get('GMAIL_TOKEN')
        
        if token_json:
            creds = Credentials.from_authorized_user_info(json.loads(token_json), SCOPES)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_config(
                    credentials_info, 
                    SCOPES,
                    redirect_uri=redirect_uri
                )
                creds = flow.run_local_server(port=0, open_browser=False)
                
                # Update token in environment (for production, you'd need to store this permanently)
                os.environ['GMAIL_TOKEN'] = creds.to_json()
    else:
        # File-based approach
        token_path = os.path.join(settings.BASE_DIR, 'token.json')
        credentials_path = os.path.join(settings.BASE_DIR, 'credentials.json')
        
        if os.path.exists(token_path):
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_path, 
                    SCOPES,
                    redirect_uri=redirect_uri
                )
                creds = flow.run_local_server(port=0)
            
            # Save credentials
            with open(token_path, 'w') as token:
                token.write(creds.to_json())
    
    return build('gmail', 'v1', credentials=creds)
import os
import logging
from mailjet_rest import Client
from django.conf import settings

logger = logging.getLogger(__name__)

def send_verification_email(user_email, username, uid, token):
    """Send verification email using Mailjet API"""
    try:
        api_key = os.environ.get('MAILJET_API_KEY')
        api_secret = os.environ.get('MAILJET_API_SECRET')
        
        if not api_key or not api_secret:
            logger.error("Mailjet API credentials not configured")
            return False
        
        mailjet = Client(auth=(api_key, api_secret), version='v3.1')
        
        frontend_url = getattr(settings, 'FRONTEND_URL', 'https://mubas-somase.onrender.com')
        from_email = os.environ.get('DEFAULT_FROM_EMAIL', 'mubassomase@gmail.com')
        
        # HTML content for the email
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Email Verification</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background-color: #f9f9f9;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    text-align: center;
                    padding: 20px 0;
                    background-color: #1e4a76;
                    color: white;
                    border-radius: 8px 8px 0 0;
                }}
                .content {{
                    padding: 20px;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 24px;
                    background-color: #1e4a76;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    margin: 20px 0;
                    font-weight: bold;
                }}
                .footer {{
                    text-align: center;
                    padding: 20px;
                    font-size: 12px;
                    color: #666;
                }}
                .verification-link {{
                    word-break: break-all;
                    color: #1e4a76;
                    font-weight: bold;
                    background-color: #f0f0f0;
                    padding: 10px;
                    border-radius: 4px;
                    margin: 10px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>MUBAS SOMASE</h1>
                    <h2>Email Verification</h2>
                </div>
                <div class="content">
                    <h2>Hello {username},</h2>
                    <p>Thank you for registering as a MUBAS SOMASE member. To complete your registration, please verify your email address by clicking the button below:</p>
                    
                    <center>
                        <a href="{frontend_url}/activate/{uid}/{token}" class="button">
                            Verify Email Address
                        </a>
                    </center>
                    
                    <p>Or copy and paste the following link into your browser:</p>
                    <p class="verification-link">{frontend_url}/activate/{uid}/{token}</p>
                    
                    <p>If you didn't request this registration, please ignore this email.</p>
                    
                    <p>Best regards,<br>The MUBAS SOMASE Team</p>
                </div>
                <div class="footer">
                    <p>This is an automated message. Please do not reply to this email.</p>
                    <p>&copy; 2024 MUBAS SOMASE Voting System. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version as fallback
        text_content = f"""
        Hello {username},
        
        Thank you for registering for the MUBAS SOMASE Voting System.
        
        Please verify your email address by clicking the following link:
        {frontend_url}/activate/{uid}/{token}
        
        If you didn't request this registration, please ignore this email.
        
        Best regards,
        The MUBAS SOMASE Team
        """
        
        data = {
            'Messages': [
                {
                    "From": {
                        "Email": from_email,
                        "Name": "MUBAS SOMASE"
                    },
                    "To": [
                        {
                            "Email": user_email,
                            "Name": username
                        }
                    ],
                    "Subject": "Verify Your MUBAS SOMASE Account",
                    "HTMLPart": html_content,
                    "TextPart": text_content
                }
            ]
        }
        
        logger.info(f"Sending verification email to {user_email} via Mailjet API")
        result = mailjet.send.create(data=data)
        
        if result.status_code == 200:
            logger.info(f"Verification email sent successfully to {user_email}")
            return True
        else:
            logger.error(f"Mailjet API error: {result.status_code} - {result.text}")
            return False
            
    except Exception as e:
        logger.error(f"Error sending email via Mailjet API: {str(e)}", exc_info=True)
        return False

def send_election_notification(emails, subject, message, election_title=""):
    """Send bulk election notifications using Mailjet API"""
    try:
        api_key = os.environ.get('MAILJET_API_KEY')
        api_secret = os.environ.get('MAILJET_API_SECRET')
        
        if not api_key or not api_secret:
            logger.error("Mailjet API credentials not configured")
            return False
        
        mailjet = Client(auth=(api_key, api_secret), version='v3.1')
        from_email = os.environ.get('DEFAULT_FROM_EMAIL', 'mubassomase@gmail.com')
        
        if not emails:
            logger.warning("No emails provided for election notification")
            return True
            
        # Send in batches of 50 (Mailjet limit per API call)
        batch_size = 50
        successful_sends = 0
        
        for i in range(0, len(emails), batch_size):
            batch_emails = emails[i:i + batch_size]
            
            # Create recipients list for this batch
            recipients = [{"Email": email} for email in batch_emails]
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background-color: #1e4a76; color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 20px; }}
                    .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #666; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>MUBAS SOMASE Elections</h1>
                        <h2>{election_title}</h2>
                    </div>
                    <div class="content">
                        <p>{message.replace(chr(10), '<br>')}</p>
                        <br>
                        <p>Best regards,<br>MUBAS SOMASE Election Committee</p>
                    </div>
                    <div class="footer">
                        <p>This is an automated notification. Please do not reply to this email.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            data = {
                'Messages': [
                    {
                        "From": {
                            "Email": from_email,
                            "Name": "MUBAS SOMASE Elections"
                        },
                        "To": recipients,
                        "Subject": subject,
                        "HTMLPart": html_content,
                        "TextPart": f"{election_title}\n\n{message}\n\nBest regards,\nMUBAS SOMASE Election Committee"
                    }
                ]
            }
            
            result = mailjet.send.create(data=data)
            if result.status_code == 200:
                successful_sends += len(batch_emails)
                logger.info(f"Successfully sent batch of {len(batch_emails)} emails")
            else:
                logger.error(f"Failed to send batch: {result.status_code} - {result.text}")
        
        logger.info(f"Election notification sent to {successful_sends} out of {len(emails)} recipients")
        return successful_sends > 0  # Return True if at least some emails were sent
        
    except Exception as e:
        logger.error(f"Error sending election notification: {str(e)}", exc_info=True)
        return False
from django.core.management.base import BaseCommand
from django.core.mail import send_mass_mail
from django.conf import settings
from vottingapp.models import CustomUser, ElectionSettings
import re
import logging

logger = logging.getLogger(__name__)

def is_email_eligible(email, start_year, end_year, additional_emails):
    """
    Check if an email is eligible to vote based on year range patterns
    and additional allowed emails
    """
    # Check if email is in additional emails list
    if additional_emails:
        additional_emails_list = [e.strip() for e in additional_emails.split('\n') if e.strip()]
        if email in additional_emails_list:
            return True
    
    # Check if email matches the pattern mseYY-username@mubas.ac.mw
    pattern = r'^mse(\d{2})-.*@mubas\.ac\.mw$'
    match = re.match(pattern, email)
    
    if not match:
        return False
    
    # Extract the 2-digit year from email
    email_year_short = int(match.group(1))
    email_year_full = 2000 + email_year_short
    
    # Check if the year is within the allowed range
    return start_year <= email_year_full <= end_year

class Command(BaseCommand):
    help = 'Send election start or end emails to all eligible users'

    def add_arguments(self, parser):
        parser.add_argument(
            '--type',
            type=str,
            choices=['start', 'end'],
            required=True,
            help='Type of email to send: start or end'
        )

    def handle(self, *args, **options):
        email_type = options['type']
        
        try:
            # Get election settings
            try:
                election_settings = ElectionSettings.objects.get(id=1)
            except ElectionSettings.DoesNotExist:
                self.stderr.write('Election settings not configured')
                return
            
            # Get all user emails
            user_emails = CustomUser.objects.filter(is_active=True).values_list('email', flat=True)
            user_emails = [email for email in user_emails if email]
            
            if not user_emails:
                self.stdout.write('No users found to send emails')
                return
            
            # Get additional emails from election settings
            additional_emails = election_settings.additional_emails
            
            # Filter emails to only include eligible voters
            eligible_emails = [
                email for email in user_emails 
                if is_email_eligible(email, election_settings.start_year, election_settings.end_year, additional_emails)
            ]
            
            # Also include additional emails that might not be in user accounts
            additional_emails_list = [e.strip() for e in additional_emails.split('\n') if e.strip()]
            for email in additional_emails_list:
                if email not in eligible_emails:
                    eligible_emails.append(email)
            
            if not eligible_emails:
                self.stdout.write('No eligible voters found to send emails')
                return
            
            if email_type == 'start':
                subject = 'MUBAS SOMASE Elections Has Started'
                message = f"""
Hello everyone,

The MUBAS SOMASE ELECTIONS has now started.

Please log in to the system to cast your vote: https://mubas-somase.onrender.com/login

The election will end on {election_settings.end_date.strftime("%Y-%m-%d at %H:%M") if election_settings.end_date else "a specified date"}.

Thank you as you will participating in the voting process.

Best regards,
MUBAS SOMASE Election Committee
"""
            else:  # end
                subject = 'MUBAS SOMASE Elections Has Ended'
                message = f"""
Hello everyone,

The MUBAS SOMASE ELECTIONS has officially ended.

Thank you to everyone who participated in the voting process. The results will be announced soon.

If you haven't voted yet, you can no longer do so as the election period has ended.

Best regards,
MUBAS SOMASE Election Committee
"""
            
            # Prepare emails for mass sending
            emails = [(subject, message, settings.DEFAULT_FROM_EMAIL, [email]) for email in eligible_emails]
            
            # Send emails
            try:
                send_mass_mail(emails, fail_silently=False)
                self.stdout.write(f"Successfully sent {email_type} emails to {len(eligible_emails)} eligible recipients")
            except Exception as e:
                self.stderr.write(f"Error sending emails: {str(e)}")
                return
                
        except Exception as e:
            self.stderr.write(f"Error in send_election_emails command: {str(e)}")
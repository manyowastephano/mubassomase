from django.core.management.base import BaseCommand
from django.utils import timezone
from vottingapp.models import ElectionSettings, AuditLog, CustomUser
from django.conf import settings
from django.core.mail import send_mass_mail
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Check if election should start or end based on scheduled time'
    
    def handle(self, *args, **options):
        try:
            # Get election settings
            try:
                election_settings = ElectionSettings.objects.get(id=1)
            except ElectionSettings.DoesNotExist:
                self.stdout.write(self.style.WARNING('No election settings found'))
                return
            
            # Get current time
            now = timezone.now()
            
            # Convert dates to timezone-aware datetime if they're naive
            start_date = election_settings.start_date
            if start_date and timezone.is_naive(start_date):
                start_date = timezone.make_aware(start_date)
                
            end_date = election_settings.end_date
            if end_date and timezone.is_naive(end_date):
                end_date = timezone.make_aware(end_date)
            
            # Check if election should start
            if start_date and start_date <= now and not election_settings.is_active:
                # Start the election
                election_settings.is_active = True
                election_settings.save()
                
                # Send election start emails
                self.send_election_started_emails(election_settings)
                
                # Create audit log
                AuditLog.objects.create(
                    user=None,  # System action
                    action='election_started',
                    details="Election started automatically"
                )
                
                self.stdout.write(
                    self.style.SUCCESS('Election started automatically and emails sent')
                )
            
            # Check if election should end
            if election_settings.is_active and end_date and end_date <= now:
                # End the election
                election_settings.is_active = False
                election_settings.save()
                
                # Send election end emails
                self.send_election_ended_emails(election_settings)
                
                # Create audit log
                AuditLog.objects.create(
                    user=None,  # System action
                    action='election_ended',
                    details="Election ended automatically"
                )
                
                self.stdout.write(
                    self.style.SUCCESS('Election ended automatically and emails sent')
                )
            
            # If election is active but end time hasn't passed
            elif election_settings.is_active and end_date and end_date > now:
                # Calculate time until election ends
                time_until_end = end_date - now
                days = time_until_end.days
                hours, remainder = divmod(time_until_end.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                
                self.stdout.write(
                    self.style.SUCCESS(f'Election active. Time remaining: {days}d {hours}h {minutes}m')
                )
            else:
                self.stdout.write(
                    self.style.WARNING('Election is not active and no start time scheduled')
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error checking election status: {str(e)}')
            )
    
    def send_election_started_emails(self, election_settings):
        """Send election started notification emails to all users"""
        # Get all user emails
        user_emails = CustomUser.objects.filter(is_active=True).values_list('email', flat=True)
        user_emails = [email for email in user_emails if email]
        
        if not user_emails:
            logger.warning("No users found to send election start emails")
            return
        
        # Get additional emails from election settings
        additional_emails = election_settings.get_additional_emails_list()
        
        # Combine all emails
        all_emails = list(user_emails) + additional_emails
        
        # Email content
        subject = 'MUBAS SOMASE Elections Has Started'
        
        # Use the frontend URL from settings or default to localhost
        frontend_url = getattr(settings, 'FRONTEND_URL', 'https://mubas-somase.onrender.com')
        
        message = f"""
Hello everyone,

The MUBAS SOMASE ELECTIONS has now started.

Please log in to the system to cast your vote: {frontend_url}/login

The election will end on {election_settings.end_date.strftime("%Y-%m-%d at %H:%M") if election_settings.end_date else "a specified date"}.

Thank you for participating in the democratic process.

Best regards,
MUBAS SOMASE Election Committee
"""
        
        # Prepare emails for mass sending
        emails = [(subject, message, settings.DEFAULT_FROM_EMAIL, [email]) for email in all_emails]
        
        # Send emails
        send_mass_mail(emails, fail_silently=False)
        
        logger.info(f"Sent election start emails to {len(all_emails)} recipients")
    
    def send_election_ended_emails(self, election_settings):
        """Send election ended notification emails to all users"""
        # Get all user emails
        user_emails = CustomUser.objects.filter(is_active=True).values_list('email', flat=True)
        user_emails = [email for email in user_emails if email]
        
        if not user_emails:
            logger.warning("No users found to send election end emails")
            return
        
        # Get additional emails from election settings
        additional_emails = election_settings.get_additional_emails_list()
        
        # Combine all emails
        all_emails = list(user_emails) + additional_emails
        
        # Email content
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
        emails = [(subject, message, settings.DEFAULT_FROM_EMAIL, [email]) for email in all_emails]
        
        # Send emails
        send_mass_mail(emails, fail_silently=False)
        
        logger.info(f"Sent election end emails to {len(all_emails)} recipients")
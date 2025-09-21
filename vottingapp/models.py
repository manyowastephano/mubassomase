'''
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.conf import settings

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    profile_photo = models.ImageField(
        upload_to='profile_photos/',
        null=True,
        blank=True,
        validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png'])]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    has_voted = models.BooleanField(default=False)
    
    # Add email verification fields
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=100, blank=True, null=True)
    token_created_at = models.DateTimeField(blank=True, null=True)
    
    ROLE_CHOICES = [
        ('voter', 'Voter'),
        ('moderator', 'Moderator'),
        ('president', 'President'),
        ('vice_president', 'Vice President'),
    ]
    role = models.CharField(max_length=30, choices=ROLE_CHOICES, default='voter')
    
    def __str__(self):
        return self.username

    class Meta:
        db_table = 'auth_user'
class Candidate(models.Model):
    POSITION_CHOICES = [
        ('president', 'President'),
        ('vice-president', 'Vice President'),
        ('general-secretary', 'General Secretary'),
        ('organising-secretary', 'Organising Secretary'),
        ('publicity-secretary', 'Publicity Secretary'),
        ('treasurer', 'Treasurer'),
        ('entertainment-director', 'Entertainment Director'),
        ('sports-director', 'Sports Director'),
        ('society-member', 'Society Member'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='candidates')
    full_name = models.CharField(max_length=255)
    position = models.CharField(max_length=50, choices=POSITION_CHOICES)
    phone = models.CharField(max_length=20)
    slogan = models.CharField(max_length=255)
    manifesto = models.TextField()
    profile_photo = models.ImageField(upload_to='candidate_photos/')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    votes = models.PositiveIntegerField(default=0)
    
    class Meta:
        unique_together = ['user', 'position']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.full_name} - {self.get_position_display()}"
    
    def get_position_display(self):
        return dict(self.POSITION_CHOICES).get(self.position, self.position)

class Vote(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='votes')
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE, related_name='candidate_votes')
    position = models.CharField(max_length=50, choices=Candidate.POSITION_CHOICES)
    voted_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'position']  # Ensure one vote per position per user
    
    


class Election(models.Model):
    name = models.CharField(max_length=255)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
# Update the ElectionSettings model
class ElectionSettings(models.Model):
    start_year = models.IntegerField(default=2022)
    end_year = models.IntegerField(default=2025)
    election_title = models.CharField(max_length=255, default="SOMASE Executive Election")
    start_date = models.DateTimeField(null=True, blank=True)
    end_date = models.DateTimeField(null=True, blank=True)
    additional_emails = models.TextField(blank=True, help_text="Additional eligible emails (one per line)")
    is_active = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    duration = models.PositiveIntegerField(default=60, help_text="Election duration in minutes")
    class Meta:
        verbose_name_plural = "Election Settings"
    
    def __str__(self):
        return f"Election Settings ({self.start_year}-{self.end_year})"
    
    def get_additional_emails_list(self):
        """Return additional emails as a list"""
        if self.additional_emails:
            return [email.strip() for email in self.additional_emails.split('\n') if email.strip()]
        return []
    
    def set_additional_emails_from_list(self, email_list):
        """Set additional emails from a list"""
        self.additional_emails = '\n'.join([email.strip() for email in email_list if email.strip()])
        
# Add to models.py
class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('candidate_approval', 'Candidate Approval'),
        ('candidate_rejection', 'Candidate Rejection'),
        ('election_start', 'Election Started'),
        ('election_end', 'Election Ended'),
        ('moderator_added', 'Moderator Added'),
        ('moderator_removed', 'Moderator Removed'),
        ('vice_president_set', 'Vice President Set'),
        ('presidency_transferred', 'Presidency Transferred'),
        ('settings_updated', 'Settings Updated'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    details = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    viewed_by = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='viewed_audit_logs', blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.get_action_display()} - {self.timestamp}"
class UserAuditLogDeletion(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    audit_log = models.ForeignKey(AuditLog, on_delete=models.CASCADE)
    deleted_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'audit_log']
    
    def __str__(self):
        return f"{self.user.username} deleted audit log #{self.audit_log.id}"

'''

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.conf import settings
from cloudinary.models import CloudinaryField

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    profile_photo = CloudinaryField(
        'profile_photo',
        folder='voting_app/profiles/',
        null=True,
        blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    has_voted = models.BooleanField(default=False)
    
    # Add email verification fields
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=100, blank=True, null=True)
    token_created_at = models.DateTimeField(blank=True, null=True)
    
    ROLE_CHOICES = [
        ('voter', 'Voter'),
        ('moderator', 'Moderator'),
        ('president', 'President'),
        ('vice_president', 'Vice President'),
    ]
    role = models.CharField(max_length=30, choices=ROLE_CHOICES, default='voter')
    
    def __str__(self):
        return self.username

    class Meta:
        pass
class Candidate(models.Model):
    POSITION_CHOICES = [
        ('president', 'President'),
        ('vice-president', 'Vice President'),
        ('general-secretary', 'General Secretary'),
        ('organising-secretary', 'Organising Secretary'),
        ('publicity-secretary', 'Publicity Secretary'),
        ('treasurer', 'Treasurer'),
        ('entertainment-director', 'Entertainment Director'),
        ('sports-director', 'Sports Director'),
        ('society-member', 'Society Member'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='candidates')
    full_name = models.CharField(max_length=255)
    position = models.CharField(max_length=50, choices=POSITION_CHOICES)
    phone = models.CharField(max_length=20)
    slogan = models.CharField(max_length=255)
    manifesto = models.TextField()
    profile_photo = CloudinaryField(
        'candidate_photo',
        folder='voting_app/candidates/'
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    votes = models.PositiveIntegerField(default=0)
    
    class Meta:
        unique_together = ['user', 'position']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.full_name} - {self.get_position_display()}"
    
    def get_position_display(self):
        return dict(self.POSITION_CHOICES).get(self.position, self.position)

class Vote(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='votes')
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE, related_name='candidate_votes')
    position = models.CharField(max_length=50, choices=Candidate.POSITION_CHOICES)
    voted_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'position']  # Ensure one vote per position per user
    
    


class Election(models.Model):
    name = models.CharField(max_length=255)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    start_emails_sent = models.BooleanField(default=False)
    end_emails_sent = models.BooleanField(default=False)
    
    def __str__(self):
        return self.name
# Update the ElectionSettings model
class ElectionSettings(models.Model):
    start_year = models.IntegerField(default=2022)
    end_year = models.IntegerField(default=2025)
    election_title = models.CharField(max_length=255, default="SOMASE Executive Election")
    start_date = models.DateTimeField(null=True, blank=True)
    end_date = models.DateTimeField(null=True, blank=True)
    additional_emails = models.TextField(blank=True, help_text="Additional eligible emails (one per line)")
    is_active = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    duration = models.PositiveIntegerField(default=60, help_text="Election duration in minutes")
    class Meta:
        verbose_name_plural = "Election Settings"
    
    def __str__(self):
        return f"Election Settings ({self.start_year}-{self.end_year})"
    
    def get_additional_emails_list(self):
        """Return additional emails as a list"""
        if self.additional_emails:
            return [email.strip() for email in self.additional_emails.split('\n') if email.strip()]
        return []
    
    def set_additional_emails_from_list(self, email_list):
        """Set additional emails from a list"""
        self.additional_emails = '\n'.join([email.strip() for email in email_list if email.strip()])
        
# Add to models.py
class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('candidate_approval', 'Candidate Approval'),
        ('candidate_rejection', 'Candidate Rejection'),
        ('election_start', 'Election Started'),
        ('election_end', 'Election Ended'),
        ('moderator_added', 'Moderator Added'),
        ('moderator_removed', 'Moderator Removed'),
        ('vice_president_set', 'Vice President Set'),
        ('presidency_transferred', 'Presidency Transferred'),
        ('settings_updated', 'Settings Updated'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    details = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    viewed_by = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='viewed_audit_logs', blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.get_action_display()} - {self.timestamp}"
class UserAuditLogDeletion(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    audit_log = models.ForeignKey(AuditLog, on_delete=models.CASCADE)
    deleted_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'audit_log']
    
    def __str__(self):
        return f"{self.user.username} deleted audit log #{self.audit_log.id}"
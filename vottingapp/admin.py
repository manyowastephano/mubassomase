from django.contrib import admin
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Candidate, Vote, Election, ElectionSettings, AuditLog, UserAuditLogDeletion

# --- CustomUser Admin ---
@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('username', 'email', 'role', 'is_staff', 'is_active', 'has_voted', 'is_email_verified')
    list_filter = ('role', 'is_staff', 'is_active', 'has_voted')
    search_fields = ('username', 'email')
    ordering = ('email',)
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password', 'profile_photo')}),
        ('Permissions', {'fields': ('role', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
        ('Voting', {'fields': ('has_voted', 'is_email_verified', 'email_verification_token', 'token_created_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role', 'is_staff', 'is_active')}
        ),
    )

# --- Candidate Admin ---
@admin.register(Candidate)
class CandidateAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'position', 'status', 'votes', 'user')
    list_filter = ('position', 'status')
    search_fields = ('full_name', 'user__username', 'user__email')
    ordering = ('-created_at',)

# --- Vote Admin ---
@admin.register(Vote)
class VoteAdmin(admin.ModelAdmin):
    list_display = ('user', 'candidate', 'position', 'voted_at')
    list_filter = ('position',)
    search_fields = ('user__username', 'candidate__full_name')

# --- Election Admin ---
@admin.register(Election)
class ElectionAdmin(admin.ModelAdmin):
    list_display = ('name', 'start_date', 'end_date', 'is_active')
    list_filter = ('is_active',)
    search_fields = ('name',)

# --- ElectionSettings Admin ---
@admin.register(ElectionSettings)
class ElectionSettingsAdmin(admin.ModelAdmin):
    list_display = ('election_title', 'start_year', 'end_year', 'is_active', 'duration')
    search_fields = ('election_title',)

# --- AuditLog Admin ---
@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('action', 'user', 'timestamp')
    list_filter = ('action',)
    search_fields = ('user__username', 'details')

# --- UserAuditLogDeletion Admin ---
@admin.register(UserAuditLogDeletion)
class UserAuditLogDeletionAdmin(admin.ModelAdmin):
    list_display = ('user', 'audit_log', 'deleted_at')
    search_fields = ('user__username',)

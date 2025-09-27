

from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, logout
from .models import CustomUser, Candidate, Vote, ElectionSettings, AuditLog,UserAuditLogDeletion
from .serializers import UserRegistrationSerializer, UserLoginSerializer, CandidateRegistrationSerializer, CandidateSerializer, ElectionSettingsSerializer, AuditLogSerializer
import json
from django.contrib.auth import authenticate
from django.utils import timezone
import re
import smtplib

from django.shortcuts import redirect
from django.core.mail import send_mail
from django.conf import settings
from django.db.models import Q
from django.db import transaction
from django.shortcuts import get_object_or_404
import logging
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.http import HttpResponse

from django.utils import timezone
from datetime import datetime, timedelta
import pytz
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from .token_generator import account_activation_token
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse
from django.middleware.csrf import get_token
import cloudinary
import cloudinary.uploader
from django.contrib.auth.decorators import login_required
from django.conf import settings

def get_frontend_url():
    """
    Returns the appropriate frontend URL based on environment
    """
    # Use FRONTEND_URL if explicitly set
    if hasattr(settings, 'FRONTEND_URL') and settings.FRONTEND_URL:
        return settings.FRONTEND_URL
    
    # Determine based on DEBUG mode
    if getattr(settings, 'DEBUG', False):
        return 'http://localhost:3000'  # Development
    else:
        # Production - use the main domain
        return 'https://mubas-somase.onrender.com'


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def get_csrf_token(request):
    """
    Get CSRF token directly in response
    """
    # Force CSRF token generation
    csrf_token = get_token(request)
    
    response = Response({
        'csrfToken': csrf_token,
        'message': 'CSRF token generated successfully'
    }, status=status.HTTP_200_OK)
    
    # Set it as a cookie with proper settings for cross-domain
    frontend_url = get_frontend_url()
    domain = None
    
    # Extract domain for cookie setting (remove protocol and path)
    if frontend_url.startswith('https://'):
        domain = frontend_url[8:]  # Remove 'https://'
    elif frontend_url.startswith('http://'):
        domain = frontend_url[7:]  # Remove 'http://'
    
    # Remove port and path if present
    if domain and ':' in domain:
        domain = domain.split(':')[0]
    if domain and '/' in domain:
        domain = domain.split('/')[0]
    
    response.set_cookie(
        'csrftoken',
        csrf_token,
        max_age=3600 * 24 * 7,  # 7 days
        secure=True if 'https' in frontend_url else False,
        samesite='None' if 'https' in frontend_url else 'Lax',
        httponly=False,  # Allow JavaScript to read it
        domain=domain if domain and domain not in ['localhost', '127.0.0.1'] else None
    )
    
    response['Access-Control-Allow-Origin'] = frontend_url
    response['Access-Control-Allow-Credentials'] = 'true'
    response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken'
    response['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
    return response
def create_audit_log(user, action, details):
    audit_log = AuditLog.objects.create(
        user=user,
        action=action,
        details=details
    )
    return audit_log


# Update the get_audit_logs function
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_audit_logs(request):
    """Get all audit logs with pagination, excluding those deleted by the user and created before user joined"""
    try:
        # Get page number from query params, default to 1
        page = int(request.GET.get('page', 1))
        page_size = 20  # Items per page
        
        # Calculate offset
        offset = (page - 1) * page_size
        
        # Get logs with pagination, excluding those deleted by the user and created before user joined
        logs = AuditLog.objects.exclude(
            userauditlogdeletion__user=request.user
        ).filter(
            timestamp__gte=request.user.date_joined  # Only show logs created after user joined
        ).order_by('-timestamp')[offset:offset + page_size]
        
        # Mark logs as viewed by this user
        for log in logs:
            if request.user not in log.viewed_by.all():
                log.viewed_by.add(request.user)
        
        serializer = AuditLogSerializer(logs, many=True)
        
        # Get total count for pagination (excluding deleted logs and logs before user joined)
        total_count = AuditLog.objects.exclude(
            userauditlogdeletion__user=request.user
        ).filter(
            timestamp__gte=request.user.date_joined
        ).count()
        
        response = Response({
            'logs': serializer.data,
            'total_count': total_count,
            'page': page,
            'page_size': page_size
        })
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error fetching audit logs: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while fetching audit logs'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

# Update the get_unread_audit_logs_count function
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_unread_audit_logs_count(request):
    """Get count of unread audit logs for the current user, excluding deleted ones and logs before user joined"""
    try:
        # Count logs not viewed by current user, not deleted by the user, and created after user joined
        unread_count = AuditLog.objects.exclude(
            viewed_by=request.user
        ).exclude(
            userauditlogdeletion__user=request.user
        ).filter(
            timestamp__gte=request.user.date_joined
        ).count()
        
        response = Response({
            'unread_count': unread_count
        })
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error fetching unread audit logs count: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while fetching unread audit logs count'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

# Update the mark_all_audit_logs_read function
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def mark_all_audit_logs_read(request):
    """Mark all audit logs as read for the current user, excluding deleted ones and logs before user joined"""
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    try:
        # Get all unread logs that haven't been deleted by the user and were created after user joined
        unread_logs = AuditLog.objects.exclude(
            viewed_by=request.user
        ).exclude(
            userauditlogdeletion__user=request.user
        ).filter(
            timestamp__gte=request.user.date_joined
        )
        
        # Mark them as read
        for log in unread_logs:
            log.viewed_by.add(request.user)
        
        response = Response({
            'message': 'All audit logs marked as read'
        })
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error marking audit logs as read: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while marking audit logs as read'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

@api_view(['GET', 'POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def moderator_management(request):
    """
    President and Vice President can manage moderators - add, remove, set vice president, and transfer presidency
    Operators can only view moderators
    """
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        return response
        
    try:
        # Check if user has permission to access moderator management
        if request.user.role not in ['president', 'vice_president', 'moderator']:
            response = Response(
                {'error': 'You do not have permission to access moderator management'},
                status=status.HTTP_403_FORBIDDEN
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
            
        if request.method == 'GET':
            # Get all moderators, president, and vice president
            moderators = CustomUser.objects.filter(role__in=['moderator', 'president', 'vice_president'])
            data = [
                {
                    'id': user.id,
                    'name': f"{user.first_name} {user.last_name}" if user.first_name and user.last_name else user.username,
                    'email': user.email,
                    'role': user.role,
                    'last_active': user.last_login.strftime('%b %d, %Y %H:%M') if user.last_login else 'Never'
                }
                for user in moderators
            ]
            
            response = Response(data)
            
        elif request.method == 'POST':
            # Check if user has permission to manage moderators
            if request.user.role not in ['president', 'vice_president']:
                response = Response(
                    {'error': 'Only president and vice president can manage moderators'},
                    status=status.HTTP_403_FORBIDDEN
                )
                response['Access-Control-Allow-Origin'] = get_frontend_url()
                response['Access-Control-Allow-Credentials'] = 'true'
                return response
                
            action = request.data.get('action')
            email = request.data.get('email')
            
            if not action or not email:
                response = Response(
                    {'error': 'Action and email are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
                response['Access-Control-Allow-Origin'] = get_frontend_url()
                response['Access-Control-Allow-Credentials'] = 'true'
                return response
                
            # Find the user by email
            try:
                target_user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                response = Response(
                    {'error': 'User with this email does not exist'},
                    status=status.HTTP_404_NOT_FOUND
                )
                response['Access-Control-Allow-Origin'] = get_frontend_url()
                response['Access-Control-Allow-Credentials'] = 'true'
                return response
                
            if action == 'add_moderator':
                if target_user.role == 'moderator':
                    response = Response(
                        {'error': 'User is already a moderator'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    target_user.role = 'moderator'
                    target_user.save()
                    
                    # Create audit log
                    create_audit_log(
                        request.user,
                        'moderator_added',
                        f"Added {email} as a moderator"
                    )
                    
                    # Send notification email
                    send_mail(
                        'You have been promoted to Moderator',
                        f'You have been promoted to Moderator in the SOMASE Election System by {request.user.email}.',
                        settings.DEFAULT_FROM_EMAIL,
                        [email],
                        fail_silently=True,
                    )
                    
                    response = Response({
                        'message': f'{email} has been added as a moderator',
                        'user_id': target_user.id
                    })
                    
            elif action == 'remove_moderator':
                if target_user.role != 'moderator':
                    response = Response(
                        {'error': 'User is not a moderator'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    target_user.role = 'voter'
                    target_user.save()
                    
                    # Create audit log
                    create_audit_log(
                        request.user,
                        'moderator_removed',
                        f"Removed {email} as a moderator"
                    )
                    
                    # Send notification email
                    send_mail(
                        'You have been removed as Moderator',
                        f'You have been removed as Moderator in the SOMASE Election System by {request.user.email}.',
                        settings.DEFAULT_FROM_EMAIL,
                        [email],
                        fail_silently=True,
                    )
                    
                    response = Response({
                        'message': f'{email} has been removed as a moderator'
                    })
                    
            elif action == 'set_vice_president':
                if target_user.role == 'vice_president':
                    response = Response(
                        {'error': 'User is already vice president'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    # Remove current vice president if exists
                    current_vice_presidents = CustomUser.objects.filter(role='vice_president')
                    for user in current_vice_presidents:
                        user.role = 'moderator'
                        user.save()
                    
                    # Set new vice president
                    target_user.role = 'vice_president'
                    target_user.save()
                    
                    # Create audit log
                    create_audit_log(
                        request.user,
                        'vice_president_set',
                        f"Set {email} as Vice President"
                    )
                    
                    # Send notification email
                    send_mail(
                        'You have been set as Vice President',
                        f'You have been set as Vice President in the SOMASE Election System by {request.user.email}.',
                        settings.DEFAULT_FROM_EMAIL,
                        [email],
                        fail_silently=True,
                    )
                    
                    response = Response({
                        'message': f'{email} has been set as vice president',
                        'user_id': target_user.id
                    })
                    
            elif action == 'transfer_presidency':
                # Only president can transfer presidency
                if request.user.role != 'president':
                    response = Response(
                        {'error': 'Only president can transfer presidency'},
                        status=status.HTTP_403_FORBIDDEN
                    )
                    response['Access-Control-Allow-Origin'] = get_frontend_url()
                    response['Access-Control-Allow-Credentials'] = 'true'
                    return response
                    
                if target_user.role == 'president':
                    response = Response(
                        {'error': 'User is already president'},
                        status=status.HTTP_400_BARD_REQUEST
                    )
                else:
                    # Transfer presidency
                    request.user.role = 'moderator'  # Current president becomes moderator
                    request.user.save()
                    
                    target_user.role = 'president'
                    target_user.save()
                    
                    # Create audit log
                    create_audit_log(
                        request.user,
                        'presidency_transferred',
                        f"Transferred presidency to {email}"
                    )
                    
                    # Send notification emails
                    send_mail(
                        'Presidency Transferred',
                        f'You have transferred your presidency to {email} in the SOMASE Election System.',
                        settings.DEFAULT_FROM_EMAIL,
                        [request.user.email],
                        fail_silently=True,
                    )
                    
                    send_mail(
                        'You are now President',
                        f'You have been made President of the SOMASE Election System by {request.user.email}.',
                        settings.DEFAULT_FROM_EMAIL,
                        [email],
                        fail_silently=True,
                    )
                    
                    response = Response({
                        'message': f'Presidency transferred to {email}'
                    })
                    
            else:
                response = Response(
                    {'error': 'Invalid action'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Set CORS headers
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in moderator management: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

# Authentication Views
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def check_auth_view(request):
    profile_photo_url = None
    if request.user.profile_photo:
        profile_photo_url = request.user.profile_photo
    
    return Response({
        'message': 'Authenticated',
        'user_id': request.user.id,
        'username': request.user.username,
        'email': request.user.email,
        'has_voted': request.user.has_voted,
        'profile_photo': profile_photo_url,
        'role': request.user.role
    }, status=status.HTTP_200_OK)

@api_view(['POST', 'OPTIONS'])
@permission_classes([permissions.AllowAny])
@csrf_exempt
def login_view(request):
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    if request.method == 'POST':
        try:
            # Use request.data which is already parsed by DRF
            data = request.data
            
            # Validate required fields
            if 'email' not in data or 'password' not in data:
                return Response({
                    'error': 'Email and password are required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Pass the request in the context to the serializer
            serializer = UserLoginSerializer(data=data, context={'request': request})
            
            if serializer.is_valid():
                user = serializer.validated_data['user']
                login(request, user)
                
                response = Response({
                    'message': 'Login successful',
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email
                }, status=status.HTTP_200_OK)
                
                # Set CORS headers
                response['Access-Control-Allow-Origin'] = get_frontend_url()
                response['Access-Control-Allow-Credentials'] = 'true'
                return response
            else:
                # Return the first error message
                error_msg = next(iter(serializer.errors.values()))[0]
                
                response = Response({
                    'error': error_msg
                }, status=status.HTTP_401_UNAUTHORIZED)
                
                # Set CORS headers
                response['Access-Control-Allow-Origin'] = get_frontend_url()
                response['Access-Control-Allow-Credentials'] = 'true'
                return response
                
        except Exception as e:
            # Log the exception for debugging
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Login error: {str(e)}", exc_info=True)
            
            response = Response({
                'error': 'An internal server error occurred during login'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Set CORS headers
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response

@api_view(['POST', 'OPTIONS'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def logout_view(request):
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    logout(request)
    response = Response({
        'message': 'Logout successful'
    }, status=status.HTTP_200_OK)
    
    # Set CORS headers
    response['Access-Control-Allow-Origin'] = get_frontend_url()
    response['Access-Control-Allow-Credentials'] = 'true'
    return response
@api_view(['POST', 'OPTIONS'])
@permission_classes([permissions.AllowAny])
@csrf_exempt
def candidate_registration_view(request):
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    if request.method == 'POST':
        try:
            # Get email from request data
            email = request.data.get('email')
            
            # Check if email exists in the system
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                response = Response({
                    'error': 'This email is not registered in our system. Please register first before applying.'
                }, status=status.HTTP_400_BAD_REQUEST)
                
                response['Access-Control-Allow-Origin'] = get_frontend_url()
                response['Access-Control-Allow-Credentials'] = 'true'
                return response
            
            # Check if user already has any candidate application (for any position)
            if Candidate.objects.filter(user=user).exists():
                response = Response({
                    'error': 'This email has already been used to submit a candidate application.'
                }, status=status.HTTP_400_BAD_REQUEST)
                
                response['Access-Control-Allow-Origin'] = get_frontend_url()
                response['Access-Control-Allow-Credentials'] = 'true'
                return response
            
            # Check if user already has a candidate application for this specific position
            position = request.data.get('position')
            if Candidate.objects.filter(user=user, position=position).exists():
                response = Response({
                    'error': f'You have already applied for the {dict(Candidate.POSITION_CHOICES).get(position)} position.'
                }, status=status.HTTP_400_BAD_REQUEST)
                
                response['Access-Control-Allow-Origin'] = get_frontend_url()
                response['Access-Control-Allow-Credentials'] = 'true'
                return response
            
            # Pass the user and request in the context to the serializer
            serializer = CandidateRegistrationSerializer(
                data=request.data, 
                context={'user': user, 'request': request}
            )
            
            if serializer.is_valid():
                candidate = serializer.save()
                
                # Create audit log
                create_audit_log(
                    user,
                    'candidate_application',
                    f"Applied for {dict(Candidate.POSITION_CHOICES).get(position)} position"
                )
                
                response = Response({
                    'message': 'Candidate application submitted successfully!',
                    'candidate_id': candidate.id,
                    'full_name': candidate.full_name,
                    'position': candidate.position,
                    'status': candidate.status
                }, status=status.HTTP_201_CREATED)
                
            else:
                response = Response(
                    serializer.errors, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Set CORS headers
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
                
        except Exception as e:
            # Log the exception for debugging
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Candidate registration error: {str(e)}", exc_info=True)
            
            response = Response({
                'error': 'An internal server error occurred during candidate registration'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Set CORS headers
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def get_candidates(request):
    # Get only approved candidates
    candidates = Candidate.objects.filter(status='approved')
    serializer = CandidateSerializer(candidates, many=True, context={'request': request})
    
    response = Response(serializer.data)
    response['Access-Control-Allow-Origin'] = get_frontend_url()
    response['Access-Control-Allow-Credentials'] = 'true'
    return response

# Helper function to check email eligibility
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


@api_view(['GET', 'PUT'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def election_settings_view(request):
    """
    Get or update election settings with email management
    """
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'GET, PUT, OPTIONS'
        return response
      
    try:
        # Get or create election settings (singleton pattern)
        settings, created = ElectionSettings.objects.get_or_create(id=1)
        if settings.is_active and settings.end_date and timezone.now() >= settings.end_date:
            settings.is_active = False
            settings.save()
        if request.method == 'GET':
            # Return settings with additional emails as a list
            settings_data = {
                'id': settings.id,
                'start_year': settings.start_year,
                'end_year': settings.end_year,
                'election_title': settings.election_title,
                'start_date': settings.start_date,
                'end_date': settings.end_date,
                'additional_emails': settings.get_additional_emails_list(),
                'is_active': settings.is_active,
                'updated_at': settings.updated_at
            }
            
            serializer = ElectionSettingsSerializer(settings_data)
            response = Response(serializer.data)
            
        elif request.method == 'PUT':
            # Handle email management operations
            data = request.data.copy()
            
            # Check if this is an email operation
            email_operation = data.get('email_operation')
            
            if email_operation:
                # Handle different email operations
                if email_operation == 'add':
                    email_to_add = data.get('email')
                    if email_to_add:
                        # Validate email format
                        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z00-9.-]+\.[a-zA-Z]{2,}$'
                        if not re.match(email_regex, email_to_add):
                            response = Response(
                                {'error': 'Invalid email format'},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                            response['Access-Control-Allow-Origin'] = get_frontend_url()
                            response['Access-Control-Allow-Credentials'] = 'true'
                            return response
                        
                        # Check if email already exists
                        current_emails = settings.get_additional_emails_list()
                        if email_to_add in current_emails:
                            response = Response(
                                {'error': 'Email already exists in the list'},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                            response['Access-Control-Allow-Origin'] = get_frontend_url()
                            response['Access-Control-Allow-Credentials'] = 'true'
                            return response
                        
                        # Add the email
                        current_emails.append(email_to_add)
                        settings.set_additional_emails_from_list(current_emails)
                        settings.save()
                        
                        response = Response({
                            'message': 'Email added successfully',
                            'additional_emails': current_emails
                        })
                        
                elif email_operation == 'remove':
                    email_to_remove = data.get('email')
                    if email_to_remove:
                        current_emails = settings.get_additional_emails_list()
                        if email_to_remove in current_emails:
                            current_emails.remove(email_to_remove)
                            settings.set_additional_emails_from_list(current_emails)
                            settings.save()
                            
                            response = Response({
                                'message': 'Email removed successfully',
                                'additional_emails': current_emails
                            })
                        else:
                            response = Response(
                                {'error': 'Email not found in the list'},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                            
                elif email_operation == 'clear_all':
                    settings.additional_emails = ''
                    settings.save()
                    
                    response = Response({
                        'message': 'All emails cleared successfully',
                        'additional_emails': []
                    })
                
                # Set CORS headers for email operations
                response['Access-Control-Allow-Origin'] = get_frontend_url()
                response['Access-Control-Allow-Credentials'] = 'true'
                return response
                
            else:
                # Regular settings update
                # Convert additional_emails list to string if provided
                if 'additional_emails' in data and isinstance(data['additional_emails'], list):
                    data['additional_emails'] = '\n'.join([email.strip() for email in data['additional_emails'] if email.strip()])
                
                serializer = ElectionSettingsSerializer(settings, data=data)
                if serializer.is_valid():
                    serializer.save()
                    
                    # Create audit log
                    create_audit_log(
                        request.user,
                        'settings_updated',
                        "Updated election settings"
                    )
                    
                    response = Response({
                        'message': 'Election settings updated successfully',
                        'settings': serializer.data
                    })
                else:
                    response = Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        # Set CORS headers
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error handling election settings: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while handling election settings'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response


# Voting Views
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def cast_vote(request):
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    try:
        candidate_id = request.data.get('candidate_id')
        
        if not candidate_id:
            response = Response({'error': 'Candidate ID is required'}, status=status.HTTP_400_BAD_REQUEST)
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Get election settings
        try:
            election_settings = ElectionSettings.objects.get(id=1)
        except ElectionSettings.DoesNotExist:
            response = Response(
                {'error': 'Election settings not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Check if user is eligible to vote based on email
        if not is_email_eligible(
            request.user.email, 
            election_settings.start_year, 
            election_settings.end_year,
            election_settings.additional_emails
        ):
            response = Response({
                'error': f'You are not eligible to vote. Only students admitted between {election_settings.start_year} and {election_settings.end_year} are allowed to vote.'
            }, status=status.HTTP_403_FORBIDDEN)
            
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Get the candidate and check if they are approved
        candidate = Candidate.objects.get(id=candidate_id, status='approved')
        
        # Check if user has already voted for this position
        if Vote.objects.filter(user=request.user, position=candidate.position).exists():
            response = Response(
                {'error': f'You have already voted for the {candidate.get_position_display()} position.'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Create the vote
        vote = Vote.objects.create(
            user=request.user,
            candidate=candidate,
            position=candidate.position
        )
        
        # Update candidate vote count
        candidate.votes += 1
        candidate.save()
        
        # Create audit log
        create_audit_log(
            request.user,
            'vote_cast',
            f"Voted for {candidate.full_name} for {candidate.get_position_display()}"
        )
        
        # Check if user has voted for all positions
        all_positions = [choice[0] for choice in Candidate.POSITION_CHOICES]
        user_votes = Vote.objects.filter(user=request.user)
        voted_positions = [vote.position for vote in user_votes]
        
        # If user has voted for all positions, mark as voted
        if set(voted_positions) == set(all_positions):
            request.user.has_voted = True
            request.user.save()
        
        response = Response({
            'message': 'Vote recorded successfully',
            'vote_id': vote.id,
            'candidate_name': candidate.full_name,
            'position': candidate.get_position_display(),
            'has_completed_voting': request.user.has_voted
        }, status=status.HTTP_201_CREATED)
        
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Candidate.DoesNotExist:
        response = Response({'error': 'Candidate not found or not approved'}, status=status.HTTP_404_NOT_FOUND)
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Vote casting error: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while casting your vote'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_user_votes(request):
    votes = Vote.objects.filter(user=request.user).select_related('candidate')
    data = [
        {
            'position': vote.position,
            'candidate_id': vote.candidate.id,
            'candidate_name': vote.candidate.full_name,
            'voted_at': vote.voted_at
        }
        for vote in votes
    ]
    
    response = Response(data)
    response['Access-Control-Allow-Origin'] = get_frontend_url()
    response['Access-Control-Allow-Credentials'] = 'true'
    return response

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def unvote(request):
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    try:
        position = request.data.get('position')
        
        if not position:
            response = Response({'error': 'Position is required'}, status=status.HTTP_400_BAD_REQUEST)
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Check if user has a vote for this position
        try:
            vote = Vote.objects.get(user=request.user, position=position)
        except Vote.DoesNotExist:
            response = Response({'error': 'No vote found for this position'}, status=status.HTTP_404_NOT_FOUND)
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        candidate = vote.candidate
        # Delete the vote
        vote.delete()
        
        # Update candidate vote count
        candidate.votes -= 1
        candidate.save()
        
        # Create audit log
       
        
        # Check if user has any votes left
        if not Vote.objects.filter(user=request.user).exists():
            request.user.has_voted = False
            request.user.save()
        
        response = Response({
            'message': 'Vote removed successfully',
            'position': position
        }, status=status.HTTP_200_OK)
        
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Unvote error: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while removing your vote'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_candidate_applications(request):
    """
    Get all candidate applications with filtering options
    """
    try:
        # Get status filter from query params
        status_filter = request.GET.get('status', 'all')
        
        # Start with all candidates
        candidates = Candidate.objects.all()
        
        # Apply status filter if provided
        if status_filter != 'all':
            candidates = candidates.filter(status=status_filter)
        
        # Serialize the data
        serializer = CandidateSerializer(candidates, many=True, context={'request': request})
        
        response = Response(serializer.data)
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error fetching candidate applications: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while fetching candidate applications'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

@api_view(['PATCH'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def update_candidate_status(request, candidate_id):
    """
    Update a candidate's status (approve/reject)
    """
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'PATCH, OPTIONS'
        return response
        
    try:
        # Get the candidate
        candidate = Candidate.objects.get(id=candidate_id)
        
        # Get the new status from request data
        new_status = request.data.get('status')
        
        if new_status not in ['approved', 'rejected', 'pending']:
            response = Response(
                {'error': 'Invalid status. Must be "approved", "rejected", or "pending"'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Update the candidate status
        candidate.status = new_status
        candidate.updated_at = timezone.now()
        candidate.save()
        
        # Create audit log
        action_type = 'candidate_approval' if new_status == 'approved' else 'candidate_rejection'
        create_audit_log(
            request.user,
            action_type,
            f"{'Approved' if new_status == 'approved' else 'Rejected'} candidate {candidate.full_name} for {candidate.get_position_display()}"
        )
        
        response = Response({
            'message': f'Candidate status updated to {new_status}',
            'candidate_id': candidate.id,
            'status': candidate.status
        }, status=status.HTTP_200_OK)
        
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Candidate.DoesNotExist:
        response = Response(
            {'error': 'Candidate not found'},
            status=status.HTTP_404_NOT_FOUND
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error updating candidate status: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while updating candidate status'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_candidate_detail(request, candidate_id):
    """
    Get detailed information about a specific candidate
    """
    try:
        candidate = Candidate.objects.get(id=candidate_id)
        
        # Check if the requesting user owns this candidate application
        if candidate.user != request.user:
            response = Response(
                {'error': 'You do not have permission to view this application'},
                status=status.HTTP_403_FORBIDDEN
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
            
        serializer = CandidateSerializer(candidate, context={'request': request})
        
        response = Response(serializer.data)
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Candidate.DoesNotExist:
        response = Response(
            {'error': 'Candidate not found'},
            status=status.HTTP_404_NOT_FOUND
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error fetching candidate details: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while fetching candidate details'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_election_results(request):
    """
    Get real-time election results
    """
    try:
        # Get election settings
        try:
            election_settings = ElectionSettings.objects.get(id=1)
        except ElectionSettings.DoesNotExist:
            # Use default values if settings not configured
            start_year = 2022
            end_year = 2025
        else:
            start_year = election_settings.start_year
            end_year = election_settings.end_year
        
        # Get all approved candidates with their vote counts
        candidates = Candidate.objects.filter(status='approved')
        serializer = CandidateSerializer(candidates, many=True, context={'request': request})
        
        # Calculate total votes
        total_votes = Vote.objects.count()
        
        response = Response({
            'totalVotes': total_votes,
            'candidates': serializer.data,
            'electionSettings': {
                'startYear': start_year,
                'endYear': end_year
            }
        })
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error fetching election results: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while fetching results'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def mark_user_voted(request):
    """
    Mark user as having voted
    """
    try:
        user = request.user
        user.has_voted = True
        user.save()
        
        response = Response({
            'message': 'User marked as voted',
            'user_id': user.id
        })
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error marking user as voted: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while marking user as voted'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_my_candidate_application(request):
    """Get the current user's candidate application"""
    try:
        candidate = Candidate.objects.get(user=request.user)
        serializer = CandidateSerializer(candidate, context={'request': request})
        response = Response(serializer.data)
    except Candidate.DoesNotExist:
        response = Response({'message': 'No application found'}, status=status.HTTP_404_NOT_FOUND)
    
    response['Access-Control-Allow-Origin'] = get_frontend_url()
    response['Access-Control-Allow-Credentials'] = 'true'
    return response

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def reset_votes(request):
    """
    Reset all votes and candidate vote counts
    """
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    try:
        # Check if user has permission (only president/vice president)
        if request.user.role not in ['president', 'vice_president']:
            response = Response(
                {'error': 'Only president and vice president can reset votes'},
                status=status.HTTP_403_FORBIDDEN
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
            
        # Reset all votes
        Vote.objects.all().delete()
        
        # Reset all candidate vote counts
        Candidate.objects.all().update(votes=0)
        
        # Reset user voting status
        CustomUser.objects.all().update(has_voted=False)
        
        # Create audit log
        create_audit_log(
            request.user,
            'votes_reset',
            "Reset all votes and candidate vote counts"
        )
        
        response = Response({
            'message': 'All votes and candidate vote counts have been reset successfully'
        }, status=status.HTTP_200_OK)
        
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error resetting votes: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while resetting votes'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def clear_audit_logs(request):
    """
    Clear audit logs for the current user only by creating deletion records
    """
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    try:
        # Get all logs that haven't been deleted by this user
        all_logs = AuditLog.objects.all()
        
        # Create deletion records for all logs for this user
        for log in all_logs:
            # Create a record that this user has deleted this log
            # This will be used to filter out logs in future queries
            UserAuditLogDeletion.objects.get_or_create(
                user=request.user,
                audit_log=log
            )
        
        response = Response({
            'message': 'Your audit logs have been cleared successfully'
        })
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error clearing audit logs: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while clearing audit logs'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def bulk_vote(request):
    """
    Submit all votes at once
    """
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    try:
        votes_data = request.data.get('votes', [])
        
        # Get election settings
        try:
            election_settings = ElectionSettings.objects.get(id=1)
        except ElectionSettings.DoesNotExist:
            response = Response(
                {'error': 'Election settings not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Check if user is eligible to vote based on email
        if not is_email_eligible(
            request.user.email, 
            election_settings.start_year, 
            election_settings.end_year,
            election_settings.additional_emails
        ):
            response = Response({
                'error': f'You are not eligible to vote. Only students admitted between {election_settings.start_year} and {election_settings.end_year} are allowed to vote.'
            }, status=status.HTTP_403_FORBIDDEN)
            
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Check if election is active
        if not election_settings.is_active:
            response = Response(
                {'error': 'Election is not active'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Use transaction to ensure all votes are recorded or none
        with transaction.atomic():
            # Delete any existing votes for this user
            Vote.objects.filter(user=request.user).delete()
            
            # Reset vote counts for candidates that this user had voted for
            previous_votes = Vote.objects.filter(user=request.user)
            for vote in previous_votes:
                vote.candidate.votes -= 1
                vote.candidate.save()
            
            # Create new votes
            for vote_data in votes_data:
                candidate_id = vote_data.get('candidate_id')
                position = vote_data.get('position')
                
                if not candidate_id or not position:
                    continue
                
                # Get the candidate
                try:
                    candidate = Candidate.objects.get(id=candidate_id, status='approved')
                except Candidate.DoesNotExist:
                    continue
                
                # Create the vote
                vote = Vote.objects.create(
                    user=request.user,
                    candidate=candidate,
                    position=position
                )
                
                # Update candidate vote count
                candidate.votes += 1
                candidate.save()
            
            # Mark user as having voted
            request.user.has_voted = True
            request.user.save()
        
        
        
        response = Response({
            'message': 'All votes submitted successfully',
            'votes_count': len(votes_data)
        }, status=status.HTTP_201_CREATED)
        
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Bulk vote error: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while submitting your votes'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
# Add this endpoint to update an application
@api_view(['PUT'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def update_candidate_application(request, candidate_id):
    """Update a candidate application"""
    if request.method == 'OPTIONS':
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'PUT, OPTIONS'
        return response
        
    try:
        # Get the candidate application
        candidate = get_object_or_404(Candidate, id=candidate_id, user=request.user)
        
        # Check if application can be edited (only pending applications can be edited)
        if candidate.status not in ['pending', 'rejected']:
            response = Response(
                {'error': 'Cannot edit application that is not in pending or rjected status'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
            
        # For file uploads, use request.data directly
        data = request.data.copy()
        
        # Handle file separately if provided
        if 'profile_photo' not in request.FILES:
            data.pop('profile_photo', None)
        
        serializer = CandidateRegistrationSerializer(
            candidate, 
            data=data, 
          partial=True,  # Allow partial updates
            context={'user': request.user, 'request': request}
        )
        
        if serializer.is_valid():
            serializer.save()
            
            # Create audit log
            create_audit_log(
                request.user,
                'candidate_application_updated',
                f"Updated candidate application for {candidate.get_position_display()}"
            )
            
            response = Response({
                'message': 'Application updated successfully',
                'candidate_id': candidate.id,
                'status': candidate.status
            })
        else:
            response = Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error updating candidate application: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An error occurred while updating application'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    response['Access-Control-Allow-Origin'] = get_frontend_url()
    response['Access-Control-Allow-Credentials'] = 'true'
    return response
@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def delete_candidate_application(request, candidate_id):
    """Delete a candidate application"""
    if request.method == 'OPTIONS':
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'DELETE, OPTIONS'
        return response
        
    try:
        candidate = get_object_or_404(Candidate, id=candidate_id, user=request.user)
        
        # Allow deletion for both pending and rejected applications
        if candidate.status not in ['pending', 'rejected']:
            response = Response(
                {'error': 'Cannot delete application that has been approved'},
                status=status.HTTP_400_BAD_REQUEST
            )
        else:
            candidate.delete()
            
            # Create audit log
            create_audit_log(
                request.user,
                'candidate_application_deleted',
                f"Deleted candidate application for {candidate.get_position_display()}"
            )
            
            response = Response({'message': 'Application deleted successfully'})
            
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error deleting candidate application: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An error occurred while deleting application'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    response['Access-Control-Allow-Origin'] = get_frontend_url()
    response['Access-Control-Allow-Credentials'] = 'true'
    return response

# Add this new view to check election status
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def check_election_status(request):
    """
    Check if a scheduled election should be started
    """
    try:
        # Get election settings
        try:
            election_settings = ElectionSettings.objects.get(id=1)
        except ElectionSettings.DoesNotExist:
            return Response(
                {'error': 'Election settings not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get current time
        now = timezone.now()
        
        # Convert start_date to timezone-aware datetime if it's naive
        start_date = election_settings.start_date
        if timezone.is_naive(start_date):
            start_date = timezone.make_aware(start_date)
        
        # Check if election is scheduled but not active and start time has passed
        if not election_settings.is_active and start_date and start_date <= now:
            # Start the election
            election_settings.is_active = True
            election_settings.save()
            
            # Convert end_date to timezone-aware datetime if it's naive
            end_date = election_settings.end_date
            if timezone.is_naive(end_date):
                end_date = timezone.make_aware(end_date)
            
            # Calculate time until election ends
            time_until_end = end_date - now
            days = time_until_end.days
            hours, remainder = divmod(time_until_end.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            
            # Create audit log
            create_audit_log(
                request.user,
                'election_start',
                f"Election automatically started as scheduled: {election_settings.election_title}"
            )
            
            return Response({
                'message': 'Election automatically started as scheduled',
                'time_remaining': {
                    'days': days,
                    'hours': hours,
                    'minutes': minutes,
                    'seconds': seconds
                },
                'election_status': 'active'
            }, status=status.HTTP_200_OK)
        
        # Return current status
        if election_settings.is_active:
            status_msg = 'active'
        elif start_date and start_date > now:
            status_msg = 'scheduled'
        else:
            status_msg = 'inactive'
        
        return Response({
            'election_status': status_msg,
            'is_active': election_settings.is_active,
            'start_date': election_settings.start_date,
            'end_date': election_settings.end_date
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error checking election status: {str(e)}", exc_info=True)
        return Response(
            {'error': 'An internal server error occurred while checking election status'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def check_election_end(request):
    """
    Check if election should end based on scheduled time
    This should be called periodically by a cron job or scheduler
    """
    try:
        # Get election settings
        try:
            election_settings = ElectionSettings.objects.get(id=1)
        except ElectionSettings.DoesNotExist:
            return Response({'status': 'no_election'}, status=status.HTTP_200_OK)
        
        # Only check if election is active
        if not election_settings.is_active:
            return Response({'status': 'not_active'}, status=status.HTTP_200_OK)
        
        # Get current time
        now = timezone.now()
        
        # Convert end_date to timezone-aware datetime if it's naive
        end_date = election_settings.end_date
        if timezone.is_naive(end_date):
            end_date = timezone.make_aware(end_date)
        
        # Check if end time has passed
        if end_date <= now:
            # End the election
            election_settings.is_active = False
            election_settings.save()
            
            # Create audit log
            create_audit_log(
                None,  # System action
                'election_ended',
                f"Election ended automatically"
            )
            
            # Send notification to all users
            try:
                send_election_ended_emails(election_settings)
                create_audit_log(
                    None,
                    'email_notification',
                    "Sent election end emails to all users"
                )
            except Exception as e:
                logger.error(f"Error sending election end emails: {str(e)}")
            
            return Response({
                'status': 'ended',
                'message': 'Election has ended automatically'
            }, status=status.HTTP_200_OK)
        
        # Calculate time until election ends
        time_until_end = end_date - now
        days = time_until_end.days
        hours, remainder = divmod(time_until_end.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        return Response({
            'status': 'active',
            'time_remaining': {
                'days': days,
                'hours': hours,
                'minutes': minutes,
                'seconds': seconds
            }
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error checking election end: {str(e)}", exc_info=True)
        return Response(
            {'error': 'An internal server error occurred while checking election end'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

def send_election_ended_emails(election_settings):
    """
    Send election ended notification emails to all users
    """
    from django.core.mail import send_mass_mail
    from django.conf import settings
    
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
    subject = f"MUBAS SOMASE Elections Has Ended"
    
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

def send_election_cancelled_emails(election_settings):
    """
    Send election cancellation notification emails to all users
    """
    from django.core.mail import send_mass_mail
    from django.conf import settings
    
    # Get all user emails
    user_emails = CustomUser.objects.filter(is_active=True).values_list('email', flat=True)
    user_emails = [email for email in user_emails if email]
    
    # Get additional emails from election settings
    additional_emails = election_settings.get_additional_emails_list()
    
    # Combine all emails
    all_emails = list(user_emails) + additional_emails
    
    if not all_emails:
        logger.warning("No recipients found to send election cancellation emails")
        return
    
    # Email content
    subject = f"SOMASE Election Cancelled"
    
    message = f"""
Hello there,

The MUBAS SOMASE ELECTIONS has been cancelled by the election administrator.

If you have already voted, your votes will not be counted as the election has been cancelled.

We apologize for any inconvenience this may cause.

Best regards,
MUBAS SOMASE Election Committee
"""
    
    # Prepare emails for mass sending
    emails = [(subject, message, settings.DEFAULT_FROM_EMAIL, [email]) for email in all_emails]
    
    # Send emails
    send_mass_mail(emails, fail_silently=False)
    
    logger.info(f"Sent election cancellation emails to {len(all_emails)} recipients")


def send_election_ended_emails(election_settings):
    """
    Send election ended notification emails to all users
    """
    from django.core.mail import send_mass_mail
    from django.conf import settings
    
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
    subject = f"MUBAS SOMASE Elections Has Ended"
    
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

def send_election_cancelled_emails(election_settings):
    """
    Send election cancellation notification emails to all users
    """
    from django.core.mail import send_mass_mail
    from django.conf import settings
    
    # Get all user emails
    user_emails = CustomUser.objects.filter(is_active=True).values_list('email', flat=True)
    user_emails = [email for email in user_emails if email]
    
    # Get additional emails from election settings
    additional_emails = election_settings.get_additional_emails_list()
    
    # Combine all emails
    all_emails = list(user_emails) + additional_emails
    
    if not all_emails:
        logger.warning("No recipients found to send election cancellation emails")
        return
    
    # Email content
    subject = f"SOMASE Election Cancelled"
    
    message = f"""
Hello there,

The MUBAS SOMASE ELECTIONS has been cancelled by the election administrator.

If you have already voted, your votes will not be counted as the election has been cancelled.

We apologize for any inconvenience this may cause.

Best regards,
MUBAS SOMASE Election Committee
"""
    
    # Prepare emails for mass sending
    emails = [(subject, message, settings.DEFAULT_FROM_EMAIL, [email]) for email in all_emails]
    
    # Send emails
    send_mass_mail(emails, fail_silently=False)
    
    logger.info(f"Sent election cancellation emails to {len(all_emails)} recipients")

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def cancel_election(request):
    """
    Cancel the election - works for both active and scheduled elections
    """
    try:
        # Get election settings
        try:
            election_settings = ElectionSettings.objects.get(id=1)
        except ElectionSettings.DoesNotExist:
            response = Response(
                {'error': 'Election settings not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Check if there's an election to cancel (either active or scheduled)
        now = timezone.now()
        start_date = election_settings.start_date
        
        # Convert to timezone-aware if needed
        if start_date and timezone.is_naive(start_date):
            start_date = timezone.make_aware(start_date)
        
        is_scheduled = start_date and start_date > now and not election_settings.is_active
        is_active = election_settings.is_active
        
        if not is_active and not is_scheduled:
            response = Response(
                {'error': 'No active or scheduled election to cancel'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Cancel the election
        election_settings.is_active = False
        
        # Clear the dates to prevent auto-start
        election_settings.start_date = None
        election_settings.end_date = None
        election_settings.save()
        
        # Send cancellation emails to all users
        try:
            send_election_cancelled_emails(election_settings)
        except Exception as e:
            logger.error(f"Error sending cancellation emails: {str(e)}")
        
        # Create audit log
        action_text = 'Cancelled scheduled election' if is_scheduled else 'Cancelled active election'
        create_audit_log(
            request.user,
            'election_cancelled',
            f"{action_text}: {election_settings.election_title}"
        )
        
        response = Response({
            'message': 'Election cancelled successfully',
            'was_scheduled': is_scheduled,
            'was_active': is_active
        }, status=status.HTTP_200_OK)
        
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error cancelling election: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while cancelling the election'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
    
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def start_election(request):
    """
    Start the election manually
    """
    if request.method == 'OPTIONS':
        # Handle preflight requests
        response = Response()
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken, Authorization'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    try:
        # Get election settings
        try:
            election_settings = ElectionSettings.objects.get(id=1)
        except ElectionSettings.DoesNotExist:
            response = Response(
                {'error': 'Election settings not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Check if user has permission (only president/vice president)
        if request.user.role not in ['president', 'vice_president']:
            response = Response(
                {'error': 'Only president and vice president can start elections'},
                status=status.HTTP_403_FORBIDDEN
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Get current time
        now = timezone.now()
        
        # Check if both start and end dates are set
        if not election_settings.start_date or not election_settings.end_date:
            response = Response(
                {'error': 'Start date and end date must be configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Convert dates to timezone-aware if needed
        start_date = election_settings.start_date
        if timezone.is_naive(start_date):
            start_date = timezone.make_aware(start_date)
            
        end_date = election_settings.end_date
        if timezone.is_naive(end_date):
            end_date = timezone.make_aware(end_date)
        
        # Check if election is already active
        if election_settings.is_active:
            # Calculate time until election ends
            if end_date > now:
                time_until_end = end_date - now
                days = time_until_end.days
                hours, remainder = divmod(time_until_end.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                
                response = Response({
                    'message': f'Election is active and will end in {days} days, {hours} hours, and {minutes} minutes',
                    'time_remaining': {
                        'days': days,
                        'hours': hours,
                        'minutes': minutes,
                        'seconds': seconds
                    },
                    'election_status': 'active'
                }, status=status.HTTP_200_OK)
            else:
                # Election has ended
                election_settings.is_active = False
                election_settings.save()
                
                response = Response({
                    'message': 'Election has ended',
                    'election_status': 'ended'
                }, status=status.HTTP_200_OK)
            
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Check if end date is before start date
        if end_date <= start_date:
            response = Response(
                {'error': 'End date must be after start date'},
                status=status.HTTP_400_BAD_REQUEST
            )
            response['Access-Control-Allow-Origin'] = get_frontend_url()
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # Start the election
        election_settings.is_active = True
        election_settings.save()
        
        # Calculate time until election ends
        time_until_end = end_date - now
        days = time_until_end.days
        hours, remainder = divmod(time_until_end.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        # Create audit log
        create_audit_log(
            request.user,
            'election_start',
            f"Started election: {election_settings.election_title}"
        )
        
        response = Response({
            'message': 'Election started successfully',
            'time_remaining': {
                'days': days,
                'hours': hours,
                'minutes': minutes,
                'seconds': seconds
            },
            'election_status': 'active'
        }, status=status.HTTP_200_OK)
        
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error starting election: {str(e)}", exc_info=True)
        
        response = Response(
            {'error': 'An internal server error occurred while starting the election'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        response['Access-Control-Allow-Origin'] = get_frontend_url()
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated])
def delete_all_candidates(request):
    # Check if user is president or vice president
    if request.user.role not in ['president', 'vice_president']:
        return Response({'error': 'Permission denied'}, status=403)
    
    try:
        # Delete all candidates
        Candidate.objects.all().delete()
        
        # Create audit log
        AuditLog.objects.create(
            user=request.user,
            action='candidate_deletion',
            details='Deleted all candidate applications'
        )
        
        return Response({'message': 'All candidates deleted successfully'})
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@csrf_exempt
def send_election_start_emails(request):
    """
    Send election start notification emails to all users using management command
    """
    try:
        # Get election settings
        try:
            election_settings = ElectionSettings.objects.get(id=1)
        except ElectionSettings.DoesNotExist:
            return Response(
                {'error': 'Election settings not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if end_date is set
        if not election_settings.end_date:
            return Response(
                {'error': 'Election end date is not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Run the management command in a subprocess
        import subprocess
        from django.core.management import call_command
        
        try:
            # Using call_command is better than subprocess for Django management commands
            call_command('send_election_emails', '--type', 'start')
        except Exception as e:
            logger.error(f"Error running management command: {str(e)}", exc_info=True)
            return Response(
                {'error': 'Failed to send emails via management command'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Create audit log
        create_audit_log(
            request.user,
            'email_notification',
            "Sent election start emails to all users via management command"
        )
        
        return Response({
            'status': 'success',
            'message': 'Election start emails are being sent via management command'
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error in send_election_start_emails: {str(e)}", exc_info=True)
        return Response(
            {'error': 'An internal server error occurred while sending election start emails'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def activate_account(request, uidb64, token):
    """
    Handle email verification and return HTML response
    """
    try:
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None
        
        if user is not None and account_activation_token.check_token(user, token):
            if not user.is_email_verified:
                user.is_active = True
                user.is_email_verified = True
                user.save()
                
                user.backend = 'vottingapp.backends.EmailBackend'
                login(request, user)
                
                
                # Successful verification - show success message with login link
                html_content = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Email Verification Successful</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            text-align: center;
                            padding: 50px;
                            background-color: #f5f5f5;
                        }
                        .success {
                            background-color: #d4edda;
                            color: #155724;
                            padding: 20px;
                            border-radius: 5px;
                            border: 1px solid #c3e6cb;
                        }
                        a {
                            color: #155724;
                            text-decoration: underline;
                        }
                    </style>
                </head>
                <body>
                    <div class="success">
                        <h1>Email Verification Successful!</h1>
                        <p>Your email has been verified successfully.</p>
                        <p><a href="https://mubas-somase.onrender.com/login">Click here to go to login page</a></p>
                    </div>
                </body>
                </html>
                """
            else:
                # Email already verified
                html_content = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Email Already Verified</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            text-align: center;
                            padding: 50px;
                            background-color: #f5f5f5;
                        }
                        .info {
                            background-color: #d1ecf1;
                            color: #0c5460;
                            padding: 20px;
                            border-radius: 5px;
                            border: 1px solid #bee5eb;
                        }
                        a {
                            color: #0c5460;
                            text-decoration: underline;
                        }
                    </style>
                </head>
                <body>
                    <div class="info">
                        <h1>Email Already Verified</h1>
                        <p>This email address has already been verified.</p>
                        <p><a href="https://mubas-somase.onrender.com/login">Click here to go to login page</a></p>
                    </div>
                </body>
                </html>
                """
        else:
            # Failed verification
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Email Verification Failed</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        padding: 50px;
                        background-color: #f5f5f5;
                    }
                    .error {
                        background-color: #f8d7da;
                        color: #721c24;
                        padding: 20px;
                        border-radius: 5px;
                        border: 1px solid #f5c6cb;
                    }
                </style>
            </head>
            <body>
                <div class="error">
                    <h1>Email Verification Failed</h1>
                    <p>The verification link is invalid or has expired.</p>
                    <p>Please try registering again or contact support if the problem persists.</p>
                </div>
            </body>
            </html>
            """
        
        return HttpResponse(html_content, content_type='text/html')
            
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in account activation: {str(e)}", exc_info=True)
        
        # Error during activation process
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Activation Error</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 50px;
                    background-color: #f5f5f5;
                }
                .error {
                    background-color: #f8d7da;
                    color: #721c24;
                    padding: 20px;
                    border-radius: 5px;
                    border: 1px solid #f5c6cb;
                }
            </style>
        </head>
        <body>
            <div class="error">
                <h1>Activation Error</h1>
                <p>An error occurred during the activation process.</p>
                <p>Please try again or contact support if the problem persists.</p>
            </div>
        </body>
        </html>
        """
        
        return HttpResponse(html_content, content_type='text/html')
 

# Set up logger
logger = logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def activate_account(request, uidb64, token):
    """
    Handle email verification and return HTML response
    """
    try:
        logger.info(f"Account activation attempt - UID: {uidb64}, Token: {token}")
        
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)
            logger.info(f"User found for activation: {user.username} ({user.email})")
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist) as e:
            user = None
            logger.error(f"Invalid UID or user not found: {str(e)}")

        if user is not None and account_activation_token.check_token(user, token):
            if not user.is_email_verified:
                user.is_active = True
                user.is_email_verified = True
                user.save()
                
                user.backend = 'vottingapp.backends.EmailBackend'
                login(request, user)
                logger.info(f"User {user.username} successfully activated and logged in")
                
                # Successful verification - show success message with login link
                html_content = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Email Verification Successful</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            text-align: center;
                            padding: 50px;
                            background-color: #f5f5f5;
                        }
                        .success {
                            background-color: #d4edda;
                            color: #155724;
                            padding: 20px;
                            border-radius: 5px;
                            border: 1px solid #c3e6cb;
                        }
                        a {
                            color: #155724;
                            text-decoration: underline;
                        }
                    </style>
                </head>
                <body>
                    <div class="success">
                        <h1>Email Verification Successful!</h1>
                        <p>Your email has been verified successfully.</p>
                        <p><a href="https://mubas-somase.onrender.com/login">Click here to go to login page</a></p>
                    </div>
                </body>
                </html>
                """
            else:
                # Email already verified
                logger.warning(f"User {user.username} attempted to verify already verified email")
                html_content = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Email Already Verified</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            text-align: center;
                            padding: 50px;
                            background-color: #f5f5f5;
                        }
                        .info {
                            background-color: #d1ecf1;
                            color: #0c5460;
                            padding: 20px;
                            border-radius: 5px;
                            border: 1px solid #bee5eb;
                        }
                        a {
                            color: #0c5460;
                            text-decoration: underline;
                        }
                    </style>
                </head>
                <body>
                    <div class="info">
                        <h1>Email Already Verified</h1>
                        <p>This email address has already been verified.</p>
                        <p><a href="https://mubas-somase.onrender.com/login">Click here to go to login page</a></p>
                    </div>
                </body>
                </html>
                """
        else:
            # Failed verification
            logger.error(f"Invalid activation token for UID: {uidb64}")
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Email Verification Failed</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        padding: 50px;
                        background-color: #f5f5f5;
                    }
                    .error {
                        background-color: #f8d7da;
                        color: #721c24;
                        padding: 20px;
                        border-radius: 5px;
                        border: 1px solid #f5c6cb;
                    }
                </style>
            </head>
            <body>
                <div class="error">
                    <h1>Email Verification Failed</h1>
                    <p>The verification link is invalid or has expired.</p>
                    <p>Please try registering again or contact support if the problem persists.</p>
                </div>
            </body>
            </html>
            """
        
        return HttpResponse(html_content, content_type='text/html')
            
    except Exception as e:
        logger.error(f"Critical error in account activation: {str(e)}", exc_info=True)
        
        # Error during activation process
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Activation Error</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 50px;
                    background-color: #f5f5f5;
                }
                .error {
                    background-color: #f8d7da;
                    color: #721c24;
                    padding: 20px;
                    border-radius: 5px;
                    border: 1px solid #f5c6cb;
                }
            </style>
        </head>
        <body>
            <div class="error">
                <h1>Activation Error</h1>
                <p>An error occurred during the activation process.</p>
                <p>Please try again or contact support if the problem persists.</p>
            </div>
        </body>
        </html>
        """
        
        return HttpResponse(html_content, content_type='text/html')


logger = logging.getLogger(__name__)

@api_view(['POST', 'OPTIONS'])
@permission_classes([permissions.AllowAny])
@csrf_exempt
def register_view(request):
    from django.conf import settings
    
    if request.method == 'OPTIONS':
        response = Response()
        response['Access-Control-Allow-Origin'] = settings.FRONTEND_URL
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response
        
    if request.method == 'POST':
        user = None
        try:
            # For file uploads, use request.data directly
            if request.content_type.startswith('multipart/form-data'):
                data = request.data
            else:
                try:
                    data = json.loads(request.body)
                except json.JSONDecodeError:
                    return Response({
                        'error': 'Invalid request format. Please check your input and try again.'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate required fields
            required_fields = ['username', 'email', 'password']
            for field in required_fields:
                if field not in data or not data[field]:
                    return Response({
                        'error': f'Missing required field: {field}'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if user already exists
            if CustomUser.objects.filter(email=data['email']).exists():
                return Response({
                    'error': 'An account with this email already exists. Please use a different email.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if CustomUser.objects.filter(username=data['username']).exists():
                return Response({
                    'error': 'Username already taken. Please choose a different username.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create the new user using serializer
            serializer = UserRegistrationSerializer(data=data)
            
            if serializer.is_valid():
                # Create user but set as inactive initially
                user = serializer.save()
                user.is_active = False
                user.is_email_verified = False
                
                # Handle profile photo upload to Cloudinary
                if 'profile_photo' in request.FILES:
                    profile_photo = request.FILES['profile_photo']
                    try:
                        upload_result = cloudinary.uploader.upload(
                            profile_photo,
                            folder='voting_app/profiles/',
                            resource_type='image',
                            timeout=30
                        )
                        user.profile_photo = upload_result['secure_url']
                        logger.info(f"Profile photo uploaded successfully: {upload_result['secure_url']}")
                    except Exception as e:
                        logger.error(f"Cloudinary upload error: {str(e)}", exc_info=True)
                        user.profile_photo = None
                
                user.save()
                
                # Generate verification token and URL
                current_site = get_current_site(request)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = account_activation_token.make_token(user)
                
                # Create HTML email message
                mail_subject = 'Activate your MUBAS SOMASE Voting account'
                
                # HTML content with styling
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
                            color:#1e4a76;
                            font-weight: bold;
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
                            <h2>Hello {user.username},</h2>
                            <p>Thank you for registering as a MUBAS SOMASE member. To complete your registration, please verify your email address by clicking the button below:</p>
                            
                            <center>
                                <a style="color:white" href="{settings.FRONTEND_URL}/activate/{uid}/{token}" class="button">
                                    Verify Email Address
                                </a>
                            </center>
                            
                            <p>Or copy and paste the following link into your browser:</p>
                            <p class="verification-link">{settings.FRONTEND_URL}/activate/{uid}/{token}</p>
                            
                            <p>If you didn't request this registration, please ignore this email.</p>
                            
                            <p>Best regards,<br>The MUBAS SOMASE Team</p>
                        </div>
                        <div class="footer">
                            <p>This is an automated message. Please do not reply to this email.</p>
                            <p>&copy; {timezone.now().year} SOMASE Voting System. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                
                # Plain text version
                text_content = f"""Hi {user.username},

Please click on the link below to confirm your registration for the SOMASE Voting System:

{settings.FRONTEND_URL}/activate/{uid}/{token}

If you didn't register for this account, please ignore this email.

Thank you,
MUBAS SOMASE Team"""
                
                # Enhanced email sending with detailed error handling
                try:
                    # Log email configuration (without password)
                    logger.info(f"Attempting to send verification email to {user.email}")
                    logger.info(f"Email host: {settings.EMAIL_HOST}")
                    logger.info(f"Email port: {settings.EMAIL_PORT}")
                    logger.info(f"Email use TLS: {settings.EMAIL_USE_TLS}")
                    logger.info(f"From email: {settings.DEFAULT_FROM_EMAIL}")
                    
                    # Test SMTP connection before sending
                    logger.info("Testing SMTP connection...")
                    if settings.EMAIL_USE_TLS:
                        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=15)
                        server.starttls()
                    else:
                        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=15)
                    
                    # Test authentication
                    server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
                    server.quit()
                    logger.info("SMTP connection test successful")
                    
                    # Create and send email
                    email = EmailMultiAlternatives(
                        mail_subject,
                        text_content,
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        reply_to=[settings.DEFAULT_FROM_EMAIL]
                    )
                    email.attach_alternative(html_content, "text/html")
                    
                    # Send with timeout
                    email.connection = None  # Force new connection
                    email.send(fail_silently=False)
                    
                    logger.info(f"Verification email sent successfully to {user.email}")
                    
                    response = Response({
                        'message': 'Registration successful! Please check your MUBAS email to verify your account. You will be automatically logged in after verification.',
                        'user_id': user.id,
                        'email_sent': True
                    }, status=status.HTTP_201_CREATED)
                    
                except smtplib.SMTPAuthenticationError as e:
                    logger.error(f"SMTP Authentication Failed: {str(e)}")
                    if user:
                        user.delete()
                    response = Response({
                        'error': 'Email service authentication failed. This is a server configuration issue. Please contact support.',
                        'error_type': 'smtp_authentication'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
                except smtplib.SMTPConnectError as e:
                    logger.error(f"SMTP Connection Error: {str(e)}")
                    if user:
                        user.delete()
                    response = Response({
                        'error': 'Cannot connect to email service. Please check your internet connection and try again later.',
                        'error_type': 'smtp_connection'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
                except smtplib.SMTPServerDisconnected as e:
                    logger.error(f"SMTP Server Disconnected: {str(e)}")
                    if user:
                        user.delete()
                    response = Response({
                        'error': 'Email server disconnected unexpectedly. Please try again.',
                        'error_type': 'smtp_disconnected'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
                except smtplib.SMTPException as e:
                    logger.error(f"SMTP Error: {str(e)}")
                    if user:
                        user.delete()
                    response = Response({
                        'error': 'Email delivery failed. Please check if your email address is valid and try again.',
                        'error_type': 'smtp_general'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
                except TimeoutError as e:
                    logger.error(f"Email sending timeout: {str(e)}")
                    if user:
                        user.delete()
                    response = Response({
                        'error': 'Email service timeout. Please try again in a few moments.',
                        'error_type': 'timeout'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
                except Exception as e:
                    logger.error(f"Unexpected email error: {str(e)}", exc_info=True)
                    if user:
                        user.delete()
                    response = Response({
                        'error': 'Failed to send verification email due to an unexpected error. Please try again or contact support.',
                        'error_type': 'unexpected'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
            else:
                # Return detailed validation errors
                error_messages = []
                for field, errors in serializer.errors.items():
                    for error in errors:
                        error_messages.append(f"{field}: {error}")
                
                response = Response({
                    'error': 'Please correct the following errors:',
                    'details': error_messages
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            # Log the exception for debugging
            logger.error(f"Registration process error: {str(e)}", exc_info=True)
            
            # Clean up user if it was created
            if user and user.pk:
                try:
                    user.delete()
                    logger.info("Cleaned up user due to registration error")
                except Exception as delete_error:
                    logger.error(f"Error cleaning up user: {str(delete_error)}")
            
            response = Response({
                'error': 'An unexpected error occurred during registration. Please try again later.',
                'error_type': 'registration_process'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Set CORS headers for all responses
        response['Access-Control-Allow-Origin'] = settings.FRONTEND_URL
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

# Additional endpoint for email configuration testing
@api_view(['GET', 'POST'])
@permission_classes([permissions.AllowAny])
@csrf_exempt
def test_email_configuration(request):
    """
    Endpoint to test email configuration (for admin debugging)
    """
    from django.core.mail import send_mail
    from django.conf import settings
    import smtplib
    
    test_results = {
        'smtp_connection': False,
        'smtp_authentication': False,
        'email_send': False,
        'details': [],
        'config': {
            'host': settings.EMAIL_HOST,
            'port': settings.EMAIL_PORT,
            'use_tls': settings.EMAIL_USE_TLS,
            'user': settings.EMAIL_HOST_USER,
            'from_email': settings.DEFAULT_FROM_EMAIL,
            'timeout': 15
        }
    }
    
    try:
        # Test 1: SMTP Connection
        logger.info("Testing SMTP connection...")
        if settings.EMAIL_USE_TLS:
            server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=15)
            server.starttls()
        else:
            server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=15)
        
        test_results['smtp_connection'] = True
        test_results['details'].append("✓ SMTP connection successful")
        
        # Test 2: SMTP Authentication
        logger.info("Testing SMTP authentication...")
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        test_results['smtp_authentication'] = True
        test_results['details'].append("✓ SMTP authentication successful")
        server.quit()
        
        # Test 3: Send Test Email
        logger.info("Testing email send...")
        send_mail(
            'MUBAS SOMASE - Email Configuration Test',
            'This is a test email from your MUBAS SOMASE application.\n\nIf you received this, your email configuration is working correctly.',
            settings.DEFAULT_FROM_EMAIL,
            [settings.DEFAULT_FROM_EMAIL],  # Send to yourself
            fail_silently=False,
        )
        test_results['email_send'] = True
        test_results['details'].append("✓ Test email sent successfully")
        
        return Response({
            'success': True,
            'message': 'Email configuration test passed',
            'results': test_results
        })
        
    except smtplib.SMTPConnectError as e:
        test_results['details'].append(f"✗ SMTP Connection Failed: {str(e)}")
        return Response({
            'success': False,
            'error': 'Cannot connect to SMTP server. Check host and port.',
            'results': test_results
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    except smtplib.SMTPAuthenticationError as e:
        test_results['details'].append(f"✗ SMTP Authentication Failed: {str(e)}")
        return Response({
            'success': False,
            'error': 'SMTP authentication failed. Check username and password.',
            'results': test_results
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    except smtplib.SMTPException as e:
        test_results['details'].append(f"✗ SMTP Error: {str(e)}")
        return Response({
            'success': False,
            'error': 'SMTP error occurred during testing.',
            'results': test_results
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    except Exception as e:
        test_results['details'].append(f"✗ Unexpected Error: {str(e)}")
        return Response({
            'success': False,
            'error': 'Unexpected error during email test.',
            'results': test_results
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
# In your Django views.py
@api_view(['DELETE'])
@login_required
def delete_user_account(request):
    try:
        user = request.user
        user.delete()
        return Response({'message': 'Account deleted successfully'}, status=200)
    except Exception as e:
        return Response({'error': str(e)}, status=400)
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def test_email_config(request):
    """
    Endpoint to test email configuration (for admin use)
    """
    from django.core.mail import send_mail
    from django.conf import settings
    import smtplib
    import logging
    
    logger = logging.getLogger(__name__)
    
    test_results = {
        'smtp_connection': False,
        'smtp_authentication': False,
        'email_send': False,
        'details': []
    }
    
    try:
        # Test 1: SMTP Connection
        logger.info("Testing SMTP connection...")
        if settings.EMAIL_USE_TLS:
            server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=10)
        
        test_results['smtp_connection'] = True
        test_results['details'].append("SMTP connection successful")
        
        # Test 2: SMTP Authentication
        logger.info("Testing SMTP authentication...")
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        test_results['smtp_authentication'] = True
        test_results['details'].append("SMTP authentication successful")
        server.quit()
        
        # Test 3: Send Test Email
        logger.info("Testing email send...")
        send_mail(
            'MUBAS SOMASE - Email Test',
            'This is a test email from your MUBAS SOMASE application.',
            settings.DEFAULT_FROM_EMAIL,
            [settings.DEFAULT_FROM_EMAIL],  # Send to yourself
            fail_silently=False,
        )
        test_results['email_send'] = True
        test_results['details'].append("Test email sent successfully")
        
        return Response({
            'success': True,
            'results': test_results,
            'config': {
                'host': settings.EMAIL_HOST,
                'port': settings.EMAIL_PORT,
                'use_tls': settings.EMAIL_USE_TLS,
                'user': settings.EMAIL_HOST_USER,
                'from_email': settings.DEFAULT_FROM_EMAIL
            }
        })
        
    except smtplib.SMTPConnectError as e:
        test_results['details'].append(f"SMTP Connection Failed: {str(e)}")
        return Response({
            'success': False,
            'error': 'Cannot connect to SMTP server',
            'results': test_results
        }, status=500)
    except smtplib.SMTPAuthenticationError as e:
        test_results['details'].append(f"SMTP Authentication Failed: {str(e)}")
        return Response({
            'success': False,
            'error': 'SMTP authentication failed',
            'results': test_results
        }, status=500)
    except Exception as e:
        test_results['details'].append(f"Unexpected error: {str(e)}")
        return Response({
            'success': False,
            'error': 'Email test failed',
            'results': test_results
        }, status=500)

# users/serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import CustomUser, Candidate, Vote, Election,ElectionSettings,AuditLog
from django.db.models import Q
import re

import cloudinary
import cloudinary.uploader
class AuditLogSerializer(serializers.ModelSerializer):
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    timestamp_formatted = serializers.SerializerMethodField()
    user_email = serializers.SerializerMethodField()
    
    class Meta:
        model = AuditLog
        fields = ('id', 'user', 'user_email', 'action', 'action_display', 'details', 'timestamp', 'timestamp_formatted')
    
    def get_timestamp_formatted(self, obj):
        return obj.timestamp.strftime('%b %d, %Y %H:%M')
    
    def get_user_email(self, obj):
        return obj.user.email if obj.user else 'System'
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)
    profile_photo = serializers.ImageField(required=False, allow_null=True)  
     
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'email', 'password', 'password2', 'profile_photo','role')
        extra_kwargs = {
            'password': {'write_only': True},
            'role': {'read_only': True} 
        }
    
    def validate_username(self, value):
        if CustomUser.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with that username already exists.")
        return value
    
    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        email_pattern = r'^mse\d{2}-.*@mubas\.ac\.mw$'
        if not re.match(email_pattern, value):
            raise serializers.ValidationError(
                "Only MUBAS SOMASE student emails (mseYY-username@mubas.ac.mw) are allowed for registration."
            )
        return value
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        # Additional password strength validation
        password = attrs['password']
        if len(password) < 8:
            raise serializers.ValidationError({"password": "Password must be at least 8 characters long."})
        
        if not any(char.isdigit() for char in password):
            raise serializers.ValidationError({"password": "Password must contain at least one digit."})
        
        if not any(char.isupper() for char in password):
            raise serializers.ValidationError({"password": "Password must contain at least one uppercase letter."})
        
        return attrs
    
    def create(self, validated_data):
        profile_photo = validated_data.pop('profile_photo', None)
        validated_data.pop('password2')
        password = validated_data.pop('password')
        
        # Create user first without the profile photo
        user = CustomUser.objects.create(**validated_data)
        user.set_password(password)
        
        # Handle profile photo upload to Cloudinary
        if profile_photo:
            try:
                # Upload to Cloudinary
                upload_result = cloudinary.uploader.upload(
                    profile_photo,
                    folder='voting_app/profiles/',
                    resource_type='image'
                )
                user.profile_photo = upload_result['secure_url']
                print(f"Profile photo uploaded successfully: {upload_result['secure_url']}")
            except Exception as e:
                # If Cloudinary upload fails, raise a validation error
                error_msg = f"Failed to upload profile photo: {str(e)}"
                print(error_msg)
                # Delete the user since registration failed
                user.delete()
                raise serializers.ValidationError({"profile_photo": error_msg})
        
        user.save()
        return user

class UserLoginSerializer(serializers.Serializer):
    email = serializers.CharField()  # Change from EmailField to CharField
    password = serializers.CharField()
    
    def validate(self, attrs):
        email_or_username = attrs.get('email')
        password = attrs.get('password')
        
        if email_or_username and password:
            # Get the request from context
            request = self.context.get('request')
            
            # Try to authenticate using email or username
            user = authenticate(
                request=request, 
                username=email_or_username, 
                password=password
            )
            
            if user:
                if not user.is_active:
                    raise serializers.ValidationError("User account is disabled.")
                attrs['user'] = user
                return attrs
            else:
                # Check if email/username exists in the system
                if CustomUser.objects.filter(
                    Q(email=email_or_username) | Q(username=email_or_username)
                ).exists():
                    raise serializers.ValidationError("Invalid password.")
                else:
                    raise serializers.ValidationError(
                        "No account found with this email address or username."
                    )
        else:
            raise serializers.ValidationError("Must include 'email' and 'password'.")
class CandidateRegistrationSerializer(serializers.ModelSerializer):
    profile_photo = serializers.ImageField(required=True)
    email = serializers.EmailField(required=True)

    class Meta:
        model = Candidate
        fields = ('id', 'email', 'full_name', 'position', 'phone', 'slogan', 'manifesto', 'profile_photo')

    def validate_email(self, value):
        if not CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is not registered in our system.")
        return value

    def validate_slogan(self, value):
        if len(value) > 50:
            raise serializers.ValidationError("Slogan must be 50 characters or less.")
        return value

    def validate_manifesto(self, value):
        word_count = len(value.strip().split())
        if word_count > 200:
            raise serializers.ValidationError("Manifesto must be 200 words or less.")
        return value

    def create(self, validated_data):
        # Remove email from validated_data (not a model field)
        validated_data.pop('email', None)

        # Associate the candidate with the user from context
        user = self.context.get('user')
        if not user:
            raise serializers.ValidationError("User context is required.")
        validated_data['user'] = user

        # Handle profile photo upload to Cloudinary
        profile_photo_file = validated_data.pop('profile_photo')
        
        try:
            # Upload to Cloudinary with proper folder
            upload_result = cloudinary.uploader.upload(
                profile_photo_file,
                folder='voting_app/candidates/',
                resource_type='image'
            )
            validated_data['profile_photo'] = upload_result['secure_url']
            print(f"Candidate profile photo uploaded successfully: {upload_result['secure_url']}")
        except Exception as e:
            # If Cloudinary upload fails, raise a validation error
            error_msg = f"Failed to upload profile photo: {str(e)}"
            print(error_msg)
            raise serializers.ValidationError({"profile_photo": error_msg})

        return super().create(validated_data)

class CandidateSerializer(serializers.ModelSerializer):
    position_display = serializers.CharField(source='get_position_display', read_only=True)
    profile_photo = serializers.SerializerMethodField()  # This should work with get_profile_photo
    applied_on = serializers.DateTimeField(source='created_at', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = Candidate
        fields = ('id', 'email', 'full_name', 'position', 'position_display', 'phone', 
                 'slogan', 'manifesto', 'profile_photo', 'status', 'applied_on', 
                 'votes', 'user', 'created_at')
        read_only_fields = ('user', 'votes')
    
    def get_profile_photo(self, obj):  # Corrected method name
        # CloudinaryField automatically provides a URL
        if obj.profile_photo:
            return obj.profile_photo.url
        return None
    
    def get_created_at_formatted(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')
class VoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vote
        fields = ('id', 'user', 'candidate', 'position', 'voted_at')
        read_only_fields = ('user', 'voted_at')
    
    def validate(self, attrs):
        # Check if user has already voted for this position
        user = self.context['request'].user
        position = attrs['candidate'].position
        
        if Vote.objects.filter(user=user, position=position).exists():
            raise serializers.ValidationError(f"You have already voted for the {position} position.")
        
        # Check if the candidate is approved
        if not attrs['candidate'].is_approved:
            raise serializers.ValidationError("You can only vote for approved candidates.")
        
        return attrs
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        validated_data['position'] = validated_data['candidate'].position
        
        # Create the vote
        vote = Vote.objects.create(**validated_data)
        
        # Update candidate vote count
        candidate = validated_data['candidate']
        candidate.votes += 1
        candidate.save()
        
        # Mark user as having voted
        user = validated_data['user']
        user.has_voted = True
        user.save()
        
        return vote


class ElectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Election
        fields = ('id', 'name', 'start_date', 'end_date', 'is_active')

class ElectionSettingsSerializer(serializers.ModelSerializer):
    additional_emails = serializers.CharField(required=False, allow_blank=True)
    
    class Meta:
        model = ElectionSettings
        fields = '__all__'
    
    def to_representation(self, instance):
        """Convert additional_emails string to list for response"""
        representation = super().to_representation(instance)
        if isinstance(instance, ElectionSettings):
            representation['additional_emails'] = instance.get_additional_emails_list()
        return representation
    
    def to_internal_value(self, data):
        """Handle additional_emails conversion from frontend"""
        # If additional_emails is provided as a list, convert it to a string
        if 'additional_emails' in data and isinstance(data['additional_emails'], list):
            data['additional_emails'] = '\n'.join([email.strip() for email in data['additional_emails'] if email.strip()])
        return super().to_internal_value(data)
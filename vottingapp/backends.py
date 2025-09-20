# vottingapp/backends.py
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.db.models import Q

UserModel = get_user_model()

class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            # Try to fetch the user by email or username
            user = UserModel.objects.get(
                Q(email__iexact=username) | Q(username__iexact=username)
            )
        except UserModel.DoesNotExist:
            # Run the default password hasher once to reduce timing difference
            UserModel().set_password(password)
            return None
        except UserModel.MultipleObjectsReturned:
            # If multiple users are found, return the first one
            user = UserModel.objects.filter(
                Q(email__iexact=username) | Q(username__iexact=username)
            ).first()

        if user and user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
    
    def get_user(self, user_id):
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
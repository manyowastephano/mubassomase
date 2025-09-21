
# from django.apps import AppConfig

# class VottingappConfig(AppConfig):
#     default_auto_field = 'django.db.models.BigAutoField'
#     name = 'vottingapp'
    
#     def ready(self):
#         # Start scheduler when Django starts
#         if not hasattr(self, 'scheduler_started'):
#             from .scheduler import start_scheduler
#             start_scheduler()
#             self.scheduler_started = True
            
from django.apps import AppConfig
import sys
import os

class VottingappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vottingapp'
    
    def ready(self):
        # Don't start scheduler during management commands
        is_management_command = any(
            cmd in sys.argv for cmd in ['migrate', 'makemigrations', 'collectstatic', 'createsuperuser']
        )
        
        # Don't start scheduler during tests
        is_test_command = 'test' in sys.argv
        
        if is_management_command or is_test_command:
            return
            
        # Start scheduler only when the app is fully loaded
        if not hasattr(self, 'scheduler_started'):
            try:
                from .scheduler import start_scheduler
                start_scheduler()
                self.scheduler_started = True
            except Exception as e:
                # Log the error but don't crash the app
                print(f"Failed to start scheduler: {e}")

from django.apps import AppConfig

class VottingappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vottingapp'
    
    def ready(self):
        # Start scheduler when Django starts
        if not hasattr(self, 'scheduler_started'):
            from .scheduler import start_scheduler
            start_scheduler()
            self.scheduler_started = True
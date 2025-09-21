from django.apps import AppConfig

class VottingappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vottingapp'
    
    # Remove the ready() method entirely or keep it empty
    # def ready(self):
    #     pass
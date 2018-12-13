from django.urls import  path
from . import views

app_name = 'check'

urlpatterns = [
    path('', views.index, name='index'),
    path('result/', views.detail, name='detail'),
    path('ibm/', views.ibm, name='ibm'),
    path('ipvoid/', views.ipvoid, name='ipvoid'),
    path('virustotal/', views.virustotal, name='virustotal'),
    path('iplocation/', views.iplocation, name='iplocation'),
    path('report/', views.report, name='report'),
    path('ibmapi/', views.ibm_api, name='ibmapi'),
    path('virustotalapi/', views.virustotal_api, name='virustotalapi'),
    path('settings/', views.settings, name='settings'),
]
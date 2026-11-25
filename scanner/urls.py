from django.urls import path
from . import views

urlpatterns = [
    path('', views.program_list, name='program_list'),
    path('programs/create/', views.program_create, name='program_create'),
    path('programs/<int:pk>/', views.program_detail, name='program_detail'),
    path('programs/<int:pk>/edit/', views.program_edit, name='program_edit'),
    path('programs/<int:pk>/scan/', views.trigger_scan_view, name='trigger_scan'),
    path('programs/<int:pk>/export-scope/', views.export_scope_json, name='export_scope_json'),
    path('programs/<int:pk>/export-report/', views.export_report_markdown, name='export_report_markdown'),
    path('runs/<int:pk>/', views.scan_run_detail, name='scan_run_detail'),
    path('runs/<int:pk>/stop/', views.stop_scan_view, name='stop_scan'),
    path('api/runs/<int:pk>/logs/', views.scan_run_logs_api, name='scan_run_logs_api'),
    path('tools/', views.tools_status_view, name='tools_status'),
]

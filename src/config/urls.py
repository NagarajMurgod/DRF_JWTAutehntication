"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from drf_yasg import openapi
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include("authentication.urls"))
]



schema_view = get_schema_view(
    openapi.Info(
        title="My API",
        default_version='v1',
        description="Test description",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@myapi.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
)

if settings.DEBUG is True:
    #urlpatterns += static(settings.MEDIA_URL, document_url=settings.MEDIA_ROOT)
    urlpatterns += [
        path('swagger/', schema_view.with_ui('swagger', cache_timeout=0),name='swagger-ui'),
        path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    ]
    
    # # default django rest framework documentation
    # from rest_framework.documentation import get_schema_view, include_docs_urls
    # urlpatterns += [
    #     # path(
    #     #     "openapi/",
    #     #     get_schema_view(title="Your Project", description="API for all things …"),
    #     #     name="openapi-schema",
    #     # ),
    #     path(
    #         "docs/", include_docs_urls(title="Your Project"),
    #     )
    # ]
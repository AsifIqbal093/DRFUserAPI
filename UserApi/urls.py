from django.urls import path, include
from User import views


app_name = 'User'

from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
)

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('create/', views.CreateUserView.as_view(), name='registration'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('confirm-email/<str:uidb64>/<str:token>/', views.ConfirmEmailView.as_view(), name='confirm-email'),
    path('me/', views.ManageUserView.as_view(), name='me'),
    path('users/', views.UserListCreateView.as_view(), name='user-list-create'),
    path('users/<int:pk>/', views.UserRetrieveUpdateDestroyView.as_view(), name='user-retrieve-update-destroy'),
    path('logout/', views.UserLogoutView.as_view(), name='user-logout'),
    path('password-change/', views.PasswordChangeView.as_view(), name='password-change'),
    path('password-reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('password-reset/<int:id>/<str:token>/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    
    path('schema/', SpectacularAPIView.as_view(), name='api-schema'),
    path('docs/', SpectacularSwaggerView.as_view(
        url_name='api-schema'
        ), name='api-docs'
    ),
]
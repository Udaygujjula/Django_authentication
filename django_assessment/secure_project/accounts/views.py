from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordChangeForm, PasswordResetForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash

@login_required
def dashboard_view(request):
    return render(request, 'dashboard.html', {'user': request.user})


@login_required
def profile_view(request):
    last_login = request.user.last_login
    return render(request, 'profile.html', {'user': request.user, 'last_login': last_login})


def logout_view(request):
    logout(request)
    return redirect('login')


def login_view(request):
    if request.method == "POST":
        login_input = request.POST.get('username_or_email')
        password = request.POST.get('password')

        user = None
        try:
            if '@' in login_input:  # Handle email input
                user = User.objects.get(email=login_input)
                user = authenticate(username=user.username, password=password)
            else:  # Handle username input
                user = authenticate(username=login_input, password=password)

            if user:
                login(request, user)
                return redirect('dashboard')
            else:
                messages.error(request, "Invalid username/email or password.")
        except User.DoesNotExist:
            messages.error(request, "User not found.")
    
    return render(request, 'login.html')


def signup_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
        else:
            try:
                if User.objects.filter(username=username).exists():
                    messages.error(request, "Username is already taken.")
                elif User.objects.filter(email=email).exists():
                    messages.error(request, "This email is already registered.")
                else:
                    new_user = User.objects.create_user(username=username, email=email, password=password)
                    messages.success(request, "Account successfully created! You can log in now.")
                    return redirect('login')
            except Exception as ex:
                messages.error(request, f"Something went wrong: {ex}")
    
    return render(request, 'signup.html')


def forgot_password_view(request):
    if request.method == "POST":
        reset_form = PasswordResetForm(request.POST)
        if reset_form.is_valid():
            reset_form.save(request=request)
            messages.success(request, "A password reset link has been sent to your email.")
            return redirect('login')
    else:
        reset_form = PasswordResetForm()
    
    return render(request, 'forgot_password.html', {'form': reset_form})


@login_required
def change_password_view(request):
    if request.method == "POST":
        password_form = PasswordChangeForm(request.user, request.POST)
        if password_form.is_valid():
            user = password_form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Your password has been updated successfully.")
            return redirect('dashboard')
    else:
        password_form = PasswordChangeForm(request.user)
    
    return render(request, 'change_password.html', {'form': password_form})

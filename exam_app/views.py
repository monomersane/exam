from django.shortcuts import render, redirect
from .models import *
from django.contrib import messages
import bcrypt

# Create your views here.
def index(request):
	return render(request, 'index.html')

def register(request):
	if request.method == "POST":
		errors = User.objects.reg_validator(request.POST)
		if len(errors) > 0:
			for key,value in errors.items():
				messages.error(request, value)
			return redirect('/')

		user = User.objects.filter(email=request.POST['email'])
		if len(user) > 0:
			messages.error(request,"Email is already in use.")
			return redirect('/')

		pw = bcrypt.hashpw(request.POST['password'].encode(),bcrypt.gensalt()).decode()

		User.objects.create(
			first_name=request.POST['first_name'],
			last_name=request.POST['last_name'],
			email=request.POST['email'],
			password=pw
		)

		request.session['user_id'] = User.objects.last().id
		return redirect('/dashboard')


	else:
		return redirect('/')

def login(request):
	if request.method == "POST":
		errors = User.objects.login_validator(request.POST)
		if len(errors) > 0:
			for key,value in errors.items():
				messages.error(request, value)
			return redirect('/')

		user = User.objects.filter(email=request.POST['login_email'])
		if len(user) == 0:
			messages.error(request,"Invalid Email/Password.")
			return redirect('/')

		if not bcrypt.checkpw(request.POST['login_password'].encode(),user[0].password.encode()):
			messages.error(request,"Invalid Email/Password.")
			return redirect('/')

		request.session['user_id'] = user[0].id
		return redirect('/dashboard')
	else:    
		return redirect('/')

def dashboard(request):
	if 'user_id' not in request.session:
		return redirect('/')
	else:
		context ={
			'user': User.objects.get(id=request.session['user_id']),
            'all_quotes': Quote.objects.all()
		}
		return render(request,'dashboard.html',context)

def logout(request):
	if 'user_id' in request.session:
		del request.session['user_id']
	return redirect('/')

def create_quote(request):
	if request.method == "POST":
		errors = Quote.objects.quote_validator(request.POST)
		if len(errors) > 0:
			for key, value in errors.items():
				messages.error(request,value,extra_tags=key)
			return redirect('/dashboard')


		Quote.objects.create(
			author=request.POST['author'],
			quote=request.POST['quote'],
			user=User.objects.get(id=request.session['user_id'])
		)
		return redirect ('/dashboard')
	else:
		return redirect('/logout')

def destroy_quote(request, quote_id):
	destroy = Quote.objects.get(id=quote_id)
	destroy.delete()
	return redirect('/dashboard')

def edit_user(request):
	context = {
		'edit': User.objects.get(id=request.session['user_id']),
	}

	return render(request,'edit_user.html',context)

def update_user(request):
	if request.method == "POST":
		errors = User.objects.edit_validator(request.POST)
		if len(errors) > 0:
			for key, value in errors.items():
				messages.error(request,value,extra_tags=key)
			return redirect('/edit_user')
		
		update = User.objects.get(id=request.session['user_id'])
		update.first_name = request.POST['edit_first_name']
		update.last_name = request.POST['edit_last_name']
		update.email = request.POST['edit_email']
		update.save()
		return redirect('/dashboard')
	else:
		return redirect('/logout')


def like(request,quo_id,user_id):
	quo = Quote.objects.get(id=quo_id)
	user = User.objects.get(id=user_id)

	quo.likes.add(user)
	return redirect('/dashboard')

def show_user(request,user_id):
	context ={
		'user': User.objects.get(id=user_id)
	}

	return render(request,'show_user.html',context)

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from .models import User, Group, Rules, Bank, Employment, Has_Contributed, Group_Loan
from .helpers import *
from decimal import *
import json, jwt, bcrypt
from django.forms.models import model_to_dict
#FOR TEST ONLY
from django.views.decorators.csrf import csrf_exempt
# stellar imports
from rendzi_service.apps.stellar import stellarOperations
from rendzi_service.apps.stellar.models import StellarAccount
from stellar_sdk import Keypair

# Create your views here.

### Landing Page, right now instruction on how to access API
def index(request):
    return HttpResponse('Youve hit the Rendzi API!<br>Test seeing users with ~/show_user/-ID-<br>Test signup with'
    +' ~/signup/?payload={"username":"","email":"","password":"","first":"","last":"","phone":""}'
    +'<br>Test login with ~/login/-email-/-password-'
    +'<br>Once logged in, get your current user with ~/get/?payload={"token":""}'
    +'<br>Logout with ~/logout/?payload={"token":""}'
    +'<br>Create group with ~/new_group/?payload={"token":"", "name":""}'
    +'<br>Add a member to a group with ~/add_member/?payload={"token":"","username":"", "name":"groupname"}'
    +'<br>Get a groups details with ~/get_group/?payload={"token":"", "name":""}'
    +'<br>Get all groups with ~/get_all_groups/?payload={"token":""}'
    +'<br>Add a rule to a group with ~/add_rule/?payload={"token":"", "name":"", "rule":""}'
    +'<br>Get system rules with ~/get_rule/?payload={"token":""}'
    +'<br>Search Users with ~/search/?payload={"token":"", "username":""}, or {"token"} for global search'
    +'<br>Add Bank info with ~/add_bank/?payload={"token":"","name":"","account":"","routing":""}'
    +'<br>Get Bank info with ~/get_bank/?payload={"token"}'
    +'<br>Add Employment info with ~/add_employment/?payload={"token":"","employer":"","ssn":"","salary":""}'
    +'<br>Get Employment infof with ~/get_employment/?payload={"token"}'
    +'<br>Update User info with ~/update_user/?payload={"token","first","middle","last","street","city","state","zipcode","county","email", "phone"}'
    +'<br>Update Bank info with ~/update_bank/?payload={"token","name","account","routing"}'
    +'<br>Update Employment info with ~/update_employment/?payload={"token","ssn","employer","salary"}'
    +'<br>All values except token are optional in update/edit functions'
    +'<br>Contribute to a group account with ~/contribute/?payload={"token":"","name":"","amount":}'
    +'<br>Get a list of a group contributors and amounts with ~/get_contributed/{"token":"","name":""}'
    +'<br>An Admin can loan from a group to a member with ~/loan/?payload={"token","name","amount","username"}'
    +'<br>A member can view the groups loans with ~/get_loans/?payload={"token","name"}'
    +'<br>*"name" in all group functions is the name of the group'
    +'<br>*"username" in loan is the username of the destination'
    +'<br>**Remeber: You can also use POST requests for this. The JSON is the same, just omit the ?payload=')

### show_user Function
# Params: http request, int id
# Returns JSON of the User at that id from the database
# Not authentication based, will NOT be in final product. Used for testing
def show_user(request, id):
    pk = id
    qs = User.objects.filter(id=pk)
    if len(qs) > 0:
        user = list(qs.values())
        return JsonResponse(user, safe=False)
    else:
        return HttpResponse("User " + str(id) + " not in the database")

### get_user Function
# Params: Http request, and a json like {"token":}
# Returns JSON of the currently logged in user with that token in the database
def get_user(request):
    temp = check_input(request)
    if temp:
        try:
            user = User.objects.get(token=temp["token"])
        except User.DoesNotExist:
            return JsonResponse({"Error":"User Does Not Exist"}, status=400)
        if authenticate(temp["token"]):
            return JsonResponse(model_to_dict(user), status=200, content_type="application/json")
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### signup Function
# Params: http POST request, json like {"username":, "email":, "password":, "first":,"last":,"phone":}
# Returns http reponse of the status of the signup as html
@csrf_exempt
def signup(request):
    temp = check_input(request)
    if temp:
        qs = User.objects.filter(email=temp["email"])
        if len(qs) == 0:
            obj, created = User.objects.get_or_create(username=temp["username"], email=temp["email"],
                                                    password=temp["password"], is_active=False,
                                                    first_name=temp["first"], last_name=temp["last"],
                                                    phone=temp["phone"], account_balance=100)
            if obj and created:
                obj.set_password(temp["password"])
                obj.save()
                keypair = stellarOperations.create_account()
                acc, new = StellarAccount.objects.get_or_create(public_key=keypair.public_key, secret_key=keypair.secret, account_balance=0)
                if acc and new:
                    obj.stellar_account = acc
                    obj.save()
                return JsonResponse({"User":"Signup Successful"}, status=200, content_type="application/json")
            else:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
        else:
            return JsonResponse({"Error":"Email already in use"}, status=400)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### login Function
# Params email address and password of the user trying to login
# Returns http reponse of the status of the login or jwt token and sets user is_active to true
def login(request, email, password):
    if not email or not password:
        return JsonResponse({"Error":"Please Enter Username/Password"}, status=400)
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return JsonResponse({"Error":"Invalid Email"}, status=400)
    matched = bcrypt.checkpw(password.encode('utf-8'), str(user.password).encode('utf-8'))
    if matched:
        payload = {"email":user.email,"pk":user.id}
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256").decode("utf-8")
        jwt_token = {"token":token}
        user.token = token
        user.is_active = True
        user.save()
        return JsonResponse(jwt_token, status=200, content_type="application/json")
    else:
        return JsonResponse({"Error":"Invalid Password"}, status=400, content_type="application/json")

### logout Function
# Params: Http request, and a json like {"token":}
# Returns status 400 if an error, and 200 is logout is successful
def logout(request):
    temp = check_input(request)
    if temp:
        try:
            user = User.objects.get(token=temp["token"])
        except User.DoesNotExist:
            return JsonResponse({"Error":"User Does Not Exist"}, status=500)
        if authenticate(temp["token"]):
            user.is_active = False
            user.token = ''
            user.save()
            return JsonResponse({"Success":"User Logged Out"}, status=200)
        else:
            return JsonResponse({"Error":"Error Logging Out"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### create_group Function
# Params: Post Request Body with {"token":, "name":}, where token is user token and name is the new group name
# Returns status of group creation
@csrf_exempt
def create_group(request):
    temp = check_input(request)
    if temp:
        try:
            user = User.objects.get(token=temp["token"])
        except User.DoesNotExist:
            return JsonResponse({"Error":"User Does Not Exist"}, status=500)
        if authenticate(temp["token"]):
            qs = Group.objects.filter(name=temp["name"])
            if len(qs) == 0:
                obj, created = Group.objects.get_or_create(manager=user, name=temp["name"], account_balance=1000)
                if obj and created:
                    keypair = stellarOperations.create_account()
                    acc, new = StellarAccount.objects.get_or_create(public_key=keypair.public_key, secret_key=keypair.secret, account_balance=1000)
                    if acc and new:
                        obj.stellar_account = acc
                        obj.save()
                    return JsonResponse({"Group":"Group Created"}, status=200)
                else:
                    return JsonResponse({"Error":"Internal Server Error"}, status=500)
            else:
                return JsonResponse({"Error":"Group Name in Use"}, status=400)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### get_group_detail Function
# Params: info json of {"token":, "name":} where token is the token of the user and name is the group name
# Returns Json of values of the group
def get_group_detail(request):
    temp = check_input(request)
    if temp:
        try:
            user = User.objects.get(token=temp["token"])
        except User.DoesNotExist:
            return JsonResponse({"Error":"User Does Not Exist"}, status=500)
        if authenticate(temp["token"]):
            try:
                group = Group.objects.get(name=temp["name"])
            except Group.DoesNotExist:
                return JsonResponse({"Error":"Group Does Not Exist"}, status=400)
            if group.manager == user or group.members == user:
                members = []
                rules = []
                manager = group.manager
                for obj in group.members.all():
                    members.append(obj.username)
                for obj in group.rules.all():
                    rules.append(obj.get_rule_display())
                return JsonResponse({"group":model_to_dict(group, fields=['name', 'account_balance']),"members":members,"manager":model_to_dict(manager, fields=['username']), "rules":rules}, status=200, content_type="application/json")
            else:
                return JsonResponse({"Error": "Internal Server Error"}, status=500)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### get_group_all Function
# Params: info json of {"token":} where token is the token of the user
# Returns json of all groups associated with that user token
def get_group_all(request):
    temp = check_input(request)
    if temp:
        try:
            user = User.objects.get(token=temp["token"])
        except User.DoesNotExist:
            return JsonResponse({"Error":"User Does Not Exist"}, status=500)
        if authenticate(temp["token"]):
            qs = Group.objects.filter(members=user) | Group.objects.filter(manager=user)
            if not qs:
                return JsonResponse({"Error":"No Groups"}, status=400)
            else:
                return JsonResponse({"groups":list(qs.values())}, status=200)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### add_member Function
# Params: POST request body with json of {"token":, "username":,} where token is the token of the user
# and username is the username of the user being added to the group.
# Returns the status of the addition of the user to the group.
@csrf_exempt
def add_member(request):
    temp = check_input(request)
    if temp:
        try:
            user = User.objects.get(token=temp["token"])
        except User.DoesNotExist:
            return JsonResponse({"Error":"User Does Not Exist"}, status=500)
        if authenticate(temp["token"]):
            try:
                group = Group.objects.get(manager=user, name=temp["name"])
            except Group.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            try:
                new_member = User.objects.get(username=temp["username"])
            except User.DoesNotExist:
                return JsonResponse({"Error":"Username is Invalid"}, status=400)
            group.members.add(new_member)
            return JsonResponse({"Success":"New Member Added"}, status=200)
        else:
            return JsonResponse({"Error":"User is Logged Out"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### search users in database
# Params: info json like {"token", "username"} or {"token"} for a global search
# Returns a list of users matching either username or phone
def search_users(request):
    temp = check_input(request)
    if temp:
        if(authenticate(temp["token"])):
            if temp.__contains__("username"):
                qs = User.objects.filter(username__icontains=temp["username"])
                if len(qs) < 1:
                    return JsonResponse({"Search":"No Results"}, status=200)
                else:
                    return JsonResponse({"users":list(qs.values())}, status=200)
            else:
                qs = User.objects.all()
                if len(qs) < 1:
                    return JsonResponse({"Search":"No Results"}, status=200)
                else:
                    return JsonResponse({"users":list(qs.values())}, status=200)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### adds a rule to a group
# Params: POST request body with json like {"token", "name", "rule"}
# Returns status of the rule addition
def add_rule(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
            except User.DoesNotExist:
                return JsonResponse({"Error":"User Does Not Exist"})
            try:
                group = Group.objects.get(name=temp["name"], manager=user)
            except Group.DoesNotExist:
                return JsonResponse({"Error":"Group Does Not Exist or User is Not Admin"})
            obj, created = Rules.objects.get_or_create(rule=temp["rule"])
            group.rules.add(obj)
            group.save()
            return JsonResponse({"Group":"Rule Added"}, status=200)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### returns all rules in the system
# Params: POST body with json of the form {"token"}
# returns a list of system levels rules
def get_rules(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            rules = []
            for choice in Rules._meta.get_field('rule').choices:
                rules.append(choice)
            return JsonResponse({"rules":rules}, status=200)
        else:
            return JsonResponse({"Error":"Internal Servver Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Creates and Adds Bank Table to User
# Params: POST body with json of the form {"token", "name", "account", "routing"}
# returns status of the bank addition
def add_bank(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
            except User.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            obj, created = Bank.objects.get_or_create(name=temp["name"], account_number=temp["account"],
                                                    routing_number=temp["routing"])
            if obj and created:
                user.bank = obj
                user.save()
                return JsonResponse({"Success":"Bank Added"}, status=200)
            else:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Retrieves Bank info from the database associated with a user
# Params: Post body json of the form {"token"}
# returns json of the bank table associated with the token
def get_bank(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
                bank = user.bank
            except User.DoesNotExist or Bank.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            return JsonResponse(model_to_dict(bank), status=200, content_type="application/json")
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Creates and Adds Employment Table to User
# Params: POST body with json of the form {"token", "employer", "ssn", "salary"}
# returns status of the employment addition
def add_employment(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
            except User.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            obj, created = Employment.objects.get_or_create(employer=temp["employer"], ssn=temp["ssn"],
                                                    salary=temp["salary"])
            if obj and created:
                user.employment = obj
                user.save()
                return JsonResponse({"Success":"Employment Added"}, status=200)
            else:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Retrieves Employment info from the database associated with a user
# Params: Post body json of the form {"token"}
# returns json of the employment table associated with the token
def get_employment(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
                employment = user.employment
            except User.DoesNotExist or Employment.DoesNotExist:
                return JsonResponse({"Error":"Interal Server Error"}, status=500)
            return JsonResponse(model_to_dict(employment), status=200, content_type="application/json")
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Updates/edits user information
# Params: POST body json like {"token","first","middle","last","street","city","state","zipcode","county","email"}
# returns the status of the update
def update_user(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
            except User.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            if temp.__contains__("first"):
                user.set_first_name(temp["first"])
            if temp.__contains__("middle"):
                user.set_middle_name(temp["middle"])
            if temp.__contains__("last"):
                user.set_last_name(temp["last"])
            if temp.__contains__("email"):
                user.set_email(temp["email"])
            if temp.__contains__("street"):
                user.set_address_street(temp["street"])
            if temp.__contains__("city"):
                user.set_address_city(temp["city"])
            if temp.__contains__("state"):
                user.set_address_state(temp["state"])
            if temp.__contains__("zipcode"):
                user.set_address_zip(temp["zipcode"])
            if temp.__contains__("country"):
                user.set_address_country(temp["country"])
            if temp.__contains__("phone"):
                user.set_phone(temp["phone"])
            user.save()
            return JsonResponse({"Success":"User Updated"}, status=200)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Updates/edits bank information associated with a user
# Params: POST body json like {"token","name","account","routing","street","city","state","zipcode","country"}
# returns the status of the update
def update_bank(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
                bank = user.bank
            except User.DoesNotExist or Bank.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            if temp.__contains__("name"):
                bank.set_name(temp["name"])
            if temp.__contains__("account"):
                bank.set_account_number(temp["account"])
            if temp.__contains__("routing"):
                bank.set_routing_number(temp["routing"])
            if temp.__contains__("street"):
                bank.set_address_street(temp["street"])
            if temp.__contains__("city"):
                bank.set_address_city(temp["city"])
            if temp.__contains__("state"):
                bank.set_address_state(temp["state"])
            if temp.__contains__("zipcode"):
                bank.set_address_zip(temp["zipcode"])
            if temp.__contains__("country"):
                bank.set_address_country(temp["country"])
            bank.save()
            return JsonResponse({"Success":"Bank Updated"}, status=200)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Updates/edits employment information associated with a user
# Params: POST body json like {"token","ssn","employer","salary","street","city","state","zipcode","country"}
# returns the status of the update
def update_employment(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
                employment = user.employment
            except User.DoesNotExist or Employment.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            if temp.__contains__("ssn"):
                employment.set_ssn(temp["ssn"])
            if temp.__contains__("employer"):
                employment.set_employer(temp["employer"])
            if temp.__contains__("salary"):
                employment.set_salary(temp["salary"])
            if temp.__contains__("street"):
                employment.set_address_street(temp["street"])
            if temp.__contains__("city"):
                employment.set_address_city(temp["city"])
            if temp.__contains__("state"):
                employment.set_address_state(temp["state"])
            if temp.__contains__("zipcode"):
                employment.set_address_zip(temp["zipcode"])
            if temp.__contains__("country"):
                employment.set_address_country(temp["country"])
            employment.save()
            return JsonResponse({"Success":"Employment Updated"}, status=200)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Function to contribute an ammount to a group
# Params: Json POST body of the form {"token","name","amount"}
# returns the status of the contribution
def contribute(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
                group = Group.objects.get(name=temp["name"])
            except User.DoesNotExist or Group.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            contribute = Has_Contributed.objects.create(user=user, group=group, account_balance=temp["amount"])
            if Decimal(temp["amount"]) <= user.account_balance - 10:
                stellar_acc = user.stellar_account
                group_acc = group.stellar_account
                transaction_obj = stellarOperations.transactionObject(group_acc.public_key, stellar_acc.secret_key, temp["amount"], 'test memo')
                transaction_obj.start()
                transaction_obj.join()
                user.account_balance -= Decimal(temp["amount"])
                group.account_balance += Decimal(temp["amount"])
                group.save()
                user.save()
                return JsonResponse({"Success":"Amount Contributed"}, status=200)
            else:
                return JsonResponse({"Error":"Could Not Add Funds"}, status=500)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Function to return a list of contributions associated with a group
# Params: Json POST body of the form {"token", "name"}
# returns 2 lists, 1 of contribution names and 1 of amounts.
def get_contributed(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
                group = Group.objects.get(name=temp["name"])
            except User.DoesNotExist or Group.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            names = []
            amount = []
            for obj in Has_Contributed.objects.filter(user=user, group=group):
                names.append(obj.user.username)
                amount.append(obj.account_balance)
            return JsonResponse({"name":names, "amount":amount}, status=200)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Function to Loan Money from Group to User
# Params: Json POST body of the form {"token", "name", "amount", "username"}
# returns the status of the loan
def loan_to_member(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
                dest = User.objects.get(username=temp["username"])
                group = Group.objects.get(name=temp["name"], manager=user, members=dest)
            except User.DoesNotExist or Group.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            loan = Group_Loan.objects.create(user=dest, group=group, account_balance=temp["amount"])
            if Decimal(temp["amount"]) <= group.account_balance - 50:
                stellar_acc = dest.stellar_account
                group_acc = group.stellar_account
                transaction_obj = stellarOperations.transactionObject(stellar_acc.secret_key,group_acc.public_key, temp["amount"], 'test memo')
                transaction_obj.start()
                transaction_obj.join()
                dest.account_balance += Decimal(temp["amount"])
                group.account_balance -= Decimal(temp["amount"])
                group.save()
                dest.save()
                return JsonResponse({"Success":"Amount Loaned"}, status=200)
            else:
                return JsonResponse({"Error":"Could Not Loan Funds"}, status=500)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

### Function to return the loans a group has made
# Params: Json POST body like {"token","name"}
# returns two lists, 1 of the group loan names and 1 of amounts
def get_group_loans(request):
    temp = check_input(request)
    if temp:
        if authenticate(temp["token"]):
            try:
                user = User.objects.get(token=temp["token"])
                group = Group.objects.get(name=temp["name"])
            except User.DoesNotExist or Group.DoesNotExist:
                return JsonResponse({"Error":"Internal Server Error"}, status=500)
            names = []
            amount = []
            for obj in Group_Loan.objects.filter(user=user, group=group):
                names.append(obj.user.username)
                amount.append(obj.account_balance)
            return JsonResponse({"name":names, "amount":amount}, status=200)
        else:
            return JsonResponse({"Error":"Internal Server Error"}, status=500)
    else:
        return JsonResponse({"Error":"Invalid Input"}, status=400)

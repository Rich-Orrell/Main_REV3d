from flask import Flask, request, render_template, redirect, url_for, flash, session, Response, make_response # For redirecting url
import requests
# from flask_mysqldb import MySQL
# import pyodbc
import mysql.connector                  # For connection to database
from cryptography.fernet import Fernet  # Library for encryption/decryption
import pyotp                            # For generate OTP
from datetime import datetime, date, timedelta    # For generate now for OTP and age calculator
import time                             # For convertion from datetime datatype to unix datetime (int)
import qrcode                           # For convert OTP to qrcode upon signup
from PIL import Image                   # For display the QR code as image
import re                               # For input validation
import threading                        # For multi-threading
import itertools                        # For generating table
import os                               # For library shutil
import shutil                           # For attaching the image of QR code to hmtl
from tabulate import tabulate
import textwrap

# -----------------SQLSERVER----------------- #
# server = 'uoe-cybercrime-app.database.windows.net'
# database = 'Cybercrime_app'
# username = 'ro_admin'
# password = 'Abc!!!123'
# Trusted = 'Yes'

# connection_string = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};UID={username}
# ;PWD={password};Encrypt=yes;TrustServerCertificate=yes"
# conn = pyodbc.connect(connection_string)

# db = conn.cursor()
# dbb = db.execute('SELECT * FROM users')
# ----------------------------------- #

# ----------------- connecting to mysql database ----------------- #
global conn
conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
db = conn.cursor()

# ------- Standard practice to create a flask application -------- #
app = Flask(__name__)
app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'

mycursor = conn.cursor ( ) # NEW123

def coding(obj) :
    # Encryption of personal information before sending to database
    en_key = b'l3FSJdFAhlk6dgV57ELV04bIzgMr1-yjxjTb9TfYwUM='
    f = Fernet ( en_key )
    return f.encrypt ( obj.encode ( ) )


# setting up client to server views, each view is connected to and HTML page
@app.route("/")
def base():
    return render_template("index.html")


@app.route("/homepage")
def hompage():
    return render_template("homepage.html")

# ---- Sign up ------ #
@app.route("/signup", methods=['GET', 'POST'])
def signup():
    '''  Sign Up  '''

    ### functions within sign up ###
    def minor(birthdate):
        '''User under 16 need parental consent under GDPR (Source: Jalli, nd)'''
        today = date.today()  # Get today's date object
        # check if before or after birthday (before, addon =0; after, addon =1)
        if (today.month, today.day) < (birthdate.month, birthdate.day):
            addon =0
        # else:
        addon =1

        year_diff = today.year - birthdate.year # check diff in year
        age = year_diff + addon # calculating age
        if age<16:
            print("Sorry, parental consent for person age below 16, please contact our data protection officer (fg@minaz.nl), Goodbye.")
            flash('Sorry, parental consent for person age below 16, please contact our data protection officer (fg@minaz.nl), Goodbye.', category='error')
            print('failed')
            return render_template('index.html')
        # else:
        print("age valid")
        return 'succ'

    def signup_otp(username):
        '''Generating OTP for 2FA (Source: NeuralNine, nd)'''
        skey=pyotp.random_base32() #  to generate a random secret key for this new user
        timeotp = pyotp.TOTP(skey) #  to apply the key in TOTP
        new_onetimepass = timeotp.now() #  to generate the one time password
        print("[Display for testing only:] The OTP is: ",new_onetimepass) # testing only

        # Pre-set time interval for generating a new OTP is 30s
        uri = pyotp.totp.TOTP(skey).provisioning_uri(name=username,
                                                   issuer_name="Dutch Cyber Crime Reporting App"
                                                   ) # generate QR code seed
        qrcode.make(uri).save("popt1.png") # convert code seed to QR code as popt1.png
        shutil.copy('popt1.png','./static/popt1.png') # NEW230410-0125
        # shutil.copy(origin+file_name, target+file_name) # NEW230410-0125
        # img = Image.open("popt1.png") # NEW230410-0125
        # img.show() # NEW230410-0125
        return(new_onetimepass,skey)

    def verify_otp(otp, signup_otp):
        '''Verifying OTP for 2FA (Source: NeuralNine, nd)'''
        if otp == signup_otp:
            print("Result: Verified")
            return "Correct"
        #else:
        flash('Sorry, incorrect OTP. Please try again.', category='error')
        return "Wrong"

    def coding(obj):
        '''Encryption of persaonl information before sending to database'''
        en_key = b'l3FSJdFAhlk6dgV57ELV04bIzgMr1-yjxjTb9TfYwUM='
        fern = Fernet(en_key)              # value of key is assigned to a variable
        return(fern.encrypt(obj.encode())) # the plaintext is converted to ciphertext

    def create_record(new_uid2,username,lastname, firstname, email_address, mobile, dob, password):
        ''' Create record in database '''
        en_lastname = coding(lastname) # personal data are encrypted before transfer to database
        en_firstname = coding(firstname)
        en_email = coding(email_address)
        en_mobile = coding(mobile)
        en_dob = coding(dob)
        en_pwd = coding(password)
        timestamp = date.today() # unix_today = int(time.mktime(today.timetuple()))
        today = timestamp

        conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
        newusers= (new_uid2, username, en_lastname, en_firstname, en_email, en_mobile, en_dob, en_pwd, "secretkey","public",today, today,1)
        sqlr = "INSERT INTO users (user_id, login_name, surname, forename, email, mobile_no, date_of_birth, password, secret_key, role_id, date_activated, date_added, active_flag) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        cur_record = conn.cursor()
        cur_record.execute(sqlr, newusers)

        conn.commit()
        conn.close()
        return cur_record.lastrowid

    def update_record(new_uid1, secret_key1):
        ''' Update record in database '''
        en_secretkey = coding(secret_key1)
        sqlu = "UPDATE Users SET secret_key = %s WHERE user_id = %s "
        data = (en_secretkey, new_uid1)

        #conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
        cur_update = conn.cursor()
        cur_update.execute(sqlu,data)
        conn.commit()
        print(new_uid1, "updated")
        return cur_update.lastrowid

    def delete_record(new_uid2):
        ''' Delete record in database '''
        #conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
        cur_delete = conn.cursor()
        cur_delete.execute("DELETE from Users WHERE user_id = %s ",[new_uid2])
        conn.commit()
        cur_delete.close()
        print(new_uid2, " deleted")

    #def log(uid,activity,status): # Log for reference
    #   with conn:
    #       activity_1= (datetime.now(),uid,activity,status)
    #       sqlc = "INSERT INTO System_log (datetime,user_id, activity,status) VALUES(%s,%s,%s,%s)"
    #       curlog = conn.cursor()
    #       curlog.execute(sqlc, activity_1)
    #       conn.commit()
    #       return curlog.lastrowid

    ### Sign up Main ###
    if request.method == 'POST':
        try:
            username = request.form['uname']
            firstname = request.form['fname']
            lastname = request.form['lname']
            email_address = request.form['email']
            mobile = request.form['mobile']
            dob = request.form['dob']
            password = request.form['pwd1']
            password2 = request.form['pwd2']

            if password != password2: # Enter password twice, compare the 2 enterings
                flash('Sorry, not the same password. Please try again.', category='error')
                print('Sorry, not the same password. Please try again.')
                return render_template("signup.html")

            # check if user already exist
            newcur = conn.cursor()
            newcur.execute("SELECT login_name, user_id FROM Users WHERE login_name = '"+ username +"' ") # Search from db
            matchuser = newcur.fetchone()

            if matchuser != None: # username exist
                print(username, "already exist.")
                flash('Username already exist, please try again.', category='error')
                print('failed')
                # log(matched_id,"Create failed: user already exist", "failed")
                return render_template('signup.html')
            else: # username not exist
                global new_uid
                cur_max= conn.cursor()
                cur_max.execute("select max(user_id) from Users ")
                max_result = cur_max.fetchone() # assign user_id of the new user from the system
                maxid = int(max_result[0])
                new_uid = str(maxid+1)
                print("new uid",new_uid)

                # check age
                global notp, secret_key
                user_dob = date(int(dob[0:4]), int(dob[5:7]), int(dob[8:10]))
                age_res = minor(user_dob) # age under 16 need perental consent
                if age_res == 'succ':
                    create_record(new_uid,username,lastname, firstname, email_address, mobile, dob, password)
                    generated_otp = signup_otp(username)
                    notp = generated_otp[0]
                    secret_key = generated_otp[1]
                    return render_template('signupotp1.html')
                # log("New user","Create failed: parental consent required", "failed")
                print("failed")

        except: # running otp for signup
            new_otp = request.form['signup_otp']
            otp_res = verify_otp(notp, new_otp)
            if otp_res == "Correct":
                update_record(new_uid, secret_key)
                # log(new_uid,"Create success", "succes")
                print("post : user => ", new_uid)
                return redirect(url_for('logout'))
            # log("New user","Create failed: incorrect OTP", "failed")
            delete_record(new_uid)

    return render_template("signup.html")

# ---- Display user terms of consent-------- #
@app.route("/ur_consent", methods=['GET', 'POST'])
def ur_consent():
    return render_template("ur_consent.html")

# -- display how to request update and erase personal data and withdraw consent --- #
@app.route('/ur_rights', methods=['GET', 'POST'])
def ur_rights():
   return render_template('ur_rights.html')

# ---------------- Log in  ----------------- #
@app.route("/login", methods=['GET', 'POST'])
def logins():
    ''' Log in '''

    ### functions within login ###
    def decoding(en_obj):
        '''decryption of encrypted persaonl data before use'''
        en_key = b'l3FSJdFAhlk6dgV57ELV04bIzgMr1-yjxjTb9TfYwUM='
        fernet = Fernet(en_key)
        return(fernet.decrypt(en_obj).decode())

    def login_otp(cuser,skey):
        ''' Generating OTP for 2FA (Source: NeuralNine, nd) '''
        timeotp =pyotp.TOTP(decoding(skey))
        onetimepass = timeotp.now()
        print(cuser,", the OPT is: ", onetimepass)
        return onetimepass

    def verify_otp(gotp, your_otp): #  NEW
        ''' Verifying OTP, valid for 30 seconds (Source: NeuralNine, nd) '''
        if gotp == your_otp:
            print("Result: Verified")
            return "Correct"
        flash('Sorry, incorrect OTP. Please try again.', category='error')
        return "Wrong"

    # def log(id,activity,status): # Log for ref only
    #   with conn:
    #       now = datetime.now()
    #       activity_2= (datetime.now(),id,activity,status)
    #       sqlc = "INSERT INTO System_log (datetime,user_id, activity,status) VALUES(%s,%s,%s,%s)"
    #       curlog = conn.cursor()
    #       curlog.execute(sqlc, activity_2)
    #       conn.commit()
    #       return curlog.lastrowid

    class CURRENT_USERS: # Defining current users as a class
        ''' Define current users '''
        def __init__(self, user_id, login_name, password, secret_key, role_id):
            self.user_id = user_id
            self.login_name = login_name
            self.password = password
            self.secret_key = secret_key
            self.role_id = role_id
        def depassword(self):
            ''' decode password for comparison '''
            try:
                return decoding(self.password)
            except:
                flash('Incorrect username or password, try again, thanks.', category='error')
                print('failed')
                return render_template('login.html')

    ### Login Main ###
    db1 = conn.cursor()
    if request.method == 'POST' :
        try: # Check if user exist - exist
            username = request.form['username'] # User enter username and password upon login
            password = request.form['password']
            db1.execute("SELECT user_id, login_name, password, secret_key,role_id FROM users WHERE login_name = '"+username+"' ")
            user = db1.fetchone()
            try:
                global gotp, cuser
                cuser=CURRENT_USERS(user[0],user[1],user[2],user[3],user[4]) # Current user
                if cuser.depassword() == password: # Verifying user password
                    print('succs and switch to otp')
                    gotp = login_otp(cuser.login_name, cuser.secret_key) # 2FA: generate OTP
                    return render_template('loginotp1.html')
                flash('Incorrect password, try again.', category='error') # Incorrect password
                print('failed')
                # log(cuser.user_id,"Login failed: incorrect password", "failed")
                return render_template('login.html')

            except: # Check if user exist - Non-exist
                flash('User not exist, try again.', category='error')
                print('Non-exist user, failed')
                # log("Non-exist user","Login failed: user not exist", "failed")
                return render_template('login.html')

        except: # 2FA
            your_otp = request.form['login_otp'] # User getenter OTP from google authenticator
            result = verify_otp(gotp, your_otp)
            session['login_name'] = cuser.login_name
            if result == "Correct": # Direct to differnt page based on user role (role-base)
                # log(cuser.user_id,"Login success", "success")
                if cuser.role_id == "public":
                    return redirect(url_for('reportv', title = cuser.login_name))
                elif cuser.role_id == "senior_officer" or cuser.role_id == "junior_officer":
                    return redirect(url_for('login_officer', title = cuser.login_name))
                elif cuser.role_id == "DPO":
                    return redirect(url_for('login_officer', title=cuser.login_name))
                elif cuser.role_id == "adm": # NEW
                    print("debug adm")
                    print(cuser.login_name)
                    return redirect(url_for('login_adm', title=cuser.login_name))
            elif result == "Wrong":
                # log(cuser.user_id,"Login failed: incorrect OTP", "failed")
                return render_template('login.html')

    return render_template('login.html')

@app.route("/login_officer.html", methods=['GET', 'POST'])
def login_officer():
   return render_template('login_officer.html')


@app.route("/login_adm.html", methods=['GET', 'POST'])
def login_adm():
   return render_template('login_adm.html')


# ------ Public users: create and view  --------- #
@app.route("/report-vulnerabilities", methods=['GET', 'POST'])
def reportv():
    ''' Public user's reporting '''

    # functions in Public user's module
    def create_case(get_uid,  type, domain_link): # create new case
        # get case id from system
        cur_maxcase= conn.cursor()
        cur_maxcase.execute("select max(case_id) from CaseHeader ")
        maxcase_result = cur_maxcase.fetchone() # assign sequential case id
        # maxcase = maxcase_result[0]
        new_caseid = int(maxcase_result[0])+1
        case_id = str(new_caseid)
        timestamp = date.today() # unix_today = int(time.mktime(today.timetuple()))
        today = timestamp

        with conn:
            newcase= (case_id, type,"start", get_uid, today,"to be determined" )
            sqlcase = "INSERT INTO CaseHeader (case_id,case_type,case_status, created_by, date_created, case_priority) VALUES(%s,%s,%s,%s,%s,%s)"
            cur_record = conn.cursor()
            cur_record.execute(sqlcase, newcase)
            print("case created")
            conn.commit()
            print("the case id sent fm create case id is:", case_id)
            return case_id

    def create_entry(newcaseid, get_uid, v_details): # create new entry
        # get entry id from system
        conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
        cur_maxentry= conn.cursor()
        cur_maxentry.execute("select max(entry_ref) from casedetail")
        maxentry_result = cur_maxentry.fetchone() # assign sequential entry ref
        maxentry = maxentry_result[0]
        new_entryid = int(maxentry)+1
        entry_ref = str(new_entryid)
        print("new case id carried fm create caes:", newcaseid)
        print("the new entry ref is:", entry_ref)
        timestamp = date.today()# unix_today = int(time.mktime(today.timetuple()))
        today = timestamp

        with conn:
            newentry= (newcaseid, entry_ref, get_uid,today, v_details , today )
            sqlentry = "INSERT INTO CaseDetail (case_id,entry_ref,entered_by,activity_datetime, activity_description,entry_datetime) VALUES(%s,%s,%s,%s,%s,%s)"
            cur_record = conn.cursor()
            cur_record.execute(sqlentry, newentry)
            print("entry created")
            conn.commit()
            return cur_record.lastrowid

    #def log(get_uid,activity,status): # for ref only
    #   with conn:
    #       activity_3= (datetime.now(),get_uid,activity,status)
    #       sqlc = "INSERT INTO System_log (datetime,user_id, activity,status) VALUES(%s,%s,%s,%s)"
    #       curlog = conn.cursor()
    #       curlog.execute(sqlc, activity_3)
    #       conn.commit()
    #       return curlog.lastrowid

    ### Report_v main
    login_name = session['login_name']
    print(login_name)
    if request.method == 'POST':
        type = request.form['type']
        data_time = request.form['dtg']
        domain_link = request.form['vweb']
        v_d = request.form['vd']
        v_s = request.form['vs']
        print(type, data_time, domain_link, v_d, v_s)

        newcur= conn.cursor()
        newcur.execute("SELECT login_name, user_id FROM Users WHERE login_name = '"+ login_name +"' ")
        get_user = newcur.fetchone()
        get_uid = get_user[1]
        conn.commit()

        newcaseid = create_case(get_uid, type, domain_link)
        print("newcaseid returned from create case is:", newcaseid)
        v_combine = v_d+v_s+domain_link
        new_entry = create_entry(newcaseid, get_uid, v_combine)
        print("The new entry is: ", new_entry)
        # log(get_uid,"Create new case","Success")
        print("Thank you for your reporting!")

        return render_template("reportv.html", title = login_name)

    return render_template("reportv.html", title = login_name)



# ------ Public users: view personal data  --------- #
@app.route("/userinfo")
def userinfo():
    '''Public users: view personal data'''
    def decoding(en_obj): # decryption
        en_key = b'l3FSJdFAhlk6dgV57ELV04bIzgMr1-yjxjTb9TfYwUM='
        fernet = Fernet(en_key)
        return(fernet.decrypt(en_obj).decode())

    ### userinfo main ###
    search_name = session['login_name']
    print("search name is :", search_name)
    #conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
    with conn:
        user_cur = conn.cursor()
        user_cur.execute("SELECT user_id, login_name, forename, surname, mobile_no, email, date_of_birth FROM Users WHERE login_name = '"+ search_name +"' ")
        search_user = user_cur.fetchone()

        user_id = search_user[0]
        login_name = search_user[1]
        first_name = decoding(search_user[2]) # decryping persaonal data, ready for display
        last_name = decoding(search_user[3])
        mobile_no = decoding(search_user[4])
        email = decoding(search_user[5])
        date_of_birth = decoding(search_user[6])

        uInfo = { # dict
             'user_id': user_id,
             'login_name': login_name,
             'first_name': first_name,
             'last_name': last_name,
             'mobile_no': mobile_no,
             'email' : email,
             'date_of_birth': date_of_birth
        }

        return render_template("userinfo.html", uInfo=uInfo)


# ------ Public users: view own cases  --------- #
@app.route("/usercase")
def usercase():
    '''Public users: view case data'''
    case_user = session['login_name']
    print("User retrive own case is:", case_user)
    conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
    with conn: # get user ID
        user_cur = conn.cursor()
        user_cur.execute("SELECT user_id FROM users WHERE login_name = '"+ case_user +"' ")
        case_uid = user_cur.fetchone()
        str_case_uid = str(case_uid[0])
        print("the uid of the user who retriving own cae is:", str_case_uid)

    conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
    with conn: # get case reported by this user
        case_cur = conn.cursor()
        sqla = "SELECT entered_by, case_id, entry_ref, activity_description, feedback, officer_id FROM casedetail WHERE entered_by = %s"
        print(sqla)
        case_cur.execute(sqla, [str_case_uid])
        desc = case_cur.description
        column_names = [col[0] for col in desc]
        data = [dict(zip(column_names, row)) for row in case_cur.fetchall()]
        case_cur.close()

        caseInfo = {}
        i = 1
        for case in data:
            print ("add information:", case)
            caseInfo[i] =case
            i=i+1
        print(caseInfo)

        return render_template("usercase.html", caseInfo=caseInfo)

# ------ Internal officers's module  --------- #
@app.route("/current-vulnerabilities")
def currentv():
    conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
    with conn: # View current reports
        currentv = conn.cursor()
        sqla = "SELECT case_id, case_type, case_priority, case_status, date_created, DomainLink FROM caseheader"
        currentv.execute(sqla)
        desc = currentv.description
        column_names = [col[0] for col in desc]
        data = [dict(zip(column_names, row)) for row in currentv.fetchall()]
        currentv.close()

        vulnerabilities = {}
        i = 1
        for vulnerability in data:
            print(vulnerability)
            vulnerabilities[i] =vulnerability 
            i=i+1
        print(vulnerabilities)

        return render_template("currentv.html", vulnerabilities=vulnerabilities)


# ------ Administrator's module  --------- #
@app.route("/admin")
def admin():
    sessionuser = session['login_name']
    return render_template("admin.html")


# --------  Session log out  ----------- #
@app.route("/logout", methods=['GET', 'POST'])
def logout():
    ''' Log out '''
    session['login_name'] = ""
    return render_template('logout.html')


# ----------------- Charles 3 - start ----------------- #
# Define the add_cases route
@app.route ( '/add_cases' , methods=['GET' , 'POST'] )
def add_cases_page(default_priority=None) :
    '''Officer users: add case data''' # NEW123
    add_case_user = session['login_name'] # NEW123
    print("User retrive own case is:", add_case_user)# NEW123
    conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
    with conn: # get user ID # NEW123
        user_cur = conn.cursor()# NEW123
        user_cur.execute("SELECT user_id FROM users WHERE login_name = '"+ add_case_user +"' ")# NEW123
        case_uid = user_cur.fetchone()# NEW123
        str_case_uid = str(case_uid[0])# NEW123
        print("the uid of the officer who add case is:", str_case_uid) # NEW123
        
    if request.method == 'POST' :
        # Get form data
        user_id = request.form['user_id']
        user_id = str_case_uid # NEW123
        case_type = request.form['case_type']
        assigned_officer = request.form['assigned_officer']
        activity_description = request.form['activity_description']
        feedback = request.form['feedback']
        investigation_note = request.form['investigation_note']

        # Retrieve the role_id associated with the selected user_id
        mycursor.execute ( "SELECT role_id FROM UserRoles WHERE role_id=(SELECT role_id FROM Users WHERE user_id=%s)" ,
                           (user_id ,) )
        role_id = mycursor.fetchone ( )[0]

        # Determine the access level based on the permissions associated with the role_id
        mycursor.execute ( "SELECT permissions FROM UserRoles WHERE role_id=%s" , (role_id ,) )
        permissions = mycursor.fetchone ( )[0]

        access_level = ""
        if permissions == "C" :
            access_level = "Create"
        elif permissions == "R" :
            access_level = "Read"
        elif permissions == "U" :
            access_level = "Update"
        elif permissions == "D" :
            access_level = "Delete"

        # Get the last case number in the database or use 1000 if there are no existing cases
        mycursor.execute ( "SELECT MAX(case_number) FROM CaseHeader" )
        last_case_number = mycursor.fetchone ( )[0]
        if last_case_number is None :
            last_case_number = 999

        # Generate a unique case ID
        case_number = last_case_number + 1
        case_id = str ( case_number ).zfill ( 8 )

        # Get the current date and time
        now = datetime.now ( )
        date_created = now.strftime ( '%Y-%m-%d %H:%M:%S' )

        # Insert data into CaseHeader table
        header_sql = "INSERT INTO CaseHeader (case_id,case_type,case_number,case_status,assigned_officer,created_by," \
                     "date_created) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        header_values = (case_id , case_type , case_number , "New" , assigned_officer , user_id , date_created)

        mycursor.execute ( header_sql , header_values )

        # Insert data into CaseDetail table
        detail_sql = "INSERT INTO CaseDetail (case_id, entry_ref, entered_by, officer_id, activity_datetime, " \
                     "activity_description,feedback,investigation_note,entry_datetime)VALUES (%s,%s,%s,%s, %s,%s, %s," \
                     " %s, %s)"
        detail_values = (
            case_id , "1" , assigned_officer , assigned_officer , date_created , activity_description , feedback ,
            investigation_note , date_created)

        mycursor.execute ( detail_sql , detail_values )

        # Commit the changes to the database
        conn.commit ( ) #NEW123

        return 'Case created successfully.'
    else :
        # Get list of officers from Users table
        mycursor.execute ( "SELECT user_id, login_name FROM Users" )
        officers = mycursor.fetchall ( )

        # Get list of case_types from CaseTypes table
        mycursor.execute ( "SELECT case_type, case_type_desc FROM CaseTypes" )
        case_types = mycursor.fetchall ( )

        return render_template('add_cases.html', officers=officers, case_types=case_types)


# Define a route for the create_staff URL
@app.route ( '/create_staff' , methods=['GET' , 'POST'] )
def create_staff_page():
    if request.method == 'POST' :
        try :
            username = request.form['uname']
            lastname = request.form['lname']
            firstname = request.form['fname']
            email_address = request.form['email']
            mobile = request.form['mobile']
            dob = request.form['dob']
            password = request.form['pwd1']
            confirm_password = request.form['pwd2']
            print("debug create staff")

            # Check if passwords match
            if password != confirm_password :
                flash ( "Passwords do not match. Please try again." , "error" )
                return redirect ( url_for ( "create_staff_page" ) )

            # Encrypt personal data before transfer to database
            en_lastname = coding ( lastname )
            en_firstname = coding ( firstname )
            en_email = coding ( email_address )
            en_mobile = coding ( mobile )
            en_dob = coding ( dob )
            en_pwd = coding ( password )

            # Get current date and calculate expiration date
            today = date.today ( )
            timestampexpiry = today + timedelta ( days=180 )

            # Create a connection to the MySQL database
            # mydb = db_connection.create_connection ( )

            # Create a cursor object to execute SQL statements
            mycursor = conn.cursor ( ) # NEW123

            # Create new user record
            new_user = (
                None ,
                username ,
                en_lastname ,
                en_firstname ,
                en_email ,
                en_mobile ,
                en_dob ,
                en_pwd ,
                "secretkey" ,
                "senior_officer" ,
                today ,
                today ,
                1
            )
            sql = "INSERT INTO users (user_id, login_name, surname, forename, email, mobile_no, date_of_birth, " \
                  "password, secret_key, role_id, date_activated, date_added, active_flag) VALUES (%s, %s, %s," \
                  "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            mycursor.execute ( sql , new_user )

            # Force password change on first login
            mycursor.execute ( "ALTER USER %s@'%%' PASSWORD EXPIRE" , (username ,) )

            # Commit changes and close connection
            conn.commit ( ) # NEW123
            conn.close ( ) # NEWE123

            flash ( "User created successfully." , "success" )
            return redirect ( url_for ( "create_staff_page" ) )

        except Exception as e :
            flash ( "Error creating user: {}".format ( e ) , "error" )
            return redirect ( url_for ( "create_staff_page" ) )

    return render_template ( 'create_staff.html' )


# Define a route for the update_users URL
@app.route ( '/manage_staff' , methods=['GET' , 'POST'] )
def update_user() :
    if request.method == 'POST' :
        # Get form data
        user_id = request.form['user_id']
        surname = request.form['surname']
        forename = request.form['forename']
        active_flag =  request.form['active_flag'] 
        email = request.form['email']
        mobile_no = request.form['mobile_no']
        date_of_birth = request.form['date_of_birth']

        # Set the anonymous flag
        anonymous = request.form.get ( 'anonymous' , 0 ) 

        # If anonymous flag is set, replace personal information with "Anonymous"
        if anonymous :
            surname = "Anonymous"
            forename = "Anonymous"
            email = "Anonymous"
            mobile_no = "0000000000"
            date_of_birth = None

        # If active flag is set to 0, set date_deactivated to current datetime
        if active_flag == 0 :
            now = datetime.now ( )
            date_deactivated = now.strftime ( '%Y-%m-%d %H:%M:%S' )
        else :
            date_deactivated = None

        # Update the user's information in the database
        sql = "UPDATE Users SET surname=%s, forename=%s, active_flag=%s, email=%s, mobile_no=%s, date_of_birth=%s, date_deactivated=%s WHERE user_id=%s"
        values = (surname , forename , active_flag , email , mobile_no , date_of_birth , date_deactivated , user_id)
        mycursor.execute ( sql , values )
        conn.commit ( ) # NEW123

        return 'User updated successfully.'
    else :
        # Get list of users from Users table
        mycursor.execute (
            "SELECT user_id, login_name, surname, forename, active_flag, email, mobile_no, date_of_birth, "
            "IF(active_flag = 1, NULL, date_deactivated) AS date_deactivated FROM Users" )
        users = mycursor.fetchall ( )

        return render_template ( 'user_management.html' , users=users )


# Define a route for the view_case_types URL
@app.route ( '/view_case_types' )
def view_case_types() :
    # Retrieve case types from the database
    mycursor.execute (
        "SELECT case_type, case_type_desc, treatment, default_priority FROM casetypes ORDER BY case_type" )
    case_types = mycursor.fetchall ( )

    # Wrap long text in the results to a limited width
    max_width = 20
    wrapped_results = []
    for row in case_types :
        wrapped_row = [textwrap.fill ( str ( cell ) , max_width ) for cell in row]
        wrapped_results.append ( wrapped_row )

    # Display the results as a table
    headers = ["Case Type" , "Description" , "Treatment" , "Default Priority"]
    table = tabulate ( wrapped_results , headers=headers , tablefmt="grid" )

    return Response ( table , content_type='text/plain; charset=utf-8' )


# Define a route for the view_cases URL
@app.route ( '/view_cases' )
def view_cases() :
    mycursor.execute ( """
        SELECT h.case_id, h.case_type, c.case_type_desc, c.treatment, 
            h.assigned_officer, h.case_status, d.entry_ref, 
            d.activity_description, d.activity_datetime, 
            d.investigation_note, d.feedback
        FROM caseheader h 
        INNER JOIN casedetail d ON h.case_id = d.case_id  
        LEFT OUTER JOIN casetypes c ON c.case_type = h.case_type;
    """ )

    # Fetch all rows from the result set
    results = mycursor.fetchall ( )

    # Wrap long text in the results to a limited width
    max_width = 20
    wrapped_results = []
    for row in results :
        wrapped_row = [textwrap.fill ( str ( cell ) , max_width ) for cell in row]
        wrapped_results.append ( wrapped_row )

    # Display the results as a table
    headers = ["Case ID" , "Case Type" , "Description" , "Treatment" , "Assigned Officer" , "Status" , "Entry Ref" ,
               "Activity Description" , "Activity Datetime" , "Investigation Note" , "Feedback"]
    table = tabulate ( wrapped_results , headers=headers , tablefmt="fancy_grid" )

    return Response ( table , content_type='text/plain; charset=utf-8' )


# Define a route for the database_activity URL
@app.route ( '/database_events' )
def database_activity() :
    # Execute the SHOW PROCESSLIST command
    mycursor.execute ( "SHOW PROCESSLIST" )

    # Fetch results
    results = mycursor.fetchall ( )

    # Wrap long text in the results to a limited width
    max_width = 20
    wrapped_results = []
    for row in results :
        wrapped_row = [textwrap.fill ( str ( cell ) , max_width ) for cell in row]
        wrapped_results.append ( wrapped_row )

    # Display the results as a table
    headers = ["Id", "User" , "Host" , "db" , "Command" , "Time" , "State" , "Info"]
    table = tabulate ( wrapped_results , headers=headers , tablefmt="fancy_grid" )

    return Response (table , content_type='text/plain; charset=utf-8' )


# Define a route for the view_events URL
@app.route ( '/view_events' )
def view_events() :
    # Create a cursor object
    mycursor = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")

    # Execute a SQL query to select data from the systemlog table
    mycursor.execute("SELECT activity_datetime, activity_type, table_changed, column_changed, old_value, new_value, changed_row_id FROM systemlog")

    # Fetch the results of the query
    results = mycursor.fetchall()

    # Wrap long text in the results to a limited width
    max_width = 20
    wrapped_results = []
    for row in results:
        wrapped_row = [textwrap.fill(str(cell), max_width) for cell in row]
        wrapped_results.append(wrapped_row)

    # Display the results as a table
    headers = ["Event Time", "Activity Type", "Table Changed", "Column Changed", "Old Value", "New Value", "Changed Row ID"]
    table = tabulate(wrapped_results, headers=headers, tablefmt="fancy_grid")

    # Return the table as a response
    return Response(table, content_type='text/plain; charset=utf-8')



# Define a route for the view_users URL
@app.route ( '/view_users' )
def view_users() :
    mycursor.execute ( """
        SELECT user_id, login_name, role_id, active_flag, date_activated, date_deactivated, 
        password_expiry, date_added FROM users;
    """ )

    # Fetch all rows from the result set
    results = mycursor.fetchall ( )

    # Wrap long text in the results to a limited width
    max_width = 20
    wrapped_results = []
    for row in results :
        wrapped_row = [textwrap.fill ( str ( cell ) , max_width ) for cell in row]
        wrapped_results.append ( wrapped_row )

    # Display the results as a table
    headers = ["user_id" , "login_name" , "role_id" , "active_flag" , "date_activated" , "date_deactivated" ,
               "password_expiry" , "date_added"]
    table = tabulate ( wrapped_results , headers=headers , tablefmt="fancy_grid" )

    return Response ( table , content_type='text/plain; charset=utf-8' )

# update cases
@app.route("/update_cases", methods=["POST"])
def update_case():
    # Get form data
    case_id = request.form["case_id"]
    activity_description = request.form["activity_description"]
    feedback = request.form["feedback"]
    investigation_note = request.form["investigation_note"]
    case_status = request.form["case_status"]
    case_type = request.form["case_type"]
    entered_by = request.form["entered_by"]
    officer_id = request.form["officer_id"]

    # Retrieve the maximum entry reference for the selected case ID
    mycursor.execute("SELECT MAX(entry_ref) FROM CaseDetail WHERE case_id=%s", (case_id,))
    max_entry_ref = mycursor.fetchone()[0]
    entry_ref = int(max_entry_ref) + 1 if max_entry_ref is not None else 1

    # Insert data into CaseDetail table
    detail_sql = "INSERT INTO CaseDetail (case_id, entry_ref, entered_by, officer_id, activity_datetime, " \
                 "activity_description, feedback, investigation_note, entry_datetime) VALUES (%s, %s, %s, %s, %s," \
                 " %s, %s ,%s,%s,)"
    detail_values = (case_id, entry_ref, entered_by, officer_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                     activity_description, feedback, investigation_note,
                     datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    mycursor.execute(detail_sql, detail_values)

    # Update the case status and case type
    update_sql = "UPDATE CaseHeader SET case_status=%s, case_type=%s WHERE case_id=%s"
    mycursor.execute(update_sql, (case_status, case_type, case_id))

    # Commit the changes to the database
    conn.commit() # NEW123

    # Retrieve the list of officers and case types for the form
    mycursor.execute("SELECT officer_id, officer_name FROM Officers")
    officers = mycursor.fetchall()

    mycursor.execute("SELECT case_type, case_type_desc, treatment FROM CaseTypes")
    case_types = mycursor.fetchall()

    # Render the update_cases.html template with the officers and case_types variables as context variables
    return render_template('update_cases.html', officers=officers, case_types=case_types)


# CK End
# ----------------- Charles 3 - end ----------------- #



# -------- standard practice to run flask server ---------- #
if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)



# Reference:
# NeuralNine (nd) Available from: https://www.youtube.com/watch?v=o0XZZkI69E8 [Accessed on 1 March 2023]
# Jalli A. (nd) Available from: https://www.codingem.com/how-to-calculate-age-in-python/ [Accessed on 29 March 2023]
# html => popip1 message of signup => for both succ and fail 2. back button of signup => should link to homepage instead of index


# -------- standard practice to run flask server ---------- #
if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)



# Reference:
# NeuralNine (nd) Available from: https://www.youtube.com/watch?v=o0XZZkI69E8 [Accessed on 1 March 2023]
# Jalli A. (nd) Available from: https://www.codingem.com/how-to-calculate-age-in-python/ [Accessed on 29 March 2023]
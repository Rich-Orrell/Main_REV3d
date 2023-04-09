from flask import Flask, request, render_template, redirect, url_for # For redirecting url
from flask import session               # For carrying variable from one function to another
from flask import Flask, render_template, request, flash # For interface
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
import itertools                        # Elsie: For generating table

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

# setting up client to server views, each view is connected to and HTML page
@app.route("/")
def base():
    return render_template("index.html")


@app.route("/homepage")
def hompage():
    return render_template("homepage.html")

# ---------------- Sign Up ----------------- #
@app.route("/signup", methods=['GET', 'POST'])
def signup():

    ### functions within sign up ###
    def minor(birthdate): # age calculator (Source: Jalli, nd). User under 16 need perental consent under GDPR
        today = date.today()  # Get today's date object
        # check if before or after birthday (before, addon =0; after, addon =1)
        if (today.month, today.day) < (birthdate.month, birthdate.day):
            addon =0
        else:
            addon =1
        year_diff = today.year - birthdate.year # check diff in year
        age = year_diff + addon # calculating age
        if age<16:
            print("Sorry, perental consent for person age below 16, please contact our data protection officer (fg@minaz.nl), Goodbye.")
            flash('Sorry, perental consent for person age below 16, please contact our data protection officer (fg@minaz.nl), Goodbye.', category='error')
            print('failed')
            return render_template('index.html')
        else:
            print("age valid")
            return('succ')

    def signup_otp(username):      # Generating OTP for 2FA (Source: NeuralNine, nd)
        skey=pyotp.random_base32() #  to generate a random secret key for this new user
        timeotp = pyotp.TOTP(skey) #  to apply the key in TOTP
        new_onetimepass = (timeotp.now()) #  to generate the one time password
        print("[Display for testing only:] The OTP is: ", new_onetimepass) # display for testing purpose
 
        # Pre-set time interval for generating a new OTP is 30s
        uri = pyotp.totp.TOTP(skey).provisioning_uri(name=username,
                                                   issuer_name="Dutch Cyber Crime Reporting App"
                                                   ) # generate QR code seed
        qrcode.make(uri).save("popt1.png") # convert the "code seed" to pictural QR code as potp1.png
        img = Image.open("popt1.png")      # open the image
        img.show()                         # show the image
        return(new_onetimepass,skey)

    def verify_otp(notp, signup_otp): # Verifying OTP for 2FA (Source: NeuralNine, nd)
        if notp == signup_otp:
            print("Result: Verified")
            return("Correct")
        else:
            flash('Sorry, incorrect OTP. Please try again.', category='error')
            return("Wrong")

    def coding(obj): # Encryption of persaonl information before sending to database
        en_key = b'l3FSJdFAhlk6dgV57ELV04bIzgMr1-yjxjTb9TfYwUM='
        f = Fernet(en_key)              # value of key is assigned to a variable
        return(f.encrypt(obj.encode())) # the plaintext is converted to ciphertext

    # Create record in database
    def create_record(new_uid,username,lastname, firstname, email_address, mobile, dob, password):
        en_lastname = coding(lastname) # personal data are encrypted before transfer to database
        en_firstname = coding(firstname)
        en_email = coding(email_address)
        en_mobile = coding(mobile)
        en_dob = coding(dob)
        en_pwd = coding(password)
        timestamp = date.today() # unix_today = int(time.mktime(today.timetuple()))
        today = timestamp
        timestampexpiry = today+timedelta(days=180)

        conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
        newusers= (new_uid, username, en_lastname, en_firstname, en_email, en_mobile, en_dob, en_pwd, "secretkey","public",today, today,1)
        sqlr = "INSERT INTO users (user_id, login_name, surname, forename, email, mobile_no, date_of_birth, password, secret_key, role_id, date_activated, date_added, active_flag) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        cur_record = conn.cursor()
        cur_record.execute(sqlr, newusers)
#OK     cur_record.execute("INSERT INTO users (user_id, login_name, surname, forename, email, mobile_no, date_of_birth, password, secret_key, role_id, date_activated, date_added, active_flag) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)" ,('1', 'Elsa123', 'Odl', 'Elsa', 'email of elsa', '+44-123-2323','encoded dob','encoded pwd', 'secret-key', 'public','20230101','20230101',1))

        print("record created 3")
        conn.commit()
        conn.close()
        return cur_record.lastrowid

    def update_record(new_uid1, secret_key1): # Update record in database
        en_secretkey = coding(secret_key1)
        sqlu = "UPDATE Users SET secret_key = %s WHERE user_id = %s "
        data = (en_secretkey, new_uid1)
        
        conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
        cur_update = conn.cursor()
        cur_update.execute(sqlu,data)
        conn.commit()
        print(new_uid1, "updated")
        return cur_update.lastrowid

    def delete_record(new_uid2): # Delete record in database
        conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
        cur_delete = conn.cursor()
        cur_delete.execute("DELETE from Users WHERE user_id = %s ",[new_uid2])
        conn.commit()
        cur_delete.close()
        print(new_uid2, " deleted")

    def log(id,activity,status): # Log for reference
        with conn:
           Activity_1= (datetime.now(),id,activity,status)
           sqlc = "INSERT INTO System_log (datetime,user_id, activity,status) VALUES(%s,%s,%s,%s)"
           curlog = conn.cursor()
           curlog.execute(sqlc, Activity_1)
           conn.commit()
           return curlog.lastrowid

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
            #allcur=conn.cursor()
            #allcur.execute("SELECT login_name, user_id, password FROM Users") # Search from db
            #alluser = allcur.fetchall()

            if matchuser != None: # username exist
                matched = (matchuser[0])
                print(username, "already exist.")
                flash('Username already exist, please try again.', category='error')
                matched_id = (matchuser[1])
                print('failed')
                # log(matched_id,"Create failed: user already exist", "failed") # db is used to generating log
                return render_template('signup.html')
            else: # username not exist
                global new_uid
                cur_max= conn.cursor()
                cur_max.execute("select max(user_id) from Users ")
                max_result = cur_max.fetchone() # assign user_id of the new user from the system
                max = max_result[0]
                max = int(max)
                new_uid = str(max+1)
                print("new uid",new_uid)
                
                # check age
                global notp, secret_key
                user_dob = date(int(dob[0:4]), int(dob[5:7]), int(dob[8:10]))
                age_res = minor(user_dob) # pass if age 16 or above, otherwise perental consent is required
                if age_res == 'succ':
                   create_record(new_uid,username,lastname, firstname, email_address, mobile, dob, password)
                   generated_otp = signup_otp(username)
                   notp = generated_otp[0]
                   secret_key = generated_otp[1]
                   return render_template('signupotp1.html')
                else:
                   # log("New user","Create failed: parental consent required", "failed")
                   print("failed")

        except: # running otp for signup
            new_otp = request.form['signup_otp']
            otp_res = verify_otp(notp, new_otp)
            if otp_res == "Correct":
                update_record(new_uid, secret_key)
                # log(new_uid,"Create success", "succes")
                print("post : user => ", new_uid)
                request.method == 'GET'
                return redirect(url_for('logout'))
            else:
                # log("New user","Create failed: incorrect OTP", "failed")
                delete_record(new_uid)
    
    return render_template("signup.html")

# ---- Display user terms of consent-------- #
@app.route("/ur_consent", methods=['GET', 'POST'])
def ur_consent():
    return render_template("ur_consent.html")

# -- display how to request update and erase personal data and withdraw consent --- #
@app.route('/ur_rights')
def ur_rights():
   return render_template('ur_rights.html')

# ---------------- Log in  ----------------- #
@app.route("/login", methods=['GET', 'POST'])
def logins():

    ### functions within login ###
    def decoding(en_obj): # decryption of encrypted persaonl data before use
        en_key = b'l3FSJdFAhlk6dgV57ELV04bIzgMr1-yjxjTb9TfYwUM='
        fernet = Fernet(en_key)
        return(fernet.decrypt(en_obj).decode())

    def login_otp(cuser,skey): # Generating OTP for 2FA (Source: NeuralNine, nd)
        timeotp =pyotp.TOTP(decoding(skey))
        onetimepass =(timeotp.now())
        print(cuser,", the OPT is: ", onetimepass)
        return(onetimepass)

    def verify_otp(gotp, your_ot): # Verifying OTP, Only 30 seconds to enter OTP, (Source: NeuralNine, nd)
        if gotp == your_otp:
            print("Result: Verified")
            return("Correct")
        else:
            flash('Sorry, incorrect OTP. Please try again.', category='error')
            return("Wrong")

    def log(id,activity,status): # Log for ref only
        with conn:
           now = datetime.now()
           Activity_2= (datetime.now(),id,activity,status)
           sqlc = "INSERT INTO System_log (datetime,user_id, activity,status) VALUES(%s,%s,%s,%s)"
           curlog = conn.cursor()
           curlog.execute(sqlc, Activity_2)
           conn.commit()
           return curlog.lastrowid

    class CURRENT_USERS: # Defining current users as a class
        def __init__(self, user_id, login_name, password, secret_key, role_id):
            self.user_id = user_id
            self.login_name = login_name
            self.password = password
            self.secret_key = secret_key
            self.role_id = role_id
        def depassword(self):
            try:
                return decoding(self.password)
            except:
                flash('Incorrect username or password, try again, thanks.', category='error')
                print('failed')
                return render_template('login.html') 
    
    ### Login Main ###
    db = conn.cursor()
    if request.method == 'POST' :
        try: # Check if user exist - exist
            username = request.form['username'] # User enter username and password upon login
            password = request.form['password']
            db.execute("SELECT user_id, login_name, password, secret_key,role_id FROM users WHERE login_name = '"+username+"' ")
            user = db.fetchone()
            try:
                global gotp, cuser
                cuser=CURRENT_USERS(user[0],user[1],user[2],user[3],user[4]) # Current user
                if cuser.depassword() == password: # Verifying user password
                    print('succs and switch to otp')
                    gotp = login_otp(cuser.login_name, cuser.secret_key) # 2FA: generating amd return OTP
                    return render_template('loginotp1.html')
                else:
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
                elif cuser.role_id == "senior_officer" or cuser.role_id == "junior_officer" or cuser.role_id == "DPO":
                    return render_template('login_officer.html', title = cuser.login_name)
                elif cuser.role_id == "DPO":
                    return render_template('login_officer.html', title=cuser.login_name)
                elif cuser.role_id == "admin":
                    return render_template('login_adm.html', title=cuser.login_name)
            elif result == "Wrong":
                # log(cuser.user_id,"Login failed: incorrect OTP", "failed")
                return render_template('login.html')

    return render_template('login.html')


# ------ Public users: create and view  --------- #
@app.route("/report-vulnerabilities", methods=['GET', 'POST'])
def reportv():

    # functions in Public user's module
    def create_case(get_uid, login_name, type, domain_link): # create new case
        # get case id from system
        cur_maxcase= conn.cursor()
        cur_maxcase.execute("select max(case_id) from CaseHeader ")
        maxcase_result = cur_maxcase.fetchone() # assign sequential case id 
        maxcase = maxcase_result[0]
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
            return(case_id)
        
    def create_entry(newcaseid, get_uid, login_name, v_d): # create new entry
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
            newentry= (newcaseid, entry_ref, get_uid,today, v_d , today )
            sqlentry = "INSERT INTO CaseDetail (case_id,entry_ref,entered_by,activity_datetime, activity_description,entry_datetime) VALUES(%s,%s,%s,%s,%s,%s)"
            cur_record = conn.cursor()
            cur_record.execute(sqlentry, newentry)
            print("entry created")
            conn.commit()
            return cur_record.lastrowid

    def log(get_uid,activity,status): # for ref only
        with conn:
           Activity_3= (datetime.now(),get_uid,activity,status)
           sqlc = "INSERT INTO System_log (datetime,user_id, activity,status) VALUES(%s,%s,%s,%s)"
           curlog = conn.cursor()
           curlog.execute(sqlc, Activity_3)
           conn.commit()
           return curlog.lastrowid

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

        newcaseid = create_case(get_uid,login_name, type, domain_link)
        print("newcaseid returned from create case is:", newcaseid)
        new_entry = create_entry(newcaseid, get_uid, login_name, v_d)
        # log(get_uid,"Create new case","Success")
        print("Thank you for your reporting!")

        return render_template("reportv.html", title = login_name)

    return render_template("reportv.html", title = login_name)


# ------ Public users: view personal data  --------- #
@app.route("/userinfo")
def userinfo():
    def decoding(en_obj): # decryption
        en_key = b'l3FSJdFAhlk6dgV57ELV04bIzgMr1-yjxjTb9TfYwUM='
        fernet = Fernet(en_key)
        return(fernet.decrypt(en_obj).decode())

    ### userinfo main ###
    search_name = session['login_name']
    print(search_name)
    conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
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
    case_user = session['login_name']
    print(case_user)
    conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
    with conn: # get user ID
       user_cur = conn.cursor()
       user_cur.execute("SELECT user_id FROM users WHERE login_name = '"+ case_user +"' ")
       case_uid = user_cur.fetchone()
       str_case_uid = str(case_uid[0])

    conn = mysql.connector.connect(host="uoe-cybercrime-app.mysql.database.azure.com", user="ro_admin", passwd="Abc!!!123", database="cybercrime_app")
    with conn: # get case reported by this user
        case_cur = conn.cursor()
        sqla = "SELECT entered_by, case_id, entry_ref, activity_description, feedback, officer_id FROM casedetail WHERE entered_by = %s"
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
    sessionuser = session['login_name']
    return render_template("currentv.html")


# ------ Administrator's module  --------- #
@app.route("/admin")
def admin():
    sessionuser = session['login_name']
    return render_template("admin.html")


# --------  Session log out  ----------- #
@app.route("/logout", methods=['GET', 'POST'])
def logout():
   session['login_name'] = ""
   return render_template('logout.html')


# -------- standard practice to run flask server ---------- #
if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)

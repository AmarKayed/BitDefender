from datetime import datetime, date, time
import os
import ipaddress
import urllib.parse
from functools import reduce


def parsare_log(linie):
    ok = 1
    for i in range(len(linie)):
        if (linie[i] == '(' or (linie[i] == '"' and linie[i - 1] == ' ') or linie[i] == '[') and ok == 1:
            ok = 0
        if ok == 0 and linie[i] == ' ' and linie[i - 3:i] != "GET" and linie[i - 4:i] != "POST":
            linie = linie[:i] + linie[i:].replace(" ", "_", 1)
        if (linie[i] == ')' or (linie[i] == '"' and linie[i + 1] == ' ') or linie[i] == ']') and ok == 0:
            ok = 1

    linie = linie.split()
    for i in range(len(linie)):
        linie[i] = linie[i].strip('"')

    try:
        int(linie[6])
        linie[6] = int(linie[6])
    except:
        pass
    try:
        linie[7] = int(linie[7])
    except:
        pass

    return linie

def date_time_analizer(dates, ip, first, last): #returneaza timpul mediu de asteptare intre loguri facute de un anumit ip
    nr = 1
    i = first
    d1 = datetime.fromisoformat(dates[i][0] + " " + dates[i][1] + dates[i][2])
    d2 = datetime.fromisoformat(dates[i + 1][0] + " " + dates[i + 1][1] + dates[i + 1][2])
    diferente = (d2 - d1)
    i += 1
    while i < last:
        if ip == IPs[i] and (status[i] >= 400 or status[i] < 300):
            j = i + 1
            while IPs[j] != IPs[i]:
               # print(i, j)
                j += 1
                if j == last - 1:
                    break
            if j == last - 1:
                break
            # if status[j] >= 400 or status[j] < 300:
            #     break
            d1 = datetime.fromisoformat(dates[i][0] + " " + dates[i][1] + dates[i][2])
            d2 = datetime.fromisoformat(dates[j][0] + " " + dates[j][1] + dates[j][2])
            diferente += (d2 - d1)
            nr += 1
            i = j - 1
        i += 1
    return (diferente / nr, nr)

def vulnerability_scan():#slab rau, incadreaza putin scanul, ia intervale de timp stabilite sau intervale de loguri (notita)
    bad_IPs = set()
    last = 25
    for first in range(len(logs_list) - 26):
        for i in IPs_distinct:
            try: #am o eroare pe care nu mi o explic fara acest try
                avg_time, nr = date_time_analizer(dates, i, first, last)
                errors = 0
                for j in range(len(status)):
                    if IPs[j] == i and status[j] >= 400:
                        errors += 1
                if errors/nr > 1/3 and avg_time.total_seconds() < 25:
                    bad_IPs.add(i)
            except:
                pass
        last += 1

    return bad_IPs

def waiting_next_request(index): #se da ca parametru un index si se cauta urmatorul requests cu acelasi ip, se va returna timpul scurs dintre aceste doua requesturi
    for i in range(index + 1, len(requests)):
        if IPs[i] == IPs[index]:
            k = datetime.fromisoformat(dates[i][0] + " " + dates[i][1] + dates[i][2]) - datetime.fromisoformat(dates[index][0] + " " + dates[index][1] + dates[index][2])
            return k.total_seconds()
    return 0


def brute_force_checker():#este posibil sa nu detecteze daca se fac mai multe bruteforceuri mici cu pauza intre ele (mici = mai putin de 100 de incercari)
    bad_IPs = list()
    for i in IPs_distinct:
        #o sa incerc pe cat posibil sa incadrez atacul cat mai bine intre first si last
        #vreau sa incep de la primul login care are timpul de asteptare mai mic decat cel mediu al ip neincadrat
        avg_time_neincadrat, numar_requests = date_time_analizer(dates, i, 0, len(dates) - 1)
        first = 0 #vreau prima incercare de login ---- (asta era ianinte de wait_net_request) dupa ultimul status de redirect sau de eroare ----
        # acum vreau primul login care are waiting_next_request mai mic decat media pt respectivul IP
        last = len(dates)
        ok_first = 0 #nu vreau sa am status 300+ in bruteforce, asa ca acest ok ne ajuta ca facem acest lucru
        #nu vreau sa iau in calcul requesturile lungi care au loc inainte sau dupa atacul propriu zis
        for j in range(len(requests)-1):
            if IPs[j] == i and "login" in requests[j] and ok_first == 0:
                first = j
                ok_first = 1
            if IPs[j] == i and "login" in requests[j] and ok_first == 1 and waiting_next_request(j) < avg_time_neincadrat.total_seconds():
                last = j
            if IPs[j] == i and ok_first == 1 and (status[j] >= 300 or (waiting_next_request(j) > avg_time_neincadrat.total_seconds() and last - first < numar_requests * (15/100))):
                #daca nu aveam chestia ai cu 15% imi gasea la sfarsit un request care are timp mare de asteptare inainte si imi punea acolo first ratand tot atacul
                ok_first = 0
                first = 0
        if first == 0 and last == len(dates): # in cazul in care cuvantul "login" nu apare in request
            for j in range(len(requests)-1):
                if IPs[j] == i and ok_first == 0:
                    first = j
                    ok_first = 1
                if IPs[j] == i and ok_first == 1 and (waiting_next_request(j) < avg_time_neincadrat.total_seconds() or last - first < numar_requests * (75/100)):
                    last = j
                if IPs[j] == i and ok_first == 1 and (status[j] >= 300 or (waiting_next_request(j) > avg_time_neincadrat.total_seconds() and last - first < numar_requests * (15 /100))):
                    ok_first = 0
                    first = 0
        #print(first, last)
        avg_time, nr = date_time_analizer(dates, i, first, last - 1)
        avg_time = avg_time.total_seconds()
        #print(avg_time, nr)
        if avg_time <= 3 and nr > 100 and avg_time > 0: #acel avg_time > 0 nu are sens in mod normal, dar la tocana.txt logurile nu sunt ordonate dupa timp(ca in mod normal)
            bad_IPs.append(i)
    return bad_IPs

def csrf():
    #ne dam seama din link daca e diferit de request
    csrf = dict()
    bad_links = list()
    for i in range(len(requests)):
        key = IPs[i] + ' ' + requests[i]
        if key not in csrf.keys():
            csrf[key] = set()
            csrf[key].add(links[i])
        else:
            csrf[key].add(links[i])

    #vrem ca linkurile sa nu fie sub "linkuri" (subpagini) ale aceluiasi site, vrem ca siteul sa fie diferit, deci linkul pe cat se poate mai diferit
    for i in csrf.keys():
        #print(i, csrf[i])
        if len(csrf[i]) > 1:
            nr = [-1,0]
            while nr[1] > nr[0]: #vedem cate caractere au in comun prefixurile linkurilor din set
                ok = 1
                lista_auxiliara = list(csrf[i])
                for j in range(len(lista_auxiliara) - 1):
                    if lista_auxiliara[j][:nr[1]] != lista_auxiliara[j + 1][:nr[1]]:
                        ok = 0
                        break
                if ok == 1:
                    nr[1] += 1
                nr[0] += 1

            if nr[1] < 10:#era mai simplu sa fac cu un csrf[i][:10] nu stiu ce a fost in capul meu
                auxiliar = i.split()[0]
                bad_links.append(auxiliar)

    return bad_links

def detect_xss_injection():
    xss_injection = list()       # lista va contine IP-urile impreuna cu request-urile in care se detecteaza xss injection
    for log in logs_list:
            # daca request-ul contine "script" sau tag-urile:
                        # "<" encoded -> "%3C"
                        # "</" encoded -> "%3C%2F"
                        # ">" encoded -> "%3E"
                        # (HTML): "&lt;" encoded -> "%26lt%3B"
                        # (HTML): "&gt;" encoded -> "%26gt%3B"
        if log[5].find("script") != -1 \
                or log[5].find("%3C") != -1 or log[5].find("%3E") != -1  or log[5].find("%3C%2F") != -1\
                or log[5].find("%26lt%3B") != -1 or log[5].find("%26gt%3B") != -1 :
            #print(log[5])       # log[5] este request-ul
            xss_injection.append((log[0], log[5]))  # se va adauga in lista perechea (IP, bad request)
    return xss_injection


def SQLi():
    detected_injections = []

    sqlWords = ['union select',
                'create table',
                'alter table',
                'drop table',
                'drop',  # For the case of a drop on the database
                'insert into',
                'update',
                'delete from',
                # 'union',            # The last two words are for the case in which there is something between union and select in the injection
                'union all',
                # 'select',
                'order by',
                'group by',
                'having'
                ]
    # I've commented the "union" and "select" keywords to avoid detecting inputs such as "select is my password" or "I love union".
    # If we want our code to be stricter, we can uncomment those two words.

    harmfulCharacters = ['\'', '\"']  # List of possible harmful characters that could cause an SQLi

    for i in logs_list:
        # print(i[5], end = '\n\n')

        url = i[5] = urllib.parse.unquote_plus(i[
                                                   5]).lower()  # We parse the log URL and make all of its characters lowecase such that we can match them with the sqlWords list

        # url = urllib.parse.unquote_plus(i[5]).lower()              # We parse the log URL and make all of its characters lowecase such that we can match them with the sqlWords list

        injection = url.split('?',
                              maxsplit=1)  # We extract the injection part of the URL by splitting the URL based on the character '?'

        if len(injection) == 1:  # This means we never had any ? in the url and hense no possbile injection could've been attempted
            continue  # Thus, we already know we have nothing else to do

        else:  # Else we will only take the part of the url that contains the actual request parameters, since we donot need the path.
            injection = injection[1]

        # print('Inainte de urllib.parse: ', injection)
        injection = urllib.parse.unquote_plus(injection)  # We parse the part of the injection
        # print('Dupa urllib.parse: ', injection)

        # Test 1: Harmful Characters

        # We first try to find any harmful characters

        continue_detecting = True  # Variable which determines whether we should proceed with all the tests if an injection has been detected early or not
        # This variables saves some time because if we detect an injection from the first test, then there is no point in running al the remaining tests

        for char in harmfulCharacters:  # For each harmfulCharacter
            if injection.count(
                    char) % 2 == 1 and '</script>' not in injection:  # If we find at least one harmful character for an odd number of times then there will be at the very least an SQL error, if not a possible SQL Injection.
                # print('HARMFUL CHARACTER: {}'.format(char) , injection, injection.count(char))
                detected_injections.append(
                    i)  # If we detected an injection, we append it to the detected_injections list
                continue_detecting = False  # We also stop running the other tests by changing the continue_detecting's value to False

        if continue_detecting == False:  # If we don't have to continue detecting
            continue  # Then we skip the remaining tests

        # Test 2: Comments

        if 'or' in injection and (
                '##' in injection or '--' in injection):  # If no harmful characters have been detected, then we start searching for comments in the injection

            indexBeforeOr = injection.find(
                'or') - 1  # indexBeforeOr == index before the index at which we find the first "or" word in our url

            if injection[indexBeforeOr] in ['\'', '\"']:  # We verify if we had ' or " before the "or" word from the URL
                detected_injections.append(
                    i)  # If we find harmful characters, then we append the log to the detected_injections list
                # print(url, end = '\n\n')                                      # We also print the url in the console

            # print(injection, end = '\n\n')
            # print(i, end = '\n\n')
            # equals = url.split('=')
            # print(equals, end = '\n\n')

        """
        SQLi with even number of harmful characters

        ' or id = ' union select 1, 2

        The first ' closes the id = '
        and the second ' cl


        """

        # Test 3: Removing URL Characters

        # If we didn't detect any harmful characters or if we only detected an even number of harmful characters
        # We will try to detect any SQL Words which could form an Injection:

        # We first remove the characters ?, ' and "
        for toBeRemovedCharcter in ['?', '\"', '\'']:
            injection = injection.replace(toBeRemovedCharcter, '')

        # Then we replace the characters = and & with a space
        for toBeReplacedCharacter in ['=', '&']:
            injection = injection.replace(toBeReplacedCharacter, ' ')

        # Test 4: Inline Comments

        # Then we must also consider the possibility of having inline comments:

        original = injection

        for j in range(len(injection)):
            if j + 1 < len(injection):
                if injection[j] in ['\\', '/'] and injection[j + 1] == '*':  # If we find the start of a comment
                    k = j + 2
                    if k + 1 < len(injection):
                        while injection[k] != '*' and injection[k + 1] not in ['\\',
                                                                               '/']:  # We calculate the range of the inline comment
                            k += 1
                    injection = injection[:j] + injection[k + 2:]  # And then we remove the inline comment,
                    # leaving the whole injection intact in the case we only
                    # have an inline comment without an actual SQL word
        #print(i[3], '\"{}\"'.format(original), injection)

        '''
        Example:
            ce/**/va will not be an SQLi
            while
            dr/*ceva aici*/op will be an SQLi

            ' UnIoN/**/SeLeCt 1, 2      will be an SQLi
        '''

        # Lastly, we remove any duplicate spaces that have formed as a result of removing = and &
        injection = injection.replace('  ', ' ')  # removing any duplicate spaces

        # Now our injection will look like this:
        # print(i[3], original, injection.split(' '), end = '\n\n')

        # If we find at least one SQL related word or combination of words then we consider it a valid injection

        # Test 5: SQL Words

        for word in sqlWords:
            startIndex = injection.find(word)
            if startIndex != -1:  # If we have detected an sqlWord in our injection
                if injection[startIndex + len(word)] in [' ', ''] and injection[startIndex - 1] in [' ',
                                                                                                    '']:  # And the sqlWord is isolated
                    detected_injections.append(i)  # Then it might cause an injection so we add it to the list
                    break
                    # Else, we simply ignore it

        '''
        Examples:
        "selecting drops" will not be considered an injection
        "text select" will be considered an injection
        "text selector now" will not be considered an injection

        '''

    # Included Tests:
    '''
    If Statement:
        ' union select if(1=1, 'true', 'false'), 2 #
    This injection will be detected due to the fact that it contains: ', union, select, union select and #

    '''

    print('\n\n\n\n\nDETECTED SQL INJECTIONS\n\n\n\n\n')

    print(*detected_injections, sep='\n\n', end='\n\n')

    print('Total injections: {}\n\n'.format(len(detected_injections)))

    return detected_injections


def file_inclusion(black_list, lfi_list, linie):
    if (linie[5].find("=") > 1):
        x = linie[5].find("=")
        for j in black_list:

            #substr = linie[5][x + 1:len(linie[5]) - 9]
            if (j in linie[5]):
                if (lfi_list == []):
                    lfi_list.append(linie[5][:x + 1])
                else:
                    if (linie[5][:x + 1] not in lfi_list):
                        lfi_list.append(linie[5][:x + 1])

                print(linie)

def log_poison(cnt, pos):
    if (pos.find("<?php") > 0):
        print("access.log poisoning: ")
        print(cnt)
        for k in logs_list[logs_list.index(cnt) + 1:]:
            if (k[5].find("access.log") > 1):
                print("Posibil web shell accesat dupa log poisoning")
                print(k)
    elif (pos.find("curl") > 0):
        print("log poisoning: ")
        print(cnt)
        for k in logs_list[logs_list.index(cnt) + 1:]:
            if (k[5].find("access.log") > 1):
                print("Posibil web shell accesat dupa log poisoning")
                print(k)


def LFI2(lfi_list, ip, index):
    x = logs_list.index(index)
    for i in lfi_list:
        for j in logs_list[x + 1:]:
            if (j[5].find(i) >= 0):
                print ("posibil atacator: ", ip, "** incercare file inclusion dupa upload", j)


def find_err(client, link, err_list):
    for i in err_list:
        ok = 0
        if (len(i) > 2 and i[2].find("client") > 0):
            x = i[2].find("_")
            ip = i[2][x + 1:len(i[2]) - 1]
            if (ip == client):
                ok = 1
        if (ok == 1):
            for j in i:
                string2 = "uri_" + '"' + link + '"'
                if (j.find(string2) > 0):
                    return 1
    return 0


def RFI(black_list2, linie, whitelist=[]):
    posit = linie[5].find("=")
    if (posit != -1):
        p = i[5][posit + 1:]
        x = p.find("/")
        posit2 = p[posit + 1:x]
        if (whitelist != []):
            for j in whitelist:
                if(p.find(j) != -1):
                    continue
        try:
            ipaddress.ip_address(posit2)
            print(linie)
        except:
            for k in black_list2:

                if (posit2[:len(k)] == k):
                    x = logs_list.index(linie) + 1
                    print(posit2)
                    print("Posibile siteuri incarcate de atacator: ")
                    while (x < len(logs_list) and logs_list[x][8].find(posit2) > 1):
                        print(logs_list[x][5])
                        x = x + 1

def upload(up_list, linie):

    for i in up_list:
        if linie[5].find(i) > 0 :
            if(find_err(linie[0],i, err_list) == 1):
                LFI2(lfi_list, linie[0], linie)

def Xpathi():

    Words = ['or','and','contain','node','position','child','find','1=1',"'1'='1","'1'='2","'a'='a",'div','class']

    detected_injections = []

    for i in logs_list:

        url = i[5] = urllib.parse.unquote_plus(i[5]).lower()
        injection = url.split('?',maxsplit=1)
        if len(injection) == 1:
            continue
        else:
            injection = injection[1]

        # print('Inainte de urllib.parse: ', injection)
        injection = urllib.parse.unquote_plus(injection)  # We parse the part of the injection
        #print('Dupa urllib.parse: ', injection)
        injection = injection.split('&')
        #print(injection)


        for x in injection:
            safe = True
            pos = x.find('=') + 1
            x = x[pos:]
            # print(x)
            # cazul in care se selecteaza un nod indica clar un xpath injection
            if x.find("//") == 0:
                # AICI ESTE INJECTION
                detected_injections.append(i)
                safe = False
                break

            if safe == False:
                continue
            # cazul in care se selecteaza atribute indica si el in xpath injection
            atribute_xpath = x.find('@')
            if atribute_xpath > 0 and x[atribute_xpath-1] == '[':
                # AICI ESTE INJECTION
                detected_injections.append(i)
                safe = False
                break

            if safe == False:
                continue
            # cazul in care gasim " 'something" indica si el un xpath injection
            something = x.find("'")
            if something > -1 and len(x[something + 1]) > 0 :
                # AICI ESTE INJECTION
                detected_injections.append(i)
                safe = False
                break

            if safe == False:
                continue
            # cazul in care gasim cuvinte specifice din sintaxa xpath
            for y in Words:
                index = x.find(y)
                if index != -1:
                    # AICI AVEM INJECTION
                    detected_injections.append(i)
                    safe = False

                if safe == False:
                    continue
                else:
                    break
    print('\n\n\n\n\nDETECTED XPATH INJECTIONS\n\n\n\n\n')
    print(*detected_injections, sep = '\n\n', end = '\n\n')
    print('Total injections: {}\n\n'.format(len(detected_injections)))

    return detected_injections



#-----------------------------------------------------------------------------------------------------------------------

f = open("sql.log", "r")
linie = f.readline()
logs_list = list()
while linie != "":
    ok = 1
    for i in range(len(linie)):
        if ((linie[i] == '"' and linie[i - 1] == ' ') or linie[i] == '[') and ok == 1:
            ok = 0
        if ok == 0 and linie[i] == ' ' and linie[i-3:i] != "GET" and linie[i-4:i] != "POST":
            linie = linie[:i] + linie[i:].replace(" ", "_", 1)
        if ((linie[i] == '"' and linie[i + 1] == ' ') or linie[i] == ']') and ok == 0:
            ok = 1

    logs_list.append(linie.split())
    linie = f.readline()

f.close()

f2 = open("error.log", "r")
linie2 = f2.readline()
err_list = list()



while linie2 != "":
    ok = 1
    for i in range(len(linie2)):
        if (linie2[i] == '(' or (linie2[i] == ' ' and linie2[i + 1] != '[') or linie2[i] == '[') and ok == 1:
            ok = 0
        if ok == 0 and linie2[i] == ' ' and linie2[i-1] != ']' and linie2[i-1] != ':' :
            linie2 = linie2[:i] + linie2[i:].replace(" ", "_", 1)
        if (linie2[i] == ')' or (linie2[i] == '"' and linie2[i + 1] == ' ') or linie2[i] == ']') and ok == 0:
            ok = 1

    err_list.append(linie2.split())
    linie2 = f2.readline()

f2.close()


for i in range(len(logs_list)):
    for j in range(len(logs_list[i])):
        logs_list[i][j] = logs_list[i][j].strip('"')

for i in range(len(logs_list)):
    try:
        int(logs_list[i][6])
        logs_list[i][6] = int(logs_list[i][6])
    except:
        pass
    try:
        logs_list[i][7] = int(logs_list[i][7])
    except:
        pass


# for i in logs_list:
#     print(i)

IPs = list()
IPs_distinct = list()
dates = list()
methods = list()
requests = list()
status = list()
size = list()
links = list()

for i in range(len(logs_list)):
    if logs_list[i][0] not in IPs_distinct:
        IPs_distinct.append(logs_list[i][0])
    IPs.append(logs_list[i][0])
    dates.append(logs_list[i][3])
    methods.append(logs_list[i][4])
    requests.append((logs_list[i][5]))
    status.append(logs_list[i][6])
    size.append(logs_list[i][7])
    links.append((logs_list[i][8]))

for i in range(len(dates)):
    dates[i] = dates[i].strip("[]")
    dates[i] = dates[i].replace(":", " ", 1)
    dates[i] = dates[i].replace("_", " ")
    dates[i] = dates[i].replace("/", "-")
    dates[i] = dates[i].split()
    dates[i][2] = dates[i][2][:3] + ':' + dates[i][2][3:]
    dates[i][0] = dates[i][0].replace("Ian", "01")
    dates[i][0] = dates[i][0].replace("Feb", "02")
    dates[i][0] = dates[i][0].replace("Mar", "03")
    dates[i][0] = dates[i][0].replace("Apr", "04")
    dates[i][0] = dates[i][0].replace("May", "05")
    dates[i][0] = dates[i][0].replace("Jun", "06")
    dates[i][0] = dates[i][0].replace("Jul", "07")
    dates[i][0] = dates[i][0].replace("Aug", "08")
    dates[i][0] = dates[i][0].replace("Sep", "09")
    dates[i][0] = dates[i][0].replace("Oct", "10")
    dates[i][0] = dates[i][0].replace("Nov", "11")
    dates[i][0] = dates[i][0].replace("Dec", "12")
    dates[i][0] = dates[i][0][-4:] + dates[i][0][2:5] + '-' + dates[i][0][:2]

#variabile pentru file_inclusion
black_list = ["/../", "../", "php://", "expect://", "zip://", "/var/", "/log/", "etc/passwd", ".htaccess", "/proc/", ".php.jpg", ".php;jpg", ".php;png", ".php.png"]

lfi_list = []

whitelist = []
black_list2 = ["www.", "http://", "https://"]
posit = 0
posit2 = ""


# print(dates)

up_list = ['/dvwa/vulnerabilities/upload/']
#citire file_inclusion

# print("Introdu paginile care permit upload: ")
# while True:
#     x = input()
#     if(x.lower() == "stop"):
#         break
#     else:
#         up_list.append(x)
# print("Introdu siteurile/linkurile la care serverul poate face referinta (pentru a nu le considera LFI): ")
# while True:
#     x = input()
#     if(x.lower() == "stop"):
#         break
#     else:
#         whitelist.append(x)
print("The following IPs tried a bruteforce attack:")
bruteforce = brute_force_checker()
for i in bruteforce:
    print(i)

print("The following IPs tried a Cross Site Request Forgery attack:")
csrf = set(csrf())
for i in csrf:
    print(i)

print("The following IPs tried a XSS attack:")
xss = detect_xss_injection()
for i in xss:
    print(i)

if len(SQLi()) == 0:
    Xpathi()

for i in logs_list:
    file_inclusion(black_list, lfi_list, i)
    RFI(black_list2, i)
    for m in i[9:]:
       log_poison(i, m)
    upload(up_list, i)
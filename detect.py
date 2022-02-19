from datetime import datetime, date, time


import os

stream = os.popen('sshpass -p owaspbwa scp root@192.168.0.105:/var/log/apache2/access.log /mnt/c/Users/amer2/Desktop/BitDefender')
# output = stream.readlines()
# print(output)


# sshpass -p owaspbwa scp root@192.168.0.105:/var/log/apache2/access.log /mnt/c/Users/amer2/Desktop/BitDefender

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
'''
def date_time_analizer(dates, ip): #returneaza timpul mediu de asteptare intre loguri facute de un anumit ip
    nr = 1
    i = 0
    d1 = datetime.fromisoformat(dates[i][0] + " " + dates[i][1] + dates[i][2])
    d2 = datetime.fromisoformat(dates[i + 1][0] + " " + dates[i + 1][1] + dates[i + 1][2])
    diferente = (d2 - d1)
    i = 1
    while i < len(dates):
        if ip == IPs[i] and (status[i] >= 400 or status[i] < 300):
            j = i + 1
            while IPs[j] != IPs[i]:
                j += 1
                if j == len(dates) - 1:
                    break
            if j == len(dates) - 1:
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

def vulnerability_scan():
    bad_IPs = list()
    for i in IPs:
        avg_time, nr = date_time_analizer(dates, i)
        errors = 0
        for j in range(len(status)):
            if IPs[j] == i and status[j] >= 400:
                errors += 1
        if errors/nr > 1/3 and avg_time.total_seconds() < 25:
            bad_IPs.append(i)

    return bad_IPs
'''



#-----------------------------------------------------------------------------------------------------------------------

f = open("access.log", "r")
linie = f.readline()
logs_list = list()

while linie != "":
    ok = 1
    for i in range(len(linie)):
        if (linie[i] == '(' or (linie[i] == '"' and linie[i - 1] == ' ') or linie[i] == '[') and ok == 1:
            ok = 0
        if ok == 0 and linie[i] == ' ' and linie[i-3:i] != "GET" and linie[i-4:i] != "POST":
            linie = linie[:i] + linie[i:].replace(" ", "_", 1)
        if (linie[i] == ')' or (linie[i] == '"' and linie[i + 1] == ' ') or linie[i] == ']') and ok == 0:
            ok = 1

    logs_list.append(linie.split())
    linie = f.readline()

f.close()

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


'''

IPs = list()
dates = list()
methods = list()
request = list()
status = list()
size = list()
links = list()

for i in range(len(logs_list)):
    IPs.append(logs_list[i][0])
    dates.append(logs_list[i][3])
    methods.append(logs_list[i][4])
    request.append((logs_list[i][5]))
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

# print(dates)



# d, n = date_time_analizer(dates, '192.168.1.115')
# t = time(0, 20)
# d = d.total_seconds() #!!!!!!!!!!!!!!!!!!!!!!
# k = datetime.fromisoformat(dates[2][0] + " " + dates[2][1] + dates[2][2])
# w = datetime.fromisoformat(dates[2][0] + " " + dates[2][1] + dates[2][2])
# print(k.time() > t)
# print(d > 0)

d, nr = date_time_analizer(dates, '192.168.1.109')
# print(d, nr)

'''




# --------------------------------------------------------------------------------De aici incepe codul meu  ---------------------------------------------------------------


# for i in logs_list:
#     print(i)



# print(*logs_list, sep = '\n\n')

# /dvwa/vulnerabilities/sqli/?id=%27or+1%3D1%3B+%23%23&Submit=Submit_HTTP/1.1

import urllib.parse

detected_injections = []

from functools import reduce

sqlWords = ['union select', 
            'create table', 
            'alter table', 
            'drop table', 
            'drop',             # for the case of a Drop on the database
            'insert into', 
            'update', 
            'delete from',
            'union',            # The last two words are for the case in which there is something between union and select in the injection
            'select'
            ]

harmfulCharacters = ['\'', '\"']

for i in logs_list:
    
    url = i[5] = urllib.parse.unquote_plus(i[5]).lower()

    # print(i[5], end = '\n\n')
    
    # path, injection, version = url.rsplit('/', maxsplit = 2)

    injection = url.split('?', maxsplit = 1)

    if len(injection) == 1:       # This means we never had any ? in the url and hense no possbile injection could've been attempted
        continue
    else:                   # Else we will only take the part of the url that contains the actual request parameters, since we donot need the path.
        injection = injection[1]
    
    
    injection = urllib.parse.unquote_plus(injection)
    # We first try to find any harmful characters

    # print(injection, end = '\n\n')
    
    
    continue_detecting = True       # Determine whether we should proceed with all the tests if an injection has been detected early

    for char in harmfulCharacters:
        if injection.count(char)%2 == 1 :           # if we find at least one harmful character for an odd number of times then there will be at the very least an SQL error, if not a possible SQL Injection.
            # print('HARMFUL CHARACTER: {}'.format(char) , injection, injection.count(char))
            detected_injections.append(i)
            continue_detecting = False
    
    if continue_detecting == False:
        continue
            
    
    if 'or' in injection and ('##' in injection or '--' in injection):
        
        indexBeforeOr = injection.find('or') - 1                # indexBeforeOr == index before the index at which we find the first "or" word in our url
        
        if injection[indexBeforeOr] in ['\'', '\"']:            # We verify if we had ' or "" before the or parameter from the URL
            detected_injections.append(i)                       # If we find harmful characters, then we append the log to the detected_injections list
            # print(url, end = '\n\n')                            # We also print the url in the console
        
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
    

    
    # If we didn't detect any harmful characters or if we only detected an even number of harmful characters
    # We will try to detect any SQL Words which could form an Injection:

    # We first remove the characters ?, ' and "
    for toBeRemovedCharcter in ['?', '\"', '\'']:
        injection = injection.replace(toBeRemovedCharcter, '')

    # Then we replace the characters = and & with a space
    for toBeReplacedCharacter in ['=', '&']:
        injection = injection.replace(toBeReplacedCharacter, ' ')
    # Then we must also consider the possibility of having inline comments:
    
    original = injection
    
    for j in range(len(injection)):
        if j+1 < len(injection):
            if injection[j] in ['\\', '/'] and injection[j+1] == '*':
                k = j+2
                if k+1 < len(injection):
                    while injection[k] != '*' and injection[k+1] not in ['\\', '/']:
                        k +=1
                injection = injection[:j] + injection[k+2:]
    print(i[3], '\"{}\"'.format(original), injection)

 
    # Lastly, we remove any duplicate spaces that have formed as a result of removing = and &
    injection = injection.replace('  ', ' ')            # removing any duplicate spaces
    
    # Now our injection will look like this:
    # print(i[3], original, injection.split(' '), end = '\n\n')

    # If we find at least one SQL related word or combination of words then we consider it a valid injection
    """ 
        injectionWords = injection.split(' ')

        # We combine union with select if it exists such that we get 'union select'
        for j in range(len(injectionWords)):
            if injectionWords[j] == 'union' and j + 1 < len(injectionWords):
                injectionWords[j] = injectionWords[j] + ' ' + injectionWords[j+1]
                # injectionWords.pop(j+1)   # Now that we've combined the two elements, there is no need to keep the next element

        for word in injectionWords:
            if word in sqlWords:
                detected_injections.append(i)
                break
    """
    for word in sqlWords:
        if injection.find(word) != -1:
            detected_injections.append(i)
            break
            
    

# test = list(range(10))
test = [x for x in range(10) if x % 2 == 0]
# print('aici', reduce(lambda x, y: x and y, list((map(lambda x: x%2 == 0, test)))))

# x = logs_list[0][5]
# print(x.lower())
"""     
x = logs_list[-1][5]

path, injection, version = x.rsplit('/', maxsplit = 2)

injection = urllib.parse.unquote_plus(injection)

print(x, injection, sep = '\n')

 """
 # print("ceva", "altceva", end = ' ')

# print(*detected_injections, sep = '\n\n')


print('\n\n\n\n\nDETECTED INJECTIONS\n\n\n\n\n')

print(*detected_injections, sep = '\n\n', end = '\n\n')

print('Total injections: {}\n\n'.format(len(detected_injections)))
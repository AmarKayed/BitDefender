import os
from datetime import datetime, date, time


# Setup:
# stream = os.popen('sshpass -p owaspbwa scp root@192.168.0.105:/var/log/apache2/access.log /mnt/c/Users/amer2/Desktop/BitDefender')
stream = os.popen('sshpass -p owaspbwa scp root@192.168.56.101:/var/log/apache2/access.log /mnt/c/Users/amer2/Desktop/BitDefender')
# sshpass -p owaspbwa scp root@192.168.0.105:/var/log/apache2/access.log /mnt/c/Users/amer2/Desktop/BitDefender
# sshpass -p owaspbwa scp root@192.168.56.101:/var/log/apache2/access.log /mnt/c/Users/amer2/Desktop/BitDefender
# scp root@192.168.56.101:/var/log/apache2/access.log /mnt/c/Users/amer2/Desktop/BitDefender

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




# --------------------------------------------------------------------------------  De aici incepe codul meu  ---------------------------------------------------------------

import urllib.parse

from functools import reduce


def SQLi():
        

    detected_injections = []

    sqlWords = ['union select', 
                'create table', 
                'alter table', 
                'drop table', 
                'drop',             # For the case of a drop on the database
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

    harmfulCharacters = ['\'', '\"', ';']           # List of possible harmful characters that could cause an SQLi

    for i in logs_list:
        # print(i[5], end = '\n\n')
        
        url = i[5] = urllib.parse.unquote_plus(i[5]).lower()       # We parse the log URL and make all of its characters lowecase such that we can match them with the sqlWords list
        
        # url = urllib.parse.unquote_plus(i[5]).lower()              # We parse the log URL and make all of its characters lowecase such that we can match them with the sqlWords list


        injection = url.split('?', maxsplit = 1)            # We extract the injection part of the URL by splitting the URL based on the character '?'

        if len(injection) == 1:                             # This means we never had any ? in the url and hense no possbile injection could've been attempted
            continue                                        # Thus, we already know we have nothing else to do

        else:                                               # Else we will only take the part of the url that contains the actual request parameters, since we donot need the path.
            injection = injection[1]
        
        # print('Inainte de urllib.parse: ', injection)
        injection = urllib.parse.unquote_plus(injection)    # We parse the part of the injection
        # print('Dupa urllib.parse: ', injection)



# Test 1: Harmful Characters

        # We first try to find any harmful characters
        
        
        continue_detecting = True                           # Variable which determines whether we should proceed with all the tests if an injection has been detected early or not
                                                            # This variables saves some time because if we detect an injection from the first test, then there is no point in running al the remaining tests
        
        for char in harmfulCharacters:                      # For each harmfulCharacter
            if injection.count(char)%2 == 1 :               # If we find at least one harmful character for an odd number of times then there will be at the very least an SQL error, if not a possible SQL Injection.
                # print('HARMFUL CHARACTER: {}'.format(char) , injection, injection.count(char))
                detected_injections.append(i)               # If we detected an injection, we append it to the detected_injections list
                continue_detecting = False                  # We also stop running the other tests by changing the continue_detecting's value to False
        
        if continue_detecting == False:                     # If we don't have to continue detecting
            continue                                        # Then we skip the remaining tests
                

# Test 2: Comments

        if 'or' in injection and ('##' in injection or '--' in injection):      # If no harmful characters have been detected, then we start searching for comments in the injection
            
            indexBeforeOr = injection.find('or') - 1                            # indexBeforeOr == index before the index at which we find the first "or" word in our url
            
            if injection[indexBeforeOr] in ['\'', '\"']:                        # We verify if we had ' or " before the "or" word from the URL
                detected_injections.append(i)                                   # If we find harmful characters, then we append the log to the detected_injections list
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
            if j+1 < len(injection):
                if injection[j] in ['\\', '/'] and injection[j+1] == '*':           # If we find the start of a comment
                    k = j+2
                    if k+1 < len(injection):
                        while injection[k] != '*' and injection[k+1] not in ['\\', '/']:    # We calculate the range of the inline comment
                            k +=1
                    injection = injection[:j] + injection[k+2:]                         # And then we remove the inline comment, 
                                                                                        # leaving the whole injection intact in the case we only 
                                                                                        # have an inline comment without an actual SQL word
        print(i[3], '\"{}\"'.format(original), injection)


        '''
        Example:
            ce/**/va will not be an SQLi
            while
            dr/*ceva aici*/op will be an SQLi

            ' UnIoN/**/SeLeCt 1, 2      will be an SQLi
        '''

    
        # Lastly, we remove any duplicate spaces that have formed as a result of removing = and &
        injection = injection.replace('  ', ' ')            # removing any duplicate spaces
        
        # Now our injection will look like this:
        # print(i[3], original, injection.split(' '), end = '\n\n')

        # If we find at least one SQL related word or combination of words then we consider it a valid injection


# Test 5: SQL Words       


        for word in sqlWords:
            startIndex = injection.find(word)
            if startIndex != -1:                        # If we have detected an sqlWord in our injection
                if injection[startIndex + len(word)] in [' ', ''] and injection[startIndex - 1] in [' ', '']:       # And the sqlWord is isolated
                    detected_injections.append(i)       # Then it might cause an injection so we add it to the list
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


    print('\n\n\n\n\nDETECTED INJECTIONS\n\n\n\n\n')

    print(*detected_injections, sep = '\n\n', end = '\n\n')

    print('Total injections: {}\n\n'.format(len(detected_injections)))

    return detected_injections

SQLi()
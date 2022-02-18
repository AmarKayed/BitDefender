f = open("access.log", "r")
linie = f.readline()
logs_list = list()

while linie != "":
    ok = 1
    for i in range(len(linie)):
        if (linie[i] == '(' or (linie[i] == '"' and linie[i - 1] == ' ') or linie[i] == '[') and ok == 1:
            ok = 0
        if ok == 0 and linie[i] == ' ':
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
        int(logs_list[i][5])
        logs_list[i][5] = int(logs_list[i][5])
    except:
        pass
    try:
        logs_list[i][6] = int(logs_list[i][6])
    except:
        pass

for i in logs_list:
    print(i)


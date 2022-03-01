import os


# while True:
#     stream = os.popen('sshpass -p owaspbwa scp root@192.168.56.101:/var/log/apache2/access.log /mnt/c/Users/amer2/Desktop/BitDefender')



from subprocess import Popen, PIPE

argumente = 'sshpass -p owaspbwa scp root@192.168.56.101:/var/log/apache2/access.log /mnt/c/Users/amer2/Desktop/BitDefender'.split(' ')
print(argumente)

# process = Popen(['swfdump', '/tmp/filename.swf', '-d'], stdout=PIPE, stderr=PIPE)
# stdout, stderr = process.communicate()
process = Popen(argumente, stdout=PIPE, stderr=PIPE)
stdout, stderr = process.communicate()



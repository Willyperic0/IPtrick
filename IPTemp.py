import os
import threading

def search(ip_address):
    command = "ping -c 1 " + ip_address
    response= os.popen(command).read() #string
    if "1 received" in response:
        print("encontrado en: ",ip_address)
    #print(command)

for ip in range (1,254):
    current_ip="192.168.1."+str(ip)
    #print("analizando la ip: ",current_ip)
    
    run=threading.Thread(target=search , args=(current_ip,))
    run.start()
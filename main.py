#Author: TEAM CH
#Date: 30/12/2022
#Customer: computerzaak.nl

#Imported modules
from scapy.all import *
import logging
from datetime import datetime
from threading import Thread
import curses
import time
import os

#STORAGE
list = list()
data = {}
ip_list = {}

#  set log file for logging 
logging.basicConfig(filename='DosAttack.log', encoding='utf-8', level=logging.INFO)    

#First function to stop syn-flood attacks ==> detects tcp-syn packets.
def syn_flood(input_filter):
    capture = sniff(filter=input_filter, prn=lambda x: list.append(x.src), count = 1) 
    ip_list[capture[0].src] = capture[0][IP].src
    
    

#Second function to intercept false request packets which are not matching our requirements.
def false_request(input_filter):
    capture = sniff(filter=input_filter, count = 1)
    load = 0
    mac = 0
    for i in capture: 
        try:
            load = i[1]["Raw"].load
            mac = i.src
        except:
            False

    if load != 0:
        if not load.startswith(b'GET') or  not load.startswith(b'POST'):
            list.append(mac)
            ip_list[capture[0].src] = capture[0][IP].src
    
#Third function which recognise server 400 error message ==> Made for packets which are set up correct.
def error_output_server(input_filter):
    capture = sniff(filter=input_filter, count = 1)

    load = 0
    mac = 0
    for i in capture: 
        try:
            load = i[1]["Raw"].load
            mac = i.dst
        except:
            False
    if load != 0:
        if load.startswith(b'HTTP/1.1 400 Bad Request'):
            list.append(mac)
            ip_list[capture[0].src] = capture[0][IP].src
        

#Scan which is checking the storage constantly and maintening the "danger" counter.
def first_scan():
    for i in list:
            try:
                data[i]
            except:
                data[i] = 0
            if(data[i] != "BLOCKED"):
                data[i] = data[i] + 1

    #  beginning of printing 
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.addstr(0, 0, "Listening ... ")
    rule = 2

    for key, value in data.items():        
        if value != "BLOCKED": 
            if value > 200:
                   rule =  block(key, rule)
                   #Danger output message
            else:                
                stdscr.move(rule,0)
                stdscr.clrtoeol()
                stdscr.addstr(rule, 0, "[+] Source Mac: {0} :counter {1}".format(key ,value))
                rule += 1
    

#Function for blocking the mac address + starting timer
def block(key, rule):
    # os.system("sudo iptables -A INPUT -s "+ key +" -j DROP")
    os.system(f"sudo iptables -A INPUT -m mac --mac-source {key} -j DROP")
    data[key] = "BLOCKED"

    # enter the details into the log file
    logging.info(': '+ ip_list[key] +' :'+key+': is blocked on ' + str(datetime.now()))
    
    stdscr = curses.initscr()
    stdscr.move(rule,0)
    stdscr.deleteln()
    stdscr.addstr(rule, 0, "[+] Source Mac: {0} : BLOCKED".format(key ))
    Thread(target=blockTimer).start()
    rule += 1
    return rule

#Timeout function of blocking the mac adress
def blockTimer():
    # set the timer to 5 min
    t = 300
    stdscr = curses.initscr()
    stdscr.refresh()    
    while t != 0:        
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        stdscr.addstr(1,0, "Time for giving up the blocking {0}".format(timer))
        time.sleep(1)
        t -= 1    
    #  unblock all the ruless on the firewall
    # os.system("sudo iptables -D INPUT -m mac --mac-source "+ key +" -j DROP")
    os.system("sudo iptables -F")    
    for key, value in data.items():        
        if value == "BLOCKED": 
            data[key] = int(0)     
    stdscr.move(1,0)
    stdscr.clrtoeol()
    
    
#  timer for resetting the counter
def oneMinTimer():
    t = 60
    while t != 0:
        stdscr = curses.initscr()
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        stdscr.addstr(0,15, "Time for reset {0}".format(timer))
        time.sleep(1)        
        t -= 1    
    list.clear()
    for key, value in data.items():        
        if value != "BLOCKED": 
            data[key] = 0
    first_scan()
    oneMinTimer()

if __name__ == "__main__":
    user_input = input(f"[Computerzaak.nl] Start monitor press => f | For help press h ..." )
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    if user_input.lower() == "f":
        # Start message ==> Listening on ports
        stdscr.addstr(0, 0, "Listening ... ")        
        Thread(target=oneMinTimer).start()
        while(True):
            syn_flood("tcp[tcpflags] & (tcp-syn) == 2 and port 80 and dst 172.17.0.2")
            false_request("tcp[tcpflags] & (tcp-ack) != 0 and port 80 and dst 172.17.0.2")
            error_output_server("tcp[tcpflags] & (tcp-ack) != 0 and port 80 and src 172.17.0.2")
            first_scan()
    elif user_input.lower() == "h":
        print(f"[HELP MESSAGE]")
        stdscr.addstr(0, 0, "[HELP MESSAGE]")        
    else:
        stdscr.addstr(0, 0, "False input, try running the script again.")
        time.sleep(2)
        exit()
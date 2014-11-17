import time
from pprint import pprint
import json
import os
import sys
import socket
import subprocess
from subprocess import Popen
import requests
from collections import defaultdict
from urlparse import urlparse
from zapv2 import ZAPv2
import nmap
    
class AutoTester:
    
    #initialize the AutoTester object
    def __init__(self, host, seed):
        self.host = host
        self.seed = seed
        self.zap = ZAPv2()
        self.nm = nmap.PortScanner()
        self.alerts = {}
        self.subproc = None
        self.main_menu()
        
    #accepts user input to change the host and seed of the target
    def change_target(self):
        status = 500
        seed = None
        host = None
        self.alerts["nmap"] = None
        while status >= 400:
            seed = raw_input("\nEnter the URL of the web application you would like to begin testing:\n>")
            try:
                status = requests.get(seed).status_code
                host = urlparse(seed)[1]
                try:
                    socket.gethostbyname(host)
                except:
                    print "Error. Invalid host " + host
                    status = 500
                    continue
            except:
                status = 404
            if(status >= 400):
                print "Error. Couldn't connected to " + seed + "\nStatus code: " + str(status) + ""
        try:
            self.zap.core.new_session()
        except:
            pass
        try:
            del self.alerts["zap"]
        except:
            pass
        self.host = host
        self.seed = seed
        print "Target changed successfully!"
        raw_input("[Press Enter to continue]")
        
    #clear the screen
    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
    #restart the current stdout line
    def restart_line(self):
        sys.stdout.write("\r")
        sys.stdout.flush()
        
    #print a header for each screen
    def print_header(self):
        print "Host: " + self.host
        print "Seed: " + self.seed
        try:
            web_app_alerts = len(self.alerts["zap"].keys())
            print "Current # of web app alerts: " + str(web_app_alerts)
        except:
            print "Current # of web app alerts: 0"
        try:
            server_alerts = 0
            for port in self.alerts["nmap"]:
                server_alerts += len(self.alerts["nmap"][port])
            print "Current # of server alerts: " + str(server_alerts)
        except:
            print "Current # of server alerts: 0"
        header_length = len("Seed: " + self.seed)
        for i in range(0, header_length):
            sys.stdout.write("=")
        print("")
    
    #perform the ZAP penetration test to find web application vulnerabilities
    def zap_pentest(self):
        try:
            self.zap.core.new_session()
        except:
            pass
        self.clear()
        self.print_header()
        print "Beginning pentest setup of '" + self.seed + "'"
        print "Accessing target..."
        error_count = 0
        FNULL = open(os.devnull, "w")
        self.subproc = Popen(["bash", "ZAP_2.3.1/zap.sh"], stdout=FNULL)
        while True:
            try:
                self.zap.urlopen(self.seed)
                break
            except:
                if(error_count == 0):
                    print "Waiting for ZAP to initialize..."
                    error_count+=1
                    time.sleep(2)
        time.sleep(2)
        self.zap_crawl()
        print "Starting passive scanner..."
        time.sleep(5)
        print "Pentest setup completed\n"
        print "Scanning target..."
        self.zap_scan()
        print "Scan completed                    "
        print "Writing results to logs..."
        self.write_webapp_logs()
        print "Logfiles spider.log and webapp_alerts.log have been recorded"
        raw_input("[Press Enter to continue]")
    
    #crawl all of the web app's pages starting with the original URL seed
    def zap_crawl(self):
        print "Crawling subdirectories..."
        self.zap.spider.scan(self.seed)
        time.sleep(2)
        while(int(self.zap.spider.status) < 100):
            print "Spider progress: " + self.zap.spider.status + "%",
            self.restart_line()
            time.sleep(2)
        print "Crawling completed               "
    
    #perform the ZAP scan to get a list of alerts
    def zap_scan(self):
        self.zap.ascan.scan(self.seed)
        while (int(self.zap.ascan.status) < 100):
            print "Scan progress: " + self.zap.ascan.status + "%",
            self.restart_line()
            time.sleep(2)
        print "Sorting alerts..."
        zap_alerts = defaultdict(list)
        for alert in self.zap.core.alerts():
           zap_alerts[alert.get("alert")].append(alert)
        self.alerts["zap"] = zap_alerts

    #write the results of the web app alerts to logfiles
    def write_webapp_logs(self):
        with open("spider.log", "w") as fout:
            fout.write("Directories found under '" + self.seed + "'\n")
            for dir in self.zap.spider.results:
                fout.write(dir.encode("ascii") + "\n")
        with open("alerts.log", "w") as fout:
            fout.write("Alerts for '" + self.seed + "\n")
            for alert in self.zap.core.alerts():
                fout.write("{\n")
                fout.write("    alert: " + alert.get("alert").encode("ascii") + "\n")
                fout.write("    description: " + alert.get("description").encode("ascii") + "\n")
                fout.write("    risk: " + alert.get("risk").encode("ascii") + "\n")
                fout.write("    url: " + alert.get("url").encode("ascii") + "\n")
                fout.write("    param: " + alert.get("param").encode("ascii") + "\n")
                fout.write("    attack: " + alert.get("attack").encode("ascii") + "\n")
                fout.write("    evidence: " + alert.get("evidence").encode("ascii") + "\n")
                fout.write("    solution: " + alert.get("solution").encode("ascii") + "\n")
                fout.write("}\n")
        
    #perform the nmap penetration test to find server vulnerabilities
    def nmap_pentest(self):
        self.clear()
        self.print_header()
        print "Scanning host server for vulnerabilities..."
        self.nm.scan(hosts=self.host, arguments="--script vuln -sV")
        print "Scanning complete."
        port_alerts = defaultdict(list)
        print "Open ports:"
        for port in self.nm[self.host].all_tcp():
            print str(port) + ": " + self.nm[self.host]['tcp'][port]['name']
            if 'script' in self.nm[self.host]['tcp'][port]:
                for alert in self.nm[self.host]['tcp'][port]['script']:
                    port_alerts[port].append(alert)
        print ""
        for port in port_alerts:
            print "Alerts for port: " + str(port)
            for alert in port_alerts[port]:
                print alert
        self.alerts["nmap"] = port_alerts
        print "\nWriting results to logs..."
        self.write_server_logs()
        print "Logfile server.log has been recorded"
        raw_input("[Press Enter to continue]")
        
    #write the results of the web server alerts to logfiles
    def write_server_logs(self):
        with open("server.log", "w") as fout:
            fout.write("Server alerts for '" + self.host + "\n")
            for port in self.alerts["nmap"]:
                fout.write("Vulnerabilities on port " + str(port) + " (" + self.nm[self.host]['tcp'][port]['name'] + ")\n")
                for alert in self.nm[self.host]['tcp'][port]['script']:
                    fout.write("{\n")
                    fout.write(alert.encode("ascii") + "\n")
                    fout.write("}\n")
    
    #main menu of the program. user can perform scans and view alerts among other tasks here.
    def main_menu(self):
        choice = 0
        while choice is not "7":
            self.clear()
            self.print_header()
            print "///////////////////"
            print "    Main Menu"
            print "///////////////////"
            print "\nSelect the number of the option you would like to perform:"
            print "1. Find web application vulnerabilities"
            print "2. Find server vulnerabilities"
            print "3. View the spidered directory tree"
            print "4. View web app alerts"
            print "5. View server alerts"
            print "6. Change target"
            print "7. Quit"
            choice = raw_input(">")
            if choice == "1":
                self.zap_pentest()
            elif choice == "2":
                self.nmap_pentest()
            elif choice == "3":
                try:
                    dir_tree = self.zap.spider.results
                    for dir in dir_tree:
                        print dir.encode("ascii")
                except:
                    print "Nothing scanned."
                raw_input("[Press Enter to continue]")
            elif choice == "4":
                self.webapp_alerts_menu()
            elif choice == "5":
                self.server_alerts_menu()
            elif choice == "6":
                self.change_target()
                dir_tree = None
            elif choice == "7":
                if self.subproc is not None:
                    self.subproc.kill()
                sys.exit()
            else:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
                
    def webapp_alerts_menu(self):
        choice = 0
        try:
            self.alerts["zap"]
        except:
            self.alerts["zap"] = {}
        while choice is not "6":
            self.clear()
            self.print_header()
            print "////////////////////////////////"
            print "     Web Application Alerts"
            print "////////////////////////////////"
            print "\nSelect the number of the option you would like to perform:"
            print "1. View all alerts"
            print "2. View high priority alerts"
            print "3. View medium priority alerts"
            print "4. View low priority alerts"
            print "5. View informational alerts"
            print "6. Return to main menu"
            choice = raw_input(">")
            priority_list = defaultdict(list)
            if choice == "1":
                self.webapp_selection_menu(self.alerts["zap"], "All")
            elif choice == "2":
                for alert in self.alerts["zap"]:
                    if(self.alerts["zap"][alert][0].get("risk") == "High"):
                        priority_list[alert] = self.alerts["zap"][alert]
                self.webapp_selection_menu(priority_list, "High")
            elif choice == "3":
                for alert in self.alerts["zap"]:
                    if(self.alerts["zap"][alert][0].get("risk") == "Medium"):
                        priority_list[alert] = self.alerts["zap"][alert]
                self.webapp_selection_menu(priority_list, "Medium")
            elif choice == "4":
                for alert in self.alerts["zap"]:
                    if(self.alerts["zap"][alert][0].get("risk") == "Low"):
                        priority_list[alert] = self.alerts["zap"][alert]
                self.webapp_selection_menu(priority_list, "Low")
            elif choice == "5":
                for alert in self.alerts["zap"]:
                    if(self.alerts["zap"][alert][0].get("risk") == "Informational"):
                        priority_list[alert] = self.alerts["zap"][alert]
                self.webapp_selection_menu(priority_list, "Informational")
            elif choice == "6":
                break
            else:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
                
    def server_alerts_menu(self):
        choice = 0
        try:
            self.alerts["nmap"]
        except:
            self.alerts["nmap"] = {}
        server_alerts = 0
        for port in self.alerts["nmap"]:
            server_alerts += 1
        while choice < 1 or choice > server_alerts+1:
            self.clear()
            self.print_header()
            print "///////////////////////"
            print "     Server Alerts"
            print "///////////////////////"
            print "Total alerts: " + str(server_alerts)
            i = 0
            print "\nSelect the number of the port you would like to investigate:"
            for port in self.alerts["nmap"]:
                print str(i+1) + ". " + str(port) + " (" + self.nm[self.host]['tcp'][port]['name'] + ")"
                i+=1
            print "--------------------------------------------------\n" + str(i+1) + ". Return to main menu"
            choice = raw_input(">")
            try: 
                int(choice)
            except:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
                continue
            if choice == str(server_alerts+1):
                break
            elif choice != '' and int(choice) >= 1 and int(choice) <= server_alerts+1:
                self.server_selection_menu(self.alerts["nmap"].keys()[int(choice)-1])
            else:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
                
    def webapp_selection_menu(self, priority_list, priority):
        choice = 0
        while choice < 1 or choice > len(priority_list)+1:
            self.clear()
            self.print_header()
            print "///////////////////////////////////////////////////////"
            print "     Select a webapp alert (" + priority + ")"
            print "///////////////////////////////////////////////////////"
            print "Total alerts: " + str(len(priority_list))
            i = 0
            print "\nSelect the number of the alert you would like to investigate:"
            for alert in priority_list:
                print str(i+1) + ". " + alert +  " (Priority: " + priority_list[alert][0].get('risk') + ")"
                i+=1
            print "--------------------------------------------------\n" + str(i+1) + ". Return to alerts menu"
            choice = raw_input(">")
            try: 
                int(choice)
            except:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
                continue
            if choice == str(len(priority_list)+1):
                break
            elif choice != '' and int(choice) >= 1 and int(choice) <= len(priority_list)+1:
                self.webapp_choice_menu(priority_list[priority_list.keys()[int(choice)-1]])
            else:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
    
    def server_selection_menu(self, port):
        choice = 0
        server_alerts = len(self.nm[self.host]['tcp'][port]['script'])
        while choice < 1 or choice > server_alerts+1:
            self.clear()
            self.print_header()
            print "///////////////////////////////"
            print "     Select a server alert"
            print "///////////////////////////////"
            print "Total alerts: " + str(server_alerts)
            i = 0
            print "\nSelect the number of the alert you would like to investigate:"
            for alert in self.nm[self.host]['tcp'][port]['script']:
                print str(i+1) + ". " + alert
                i+=1
            print "--------------------------------------------------\n" + str(i+1) + ". Return to alerts menu"
            choice = raw_input(">")
            try:
                int(choice)
            except:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
                continue
            if choice == str(server_alerts+1):
                break
            elif choice != '' and int(choice) >= 1 and int(choice) <= server_alerts+1:
                self.server_choice_menu(self.nm[self.host]['tcp'][port]['script'][self.nm[self.host]['tcp'][port]['script'].keys()[int(choice)-1]])
            else:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
                
    def webapp_choice_menu(self, alert_info):
        description = alert_info[0].get("description")
        risk = alert_info[0].get("risk")
        solution = alert_info[0].get("solution")
        choice = 0
        while choice is not "2":
            self.clear()
            self.print_header()
            print "//////////////////////////////////////////////////////////"
            print "     " + alert_info[0].get("alert")
            print "//////////////////////////////////////////////////////////"
            print "\nDESCRIPTION:\n" + description + "\n"
            print "RISK:\n" + risk + "\n"
            print "SOLUTION:\n" + solution
            print "\nSelect the number of the option you would like to perform:"
            print "1. See all urls that have this alert"
            print "2. Return to alert list"
            choice = raw_input(">")
            if choice == "1":
                for alert in alert_info:
                    print alert.get("url")
                raw_input("[Press Enter to continue]")
            elif choice == "2":
                break
            else:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
                
    def server_choice_menu(self, alert_info):
        self.clear()
        self.print_header()
        print "//////////////////////////////////////////////////////////"
        print "     " + alert_info
        print "//////////////////////////////////////////////////////////"
        for item in alert_info:
            print item.encode("ascii")

#first screen of the program. the hostname of the target is entered here.
def startup():
    os.system('cls' if os.name == 'nt' else 'clear')
    print "              /////////////////////////////////////////"
    print "                       OWASP PEN TESTING TOOL          "
    print "                           (Working Title)             "
    print "              /////////////////////////////////////////"
    status = 500
    host = None
    seed = None
    while status >= 400:
        seed = raw_input("\nEnter the URL of the web application you would like to begin testing:\n>")
        try:
            status = requests.get(seed).status_code
            host = urlparse(seed)[1]
            try:
                socket.gethostbyname(host)
            except:
                print "Error. Invalid host " + host
                status = 500
                continue
        except:
            status = 404
        if(status >= 400):
            print "Error. Couldn't connected to " + seed + "\nStatus code: " + str(status) + ""
    autotester = AutoTester(host, seed)
    
startup()
                
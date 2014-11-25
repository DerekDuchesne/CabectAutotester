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
    def __init__(self):
        self.host = None
        self.seed = None
        self.zap = ZAPv2()
        self.nm = None
        self.alerts = {}
        self.dir_tree = None
        self.subproc = None
        self.startup()
        
    #first screen of the program. the hostname of the target is entered here.
    def startup(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print "              /////////////////////////////////////////"
        print "                       OWASP PEN TESTING TOOL          "
        print "                           (Working Title)             "
        print "              /////////////////////////////////////////"
        status = 500
        host = None
        seed = None
        while not self.set_target():
            pass
        self.main_menu()
        
    #accepts user input to change the host and seed of the target
    def set_target(self):
        seed = None
        host = None
        url_comp = None
        seed = raw_input("\nEnter the URL of the web application you would like to begin testing:\n>")
        try:
            url_comp = urlparse(seed)
            if url_comp[0] == "":
                seed = "http://" + seed
            else:
                seed = seed
            url_comp = urlparse(seed)
            status = requests.get(seed).status_code
            socket.gethostbyname(url_comp[1])
        except:
            status = 404
        if(status >= 400):
            print "Error. Couldn't connect to " + seed + "\nStatus code: " + str(status) + ""
            return False
        try:
            self.zap.core.new_session()
        except:
            pass
        self.nm = None
        self.dir_tree = None
        self.host = url_comp[1]
        self.seed = seed
        self.zap = ZAPv2()
        self.alerts = {}
        print "Target set successfully!"
        raw_input("[Press Enter to continue]")
        return True
        
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
            for protocol in self.nm[self.host].all_protocols():
                for port in self.nm[self.host][protocol]:
                    if 'script' in self.nm[self.host][protocol][port]:
                        server_alerts += len(self.nm[self.host][protocol][port]['script'])
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
        if self.subproc is None:
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
        print "Waiting for passive scanner..."
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
        self.dir_tree = self.zap.spider.results
        print "Crawling completed               "
    
    #perform the ZAP scan to get a list of alerts
    def zap_scan(self):
        self.zap.ascan.scan(self.seed)
        while (int(self.zap.ascan.status) < 100):
            print "Scan progress: " + self.zap.ascan.status + "%",
            self.restart_line()
            time.sleep(2)
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
        self.nm = nmap.PortScanner()
        self.clear()
        self.print_header()
        print "Scanning host server for vulnerabilities..."
        self.nm.scan(hosts=self.host, arguments="--script vuln -sV")
        print "Scanning complete."
        print "Open ports:"
        for protocol in self.nm[self.host].all_protocols():
            for port in self.nm[self.host][protocol]: 
                print str(port) + ": " + self.nm[self.host][protocol][port]['name']
        print "\nWriting results to logs..."
        self.write_server_logs()
        print "Logfile server.log has been recorded"
        raw_input("[Press Enter to continue]")
        
    #write the results of the web server alerts to logfiles
    def write_server_logs(self):
        with open("server.log", "w") as fout:
            fout.write("Server alerts for '" + self.host + "\n")
            for protocol in self.nm[self.host].all_protocols():
                for port in self.nm[self.host][protocol]:
                    fout.write("Vulnerabilities on port " + str(port) + " (" + self.nm[self.host][protocol][port]['name'] + ")\n")
                    if 'script' in self.nm[self.host][protocol][port]:
                        for alert in self.nm[self.host][protocol][port]['script']:
                            fout.write("{\n")
                            fout.write(alert + ":\n")
                            fout.write(self.nm[self.host][protocol][port]['script'][alert])
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
                    for dir in self.dir_tree:
                        print dir.encode("ascii")
                except:
                    print "Nothing scanned."
                raw_input("[Press Enter to continue]")
            elif choice == "4":
                self.webapp_alerts_menu()
            elif choice == "5":
                self.server_alerts_menu()
            elif choice == "6":
                if not self.set_target():
                    raw_input("[Press Enter to continue]")
            elif choice == "7":
                if self.subproc is not None:
                    self.subproc.kill()
                sys.exit()
            else:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
    
    #menu to select the web app alerts by priority
    def webapp_alerts_menu(self):
        choice = 0
        try:
            self.alerts["zap"]
        except:
            print "No web application alerts could be found."
            raw_input("[Press Enter to continue]")
            return
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
                for alert in self.alerts["zap"]:
                    priority_list[alert] = self.alerts["zap"][alert]
                self.webapp_selection_menu(priority_list, "All")
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
    
    #menu to select server alerts by port number
    def server_alerts_menu(self):
        choice = 0
        try:
            self.nm[self.host]
        except:
            print "No server alerts could be found."
            raw_input("[Press Enter to continue]")
            return
        server_alerts = 0
        for protocol in self.nm[self.host].all_protocols():
                for port in self.nm[self.host][protocol]:
                    if 'script' in self.nm[self.host][protocol][port]:
                        server_alerts+=1
        if server_alerts == 0:
            print "No server alerts could be found."
            raw_input("[Press Enter to continue]")
            return
        while choice < 1 or choice > server_alerts+1:
            self.clear()
            self.print_header()
            print "///////////////////////"
            print "     Server Alerts"
            print "///////////////////////"
            print "Ports with alerts: " + str(server_alerts)
            i = 0
            print "\nSelect the number of the port you would like to investigate:"
            protocol_list = []
            for protocol in self.nm[self.host].all_protocols():
                for port in self.nm[self.host][protocol]:
                        if 'script' in self.nm[self.host][protocol][port]:
                            protocol_list.append((protocol, port))
                            print str(i+1) + ". " + str(port) + " (" + self.nm[self.host][protocol][port]['name'] + ")"
                            i+=1
                            break
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
                self.server_selection_menu(protocol_list[int(choice)-1][0], protocol_list[int(choice)-1][1])
            else:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
    
    #menu to select an individual web app alert
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
    
    #menu to select an individual server alert
    def server_selection_menu(self, protocol, port):
        choice = 0
        server_alerts = len(self.nm[self.host][protocol][port]['script'])
        while choice < 1 or choice > server_alerts+1:
            self.clear()
            self.print_header()
            print "///////////////////////////////"
            print "     Select a server alert"
            print "///////////////////////////////"
            print "Total alerts: " + str(server_alerts)
            i = 0
            print "\nSelect the number of the alert you would like to investigate:"
            for alert in self.nm[self.host][protocol][port]['script']:
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
                self.server_choice_menu(protocol, port, self.nm[self.host][protocol][port]['script'].keys()[int(choice)-1])
            else:
                print "Invalid input."
                raw_input("[Press Enter to continue]")
    
    #screen displaying a specific web app alert
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
     
    #screen displaying a specific server alert
    def server_choice_menu(self, protocol, port, alert):
        self.clear()
        self.print_header()
        print "//////////////////////////////////////////////////////////"
        print "     " + alert
        print "//////////////////////////////////////////////////////////"
        print self.nm[self.host][protocol][port]['script'][alert]
        raw_input("[Press Enter to continue]")

#initialize the autotest object (start the program)    
autotester = AutoTester()
                

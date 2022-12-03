import socket
import os, subprocess
import nmap
import re
#import scanner
import dns
import dns.resolver
import requests
import sys
from flask import Flask, render_template,request
import whois 
from tld import get_fld, get_tld

app = Flask(__name__)

@app.route("/")
@app.route("/home")

def home():
    return render_template("index.html")



@app.route("/result",methods=['POST',"GET"])

def result():
    # taking input from the web browser.
    output= request.form.to_dict()
    web_address = output["webaddress"]
    portNumber = output["portNumber"]

    a = 0 

    ##########################################################################
                # Part -5 
                # Find whois 
                # Step-5
    ##########################################################################
    def part5():
        print("Part 5 printed")
        w = whois.whois(web_address)
        print(w)

        for x in w.domain_name:
            print(x)
        return w
    ##########################################################################
                # Part - 4 
                # Find Subdomain 
                # you can change the wordlist 
                # Step-4
    ##########################################################################
    def part4():
        print("part 4 printed \n\n\n\n ")   

        sub = open('ab.txt').read()
        subs = sub.splitlines()

        valid_url = []
        a=0

        
        for s in subs:
            url = "https://{}.{}".format(s,web_address)
            print(url)
            try:
                requests.get(url)
            except Exception as ex:
                pass
            else:
                print("valid",url)
                valid_url.append(url)

        print("\n\n\n\n")

        print("Valid Subdomain: ", valid_url)  

        return valid_url 
        
        #part5()
    ##########################################################################
                # Part 3 
                # Find A record
                # Find MX Records
                # Step-3
    ##########################################################################
    def part3(web_address):
        print("Part 3 printed")
         #  Finding A Records
        result = dns.resolver.resolve(web_address, 'A') #here web address taken from global variable
        A_records = []
        for IPval in result:
            A_records.append(IPval.to_text())
        print("A Records are ", A_records)
        return A_records

    def part3_1(web_address):
        # 🔹 Finding MX Records
        MX_record = []
        print("\n\n\n\n")
        result = dns.resolver.resolve(web_address, 'MX')

        for exdata in result:
            print('MX Record: ',exdata)
            MX_record.append(exdata)
        return MX_record
    #part4()
    ##########################################################################
                    # Part 2  
                    # Finding Open ports 
                    # Validating the enter port number
                    # Finding Open port running services
                    # Step-3
    ##########################################################################

    def part2(ipAddress):
        print("Part 2 ")
        # Regular Expression Pattern to extract the number of ports you want to scan. 
        # You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
        port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
        # Initialising the port numbers, will be using the variables later on.
        port_min = 0
        port_max = 65535
        print("Found Part 2 ")
        print('\n\n\n\n')

        while True:
        # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning 
        # all the ports is not advised.
            print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
            port_range = portNumber
            port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
      
            if port_range_valid:
                port_min = int(port_range_valid.group(1))
                port_max = int(port_range_valid.group(2))
                break


        valid_port_number = []
        valid_port_number_and_service = []
        nm = nmap.PortScanner()
        # We're looping over all of the ports in the specified range.
        ip_add_entered = ipAddress
        for port in range(port_min, port_max + 1):
            try:
                # The result is quite interesting to look at. You may want to inspect the dictionary it returns. 
                # It contains what was sent to the command line in addition to the port status we're after. 
                # For in nmap for port 80 and ip 10.0.0.2 you'd run: nmap -oX - -p 89 -sV 10.0.0.2
                result = nm.scan(ip_add_entered, str(port))
                # Uncomment following line and look at dictionary
                # print(result)
                # We extract the port status from the returned object
                port_status = (result['scan'][ip_add_entered]['tcp'][port]['state'])
                print(f"Port {port} is {port_status}")
                if(port_status == "open"):
                    valid_port_number.append(port)
            except:
                # We cannot scan some ports and this ensures the program doesn't crash when we try to scan them.
                print(f"Cannot scan port {port}.")

        protocolname = 'tcp' 
        for port in valid_port_number: 
            temp_protocol_name = socket.getservbyport(port, protocolname)
            temp_adder_port_and_service = "Open Port Number: " + str(port) + " Service Running " +  temp_protocol_name
            valid_port_number_and_service.append(temp_adder_port_and_service)
            print ("Port: %s => service name: %s" %(port, socket.getservbyport(port, protocolname))) 
        
        return valid_port_number_and_service
        # calling the part 3 function for the work
   # part3()


##########################################################################
			# Part -1 
            # Webaddress Address Validating
			# Converting the ip address and DNS
			# Step-1 and Step-2
            #TLD, FTLD
##########################################################################
    # This function is for  defining the domain and validating 

    def is_registered(domain_name):
        print("Part -1 ")
        try:
            w = whois.whois(domain_name)
        except Exception:
            return False
        else:
            return bool(w.domain_name)

    print('\n\n\n\n')

    if is_registered(web_address):
        print(web_address, "is registered \n \n \n ")

        
        #Getting Full top lavel doamian name and domain type          
        if not (web_address.startswith('http://') or web_address.startswith('https://') or web_address.endswith('/')):
            web_address = 'https://{}'.format(web_address)
            domain_name = get_fld(web_address,fix_protocol=True)
            domain_type = get_tld(web_address)
            print("Domain Name: ",domain_name)
            print("Domain type: ",domain_type)
        else :   
            domain_name = web_address
            domain_type = get_tld(web_address,fix_protocol=True)
            print("domain Name: ",domain_name)
            print("Domain type: ",domain_type)  
        
        #Getting the Ip Address 
        ipAddress = socket.gethostbyname(domain_name)
        print(f'The {web_address} IP Address is {ipAddress}')

        # calling the second part of the program
        valid_port_number_and_service = part2(ipAddress)
        A_records = part3(domain_name)
        MX_record = part3_1(domain_name)
        valid_url = part4()
        w = part5()
        print("final prinitng")
        print(w)
       
        a = a + 1 
    else: 
        print(web_address,'is not registered')

    print('\n\n\n\n')
    
    if a==1:
        return render_template("index2.html",web_address=web_address,valid_port_number_and_service = valid_port_number_and_service,A_records=A_records,MX_record=MX_record,valid_url=valid_url,w=w,domain_name=domain_name,domain_type=domain_type,ipAddress=ipAddress)
    else:
        return render_template("index3.html")

    # I have not added the summary list. It was in app copy.py




if __name__ =='__main__':
    app.run(debug=True,port=5001)

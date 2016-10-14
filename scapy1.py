#!/usr/bin/python
from scapy.all import *
import os
import re
import sqlite3
import requests
import sys


GET_re = re.compile("GET ([a-zA-Z0-9\/+?/._]+) HTTP/1.1\r\n")
HOST_re = re.compile("Host: ((http://)?(th-)?p.talk.kakao.co.kr)\r\n")
kakao_re = re.compile("http://(th-)?p.talk.kakao.co.kr")


remove_duplicate = {} # remove duplicate requests

def http_header(packet):
    str_pkt = str(packet)
<<<<<<< HEAD
=======
    #a = GET_re.findall("GET th/talkp/wksCVVLDGd/EPc2iXgCMBCg0S75Be6S80/1obrnl_940x940_s.jpg HTTP/1.1\r\n")
>>>>>>> 2c280faf51c3f62e2b447c6fc4c748a17a315f09
    if packet.haslayer("Dot11Beacon"):
        return
    elif packet.haslayer("TCP") == 0:
        return

    str_pkt = str(packet)
    print(repr(packet))
    matched_GET = GET_re.findall(str_pkt)
    matched_HOST = HOST_re.findall(str_pkt)
    
    global remove_duplicate

    if len(matched_GET) != 0 and len(matched_HOST) != 0:
        matched_url2 = matched_GET[0]
        matched_url1 = matched_HOST[0][0]
                                                                                                                                                                                                              
        full_url = matched_url1 + matched_url2

        if full_url not in remove_duplicate.keys():
            remove_duplicate[full_url] = 1
            
            fName_idx = full_url.rfind("/")
            filename = full_url[ fName_idx+1 : ]
<<<<<<< HEAD
            #print full_url
=======
            print full_url
>>>>>>> 2c280faf51c3f62e2b447c6fc4c748a17a315f09
            download_kakao_jpg(full_url, filename)
            
    else:
        pass
        #print "No KaKao"


def download_kakao_jpg(full_url, filename):

    
    if full_url.find("http://") == -1:
        full_url = "http://" + full_url
<<<<<<< HEAD
    try:	
    	requester = requests.get(full_url);
    except:
	print "i need wifi"   
=======
		


    requester = requests.get(full_url);
       
>>>>>>> 2c280faf51c3f62e2b447c6fc4c748a17a315f09
    with open("./" + filename, "wb") as f:
        f.write(requester.content)
    with open("daankao.txt", "a+t") as f:
        f.write(full_url + " " + filename + "\n")

    
    print "Success"
    
             

<<<<<<< HEAD
if __name__ == '__main__':
   if (len(sys.argv) != 2):
      if sys.argv[1] not in ["live", "pcap"]:
         print "Input Condition 'live' or 'pcap'"
         print "USAGE : %s Condition - live or pcap" % sys.argv[0]
         sys.exit()

   else :
      if(sys.argv[1]=="live"):
         sniff(iface= "tap0", prn=http_header, filter="tcp port 80")
      elif(sys.argv[1]=="pcap"):
         filename = raw_input("Input File Name : ")
         now_path = os.path.dirname(os.path.abspath(__file__))
         pcap_path = os.path.join(now_path, filename)
	 pcap = rdpcap(pcap_path)
	 for packet in pcap:
	    http_header(packet)	

         #sniff(iface="tap0", prn=http_header, filter="tcp port 80")

=======
if len(sys.argv) != 3:
    print("USAGE : %s -p" % sys.argv[0]) 

else :
	pcap_file = "argv[1]"
	pxap = rdpcap(pcap_file)
	data = ""
	for packet in pcap:
		http_header(packet)	

with open("daankao.txt", "wt") as f:
	f.write("This is FULL_URL FILE_NAME\n")
sniff(iface= "wlan0", prn=http_header, filter="tcp port 80")
>>>>>>> 2c280faf51c3f62e2b447c6fc4c748a17a315f09


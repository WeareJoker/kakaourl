#!/usr/bin/python
from scapy.all import *
import re
import sqlite3
import requests
import sys

#con sqlite3.connect("./kakatalk.db")

GET_re = re.compile("GET ([a-zA-Z0-9\/+?/._]+) HTTP/1.1\r\n")
HOST_re = re.compile("Host: ((http://)?(th-)?p.talk.kakao.co.kr)\r\n")
#sqlite3.connect("./kakatalk.db")
kakao_re = re.compile("http://(th-)?p.talk.kakao.co.kr")
#(th/)?talkp/[0-9a-zA-Z]{10}/[0-9a-zA-Z]{22}/[0-9a-zA-Z_]{16}.jpg

remove_duplicate = {} # remove duplicate requests

def http_header(packet):
    
    str_pkt = str(packet)
    #a = GET_re.findall("GET th/talkp/wksCVVLDGd/EPc2iXgCMBCg0S75Be6S80/1obrnl_940x940_s.jpg HTTP/1.1\r\n")
    ##b = HOST_re.findall("Host: http://p.talk.kakao.co.kr\x0d\x0a")
    #print a.group(0)
    #print b.group(0)
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
            print full_url
            download_kakao_jpg(full_url, filename)
            
    else:
        pass
        #print "No KaKao"


def download_kakao_jpg(full_url, filename):

    
    if full_url.find("http://") == -1:
        full_url = "http://" + full_url
		


    requester = requests.get(full_url);
       
    with open("./" + filename, "wb") as f:
        f.write(requester.content)
    with open("daankao.txt", "a+t") as f:
        f.write(full_url + " " + filename + "\n")

    
    print "Success"
    
             

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


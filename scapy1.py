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
    if packet.haslayer("Dot11Beacon"):
        return
    elif packet.haslayer("TCP") == 0:
        return

    str_pkt = str(packet)
    print(repr(packet))
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
            print(full_url)
            download_kakao_jpg(full_url, filename)

    else:
        pass
        #print "No KaKao"


def download_kakao_jpg(full_url, filename):
    print("download kakao jpg")
    if full_url.find("http://") == -1:
        full_url = "http://" + full_url

    requester = requests.get(full_url);

    with open("./" + filename, "wb") as f:
        f.write(requester.content)
    print("Success")

"""
def GET_print(packet1):
        http_GET_packet = str(packet1)
        http_get_packet_list = http_GET_packet.split("\r\n")
        for extrect_packet_line in http_get_packet_list:
                http_packet_host_len = extrect_packet_line.find('Host:')
                if -1 != http_packet_host_len:
                    m = p.match(extrect_packet_line[http_packet_host_len+5:].strip())
                    if m is not None:
                        saveurl = m.group()
                        print saveurl
                        cursor = con.cursor()
                        cursor.execute("insert into kakaourl (url) values (\'" + saveurl + "\');")
                        con.commit()
                    else:
                        print('No Kakao')

"""

if __name__ == '__main__':
        mon_iface = ""
        if len(sys.argv) != 2 :
                print("USAGE : thiscode.py 'interface' ")
                sys.exit()
        mon_iface = sys.argv[1]

        try:
                sniff(iface= mon_iface, prn=http_header)
        except KeyboardInterrupt:
                sys.exit()



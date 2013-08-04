'''
Author: Joseph Rodriguez
Date: August 1st 2013
Description:
This script will search through all of the IP addresses(5 at a time) provided upon startup, and will grab certificate
information from each IP address and write it to a spreadsheet file(.csv).
'''

from M2Crypto import SSL, RSA
from subprocess import *
import ssl
import OpenSSL
import threading
import csv
import re
from datetime import datetime

def main():
    now = datetime.now()

    global title
    title = now.strftime("%Y-%m-%d_%H-%M-%S") + '_Log.csv'

    timeLog = open('Logs.txt','a')
    timeLog.write('Started: '+ str(now) + '\n')
    timeLog.write('Writing to:' + str(title) + '\n')
    timeLog.close()
    
    
    c = open(title, 'w')
    
    w = csv.writer(c)
    w.writerow(['IP', 'Company Name', 'ExpirationDate','Time Left(In Days)', 'CommonName', 'Issuer',
                'Serial #','Public Key','Public Key Size','Error Code','Description'])
    c.close()
    global IP_list
    IP_list = []
    global certInfoHolder
    certInfoHolder = []
    global brokenCerts
    brokenCerts = []

    getRanges()

def getRanges():
    print 'Enter a range(ex. From: 173.252.1.0 , To: 173.252.1.200)'
    starting_IP = raw_input('From: ')
    ending_IP = raw_input('To: ')

    ip_ranges = ipRange(starting_IP, ending_IP)
    addMore = raw_input('Do you want to add another IP range?Y/N')
    addMore = addMore[0].lower()
    if addMore == 'y':
        getRanges()       
    elif addMore == 'n':
        timeLog = open('Logs.txt','a')
        timeLog.write('Scanning: ' + str(len(IP_list)) + ' IP Addresses \n')
        timeLog.close()
        #print 'Done gathering IP Addresses'
        createdThreads = 0
        threadSplit = len(IP_list) / 5

        #Splitting the work up between the threads
        thread_1_list = IP_list[0:threadSplit]
        thread_2_list = IP_list[threadSplit:(threadSplit*2)]
        thread_3_list = IP_list[(threadSplit*2):(threadSplit*3)]
        thread_4_list = IP_list[(threadSplit*3):(threadSplit*4)]
        thread_5_list = IP_list[(threadSplit*4):(threadSplit*5)]
        thread_6_list = IP_list[(threadSplit*5):]

        threadList = [] 
        for address in range(threadSplit):
            thread_1 = getCertInfo(thread_1_list[address])
            thread_2 = getCertInfo(thread_2_list[address])
            thread_3 = getCertInfo(thread_3_list[address])
            thread_4 = getCertInfo(thread_4_list[address])
            thread_5 = getCertInfo(thread_5_list[address])
            thread_1.start()
            thread_2.start()
            thread_3.start()
            thread_4.start()
            thread_5.start()
    
            thread_1.join()      
            thread_2.join()
            thread_3.join()
            thread_4.join()
            thread_5.join()
     
            if address == threadSplit-1:
                for address in range(len(thread_6_list)):
                     thread_6 = getCertInfo(thread_6_list[address])
                     thread_6.start()
                     thread_6.join()
            
        CIH = certInfoHolder
        openCSV = open(title, "a")
        writeToCSV = csv.writer(openCSV)
        for info in CIH:
            writeToCSV.writerow([info[0], info[1], info[2], info[3], info[4] , info[5][16:],
                                 info[6],info[7],info[8],0])
        for info in brokenCerts:
            writeToCSV.writerow([info[0],'','','','','','','','',info[1],info[2]])
        openCSV.close()

    timeLog = open('Logs.txt','a')
    timeLog.write('Finished: ' + str(datetime.now()) + '\n')
    timeLog.close()

                              
def ipRange(start_ip, end_ip):
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    
    IP_list.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1        
        IP = ".".join(map(str, temp))
        IP_list.append(IP)

class getCertInfo(threading.Thread):
     def __init__(self,IP):
         threading.Thread.__init__(self)
         self.IP_check=IP

     def run(self):
        try:
            #Checking for cert
            self.getCert = check_output('curl -v --max-time 2 https://'+ self.IP_check,
            stderr=STDOUT,
            shell=True)
            self.getSSLCert()

        except CalledProcessError as detail:
            detail = str(detail)
            self.eC = detail[len(detail)-2:]
            # If operation times out(28):
            if re.search('28', self.eC) is not None:
                self.x = [str(self.IP_check), '28', 'Operation timed out']
                brokenCerts.append(self.x)
                print self.x
    
            #60:Unable to verify Certificate with known CA Certs --Expired or Self-Signed
            #51: Cert CN doesn't match host name
            elif re.search('60', self.eC) is not None or re.search('51', self.eC) is not None:
                self.getSSLCert()

            elif re.match(' 7', self.eC) is not None:
                self.x = [str(self.IP_check), '7', 'Failed to connect to host/proxy']
                brokenCerts.append(self.x)

            elif re.match('35', self.eC) is not None:
                self.x = [str(self.IP_check), '35', 'Problem with SSL/TLS handshake']
                brokenCerts.append(self.x)
            else:
                self.x = [str(self.IP_check), self.eC, '']
                brokenCerts.append(self.x)
                print self.x                    

     def getSSLCert(self):

        #M2Crypto : Establishing Connection - Retrieving Cert
        SSL.Connection.clientPostConnectionCheck = None
        self.ctx = SSL.Context()
        self.conn = SSL.Connection(self.ctx)
        self.conn.connect((self.IP_check,443))
        self.cert = self.conn.get_peer_cert()

        #M2Crypto : Getting Cert info
        self.pubKey = self.cert.get_pubkey().get_rsa().as_pem()
        self.pubKey = self.pubKey[26:len(self.pubKey)-25]
        self.pubKeySize = self.cert.get_pubkey().size()*8

        #OpenSSL
        self.serv_cert = ssl.get_server_certificate((self.IP_check, 443))
        self.x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.serv_cert)
        #Formatting expiration date and time
        self.eDateT = str(self.x509.get_notAfter())
        try:
            self.formatDT = datetime.strptime(self.eDateT[0:4] +' '+self.eDateT[4:6]+' '+ self.eDateT[6:8],'%Y %m %d')
        except AttributeError:
            self.formatDT = datetime.strptime(self.eDateT[0:4] +' '+self.eDateT[4:6]+' '+ self.eDateT[6:8],'%Y %m %d')
        self.expiresIn = self.formatDT - datetime.now()
        self.certInfo = self.x509.get_subject()
        self.commonName = self.certInfo.commonName
        self.companyName = self.certInfo.O
        self.serialNumber = self.x509.get_serial_number()
        self.issuer = self.x509.get_issuer()
        self.x = [str(self.IP_check),str(self.companyName),str(self.formatDT.strftime("%Y-%m-%d")),
                  str(self.expiresIn.days), str(self.commonName) , str(self.issuer),
                  str(self.serialNumber),str(self.pubKey),str(self.pubKeySize)]
        certInfoHolder.append(self.x)
        print self.x
    
main()

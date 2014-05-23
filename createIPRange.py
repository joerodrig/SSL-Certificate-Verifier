'''
Author: Joseph Rodriguez

Last Edit: May 23,2014
Credits to: http://cmikavac.net/2011/09/11/how-to-generate-an-ip-range-list-in-python/
For the initial ipRange() code that I modified slightly for my purposes

Use this program to create an IP Range List to read from.

After you input you range values, a text file will be created that "checkSSLCert_nohup.py" reads from by default.

The text file created is called: IPRange.txt

'''
def main():
    IP_list = []
    getRange(IP_list)


def getRange(ipl):
    print 'Enter a range(ex. From: 173.252.1.0 , To: 173.252.1.200)'
    starting_IP = raw_input('From: ')
    ending_IP = raw_input('To: ')
    ipRange(ipl,starting_IP,ending_IP)

    #Add more addresses or write addresses to IPrange.txt file
    getRange(ipl) if raw_input('Add another IP range?y/n')[0].lower() == 'y' else writeToText(ipl)

def writeToText(ipl_in):
    ranges = open('IPrange.txt','w')
    for i in range(len(ipl_in)):
        ranges.write(ipl_in[i] + '\n')
    ranges.close()
    print 'Wrote to addresses IPrange.txt'

def ipRange(IP_List,start_ip, end_ip):
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    
    IP_List.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1        
        IP = ".".join(map(str, temp))
        IP_List.append(IP)
main()

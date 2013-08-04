'''
Credits to: http://cmikavac.net/2011/09/11/how-to-generate-an-ip-range-list-in-python/
For the initial code that I modified a bit for my purposes

Use this program to create an IP Range List to read from.

After you input you range values, a text file will be created that "checkSSLCert_nohup.py" reads from by default.

The text file created is called: IPRange.txt

'''
def main():
    global IP_list
    IP_list = []
    
    print 'Enter a range(ex. From: 173.252.1.0 , To: 173.252.1.200)'
    starting_IP = raw_input('From: ')
    ending_IP = raw_input('To: ')
    ipRange(starting_IP,ending_IP)

    addMore = raw_input('Do you want to add another IP range?Y/N')
    addMore = addMore[0].lower()
    if addMore == 'y':
        getRanges()

    else:
        rangeText = open('IPrange.txt','w')
        for i in range(len(IP_list)):
            rangeText.write(IP_list[i] + '\n')
        rangeText.close()
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
main()

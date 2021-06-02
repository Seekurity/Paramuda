import threading
import time
import requests
import argparse
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__='Seif Elsallamy'

__version__='2.0 alpha'

__url__='https://github.com/seifelsallamy/paramuda'


__description__='''\
___________________________________________
paramuda url params scan
paramuda v.'''+__version__+'''
Author: '''+__author__+'''
Github: '''+__url__+'''
___________________________________________
'''


def print_banner():
    print """ ____    ____  ____    ____  ___  ___  __ __  ___     ____ 
|    \  /    T|    \  /    T|   T   T|  T  T|   \   /    T
|  o  )Y  o  ||  D  )Y  o  || _   _ ||  |  ||    \ Y  o  |
|   _/ |     ||    / |     ||  \_/  ||  |  ||  D  Y|     |
|  |   |  _  ||    \ |  _  ||   |   ||  :  ||     ||  _  |
|  |   |  |  ||  .  Y|  |  ||   |   |l     ||     ||  |  |
l__j   l__j__jl__j\_jl__j__jl___j___j \__,_jl_____jl__j__j
                                                          """+__version__+""""""


inputs = []
dynamic = []
finalResult = []
def reqs(req, test, isFinal):
    global debug
    global dynamic
    global nn
    global signature
    global finalResult
    payload = "a"
    req = req.replace("$inject$",payload)
    req = req.split("\n")
    raw1 = req[0].split(" ")
    method = raw1[0]
    path = raw1[1]
    headers = {}
    body = ""
    n = 0
    for i in req[1:]:
        
        if i == "":
            n = 1
        elif n==0:
            p = i.split(": ")
            if p[0].lower() == "host":
                host = p[1].replace(" ","")
            headers[p[0]]= p[1]
        else:
            body = body + i + "\n"
    if method.lower() == "post":
        if debug:
            r = requests.post(path, data=body, headers=headers, proxies={"https":"127.0.0.1:8888"}, verify=False)
        else:
            r = requests.post(path, data=body, headers=headers)
        m = r.text
    elif method.lower() == "get":
        if debug:
            r = requests.get(path, headers=headers, proxies={"https":"127.0.0.1:8888"}, verify=False) #debug
        else:
            r = requests.get(path, headers=headers)
        m = r.text + "zqzqzq" + str(r.headers)
        if test:
            return m
        if signature_check(m, nn, signature):
            dynamic.append(path)

            if not isFinal:
                print "[*] Detected a dynamic param on " + path

            else:
                if "&" in path:
                    finalParam = path.split("&")[-1]
                else:
                    finalParam = path.split("?")[-1]

                print "[*] Detected a dynamic param on " + path
                finalResult.append(finalParam)

    else:
        m = "method not supported"
    #print m
    


def X_Threading(nThreads, function): #X_Threading(15, printxy, [["x","y"]["hello","hey"]] )
    global inputs
    ready=True
    nThreads = nThreads + threading.activeCount() # nthreads bigger than the number of already active by nthreads
    while ready:
        
        if threading.activeCount() > nThreads: # if active threads bigger than nthreads stop for 0.1 second
            time.sleep(0.1)
            continue
        if len(inputs) % 300 == 0:
            print "[*] " + str(len(inputs)) + " requests left"
        t = threading.Thread(target=function, args=(inputs.pop(0))) # send threads
        t.start()
        if len(inputs) < 1:
            time.sleep(3)
            if len(inputs) < 1:
                ready = False

    return 0
lock = False
def signature_check(output, n, signature):
    #print output.encode("utf8")
    #print "[*] nn = " + str(n) + "count(payload)= " + str(output.count(signature)) 
    
    global lock
    if lock == True:
        time.sleep(0.1)
    lock = True
    c = output.count(signature)
    if c != n:
        #print "[*] count(payload)=" + str(c) 
        if output.split("zqzqzq")[1].count(signature):
            print "in headers!"
        lock = False
        
        return True
    else:
        lock = False
        return False
    
def urls_generator(url, params, n, payload, isFinal):
    if url[:4] != "http":
        rr = url
        url = url.split(" ")[1]
        r = rr.replace(url,"$URL$")
    else:
        r = """GET $URL$ HTTP/1.1"""
    urls = []
    if "?" in url:
        curl=url+"&"
    else:
        curl=url+"?"
    for i in range(len(params)):
        param = params[i]
        if i!=0 and i % n == 0:
            curl = curl[:-1]
            urls.append([r.replace("$URL$",curl), 0, isFinal])
            if "?" in url:
                curl=url + "&"
            else:
                curl=url + "?"
        curl = curl + param + "=" + payload + "&"
        
    if n != 1:
        lost=n-i%n
        p=""
        for c in range(lost-1):
            p = p + "&0q"+ str(c) + "=" + payload
        curl = curl + p
        urls.append([r.replace("$URL$",curl), 0, isFinal])

    return urls


def test_n(url, n, payload):

    if url[:8].lower() == "get http":
        rr = url
        url = url.split(" ")[1]
        r = rr.replace(url,"$URL$")
    elif url[:4] == "http":
        r = """GET $URL$ HTTP/1.1"""
    elif url[:9].lower() == "post http":
        print "POST method currently isn't supported"
        exit(1)
    else:
        print "Invalid URL or raw request file"
        print "\nExample for a valid URL"
        print "https://example.com/xx/xx"
        print "\nExample for a valid request "
        print """```\nGET http://example.com/ HTTP/1.1\nXXX: YYY\n...\n\n```"""
        exit(1)
        
    p = ""
    for c in range(n):
        p = p + "&0q"+ str(c) + "=" + payload
    if "?" in url:
        nurl = url + "&" + p
    else:
        nurl = url + "?" + p
    req=r.replace("$URL$",nurl)
    
    r=reqs(req, 1, False)
    o=cleanString = re.sub('\W+',' ', r ).split(" ")
    o = list(set(o))
    return [r.count(payload), o]
    

#Program start


def go(url, payload, n, tn, params, blackList):

    global inputs
    global dynamic
    global nn
    global signature
    global finalResult
    
    #Calculating normal n
    result = test_n(url, n, payload)
    nn = result[0]
    o = result[1] #wordlist generator
    params = list(set(params+o))
    params = list(set(params) - set(blackList.split(",")))
    print "[*] Setting url/req to " + url
    print "[*] Setting params per req to " + str(n)
    print "[*] Setting payload to " + payload
    print "[*] Setting Threads to " + str(tn)
    print "[*] Calculating normal n"
    print "[*] Normal n = " + str(nn)
    signature = payload
    #Generating requests
    print "[*] Generating requests"
    rs = urls_generator(url, params, n, payload, False)
    print "[*] " + str(len(rs)) + " Requests"
    print "[*] Start sending threads"



    inputs = rs    
    X_Threading(tn, reqs)



    #phase 2
    print "[*] Finished"

    #New params
    time.sleep(5)
    if not dynamic:
        return 0
    print "[*] Start detecting exact dynamic parameters"
    nparams=[]
    for r in dynamic:
        for p in r.split("&"):
            nparams.append(p.split("=")[0])
        
    #Program start

    #Setting vars
   
    params = nparams
    n = 1
    #payload = "qqq000"
    #tn = 5 #threads

    #Calculating normal n
    nn = test_n(url, n, payload)[0]
    print "[*] Setting url to " + url
    print "[*] Setting params per req to " + str(n)
    print "[*] Setting payload to " + payload
    print "[*] Setting Threads to " + str(tn)
    print "[*] Calculating normal n"
    print "[*] Normal n = " + str(nn)
    signature = payload
    #Generating requests
    print "[*] Generating requests"
    rs = urls_generator(url, params, n, payload, True)
    print "[*] " + str(len(rs)) + " Requests"
    print "[*] Start sending threads"



    inputs = rs    
    X_Threading(tn, reqs)

    time.sleep(5)

    finalResultString1 = ""
    finalResultString2 = ""
    for finalResultString in finalResult:
        finalResultString1 = finalResultString1 + finalResultString.split("=")[0] + ","
        finalResultString2 = finalResultString2 + finalResultString + "&"
    print "\n"
    print finalResultString1
    print "\n"
    print finalResultString2
        




def main():

    parser = argparse.ArgumentParser(
		version=__version__,
		formatter_class=argparse.RawTextHelpFormatter,
		prog='paramuda',
		description=__description__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url',type=str, help='target URL')
    group.add_argument('-r', '--request',type=str, help='specific path to raw request file')

    group2 = parser.add_mutually_exclusive_group(required=False)
    group2.add_argument('-w', '--wordlist',type=str, help='specific path to wordlist file', required=False)
    group2.add_argument('-b', '--bruteforce',type=int, choices=[1,2,3], help='bruteforcing params level from 1 to 3 default = 1', required=False, default=1)

    parser.add_argument('-n', '--nparamsperreq', type=int, help='Number of parameters per request default=50', required=False, default=50)
    parser.add_argument('-t', '--threads', type=int , help='Number of threads default=5', required=False, default=5)
    parser.add_argument('-p', '--payload' , type=str, help='Payload for testing default=qqq000', required=False, default="qqq000")
    parser.add_argument('-e', '--excludeParams' , type=str, help='Exclude parameters example "sid,firName,loginId"', required=False, default="")

    args = parser.parse_args()
	
    url = args.url
    request = args.request
    wordlist = args.wordlist
    bruteforce=args.bruteforce
    n = args.nparamsperreq
    tn = args.threads
    payload = args.payload
    blackList = args.excludeParams
    print_banner()

    if request is not None:
        try:
            with open(request,"r") as f:
                url = f.read()
        except:
            print 'The file ' + request + ' could not be opened.'
            return 1
    if wordlist is not None:
        try:
            with open(wordlist,"r") as f:
                wordlist = f.read().split("\n")
                wordlist = filter(None, wordlist)
        except:
            print 'The file ' + wordlist + ' could not be opened.'
            return 1
        

    else :
        lv_1 = []
        lv_2 = []
        lv_3 = []
        lv_4 = []

        an = "_abcdefghijklmnopqrstuvwxyz1234567890"
        
        for c in an:
            lv_1.append(c)
            for cc in an:
                lv_2.append(c+cc)
                for ccc in an:
                    lv_3.append(c+cc+ccc)
                    for cccc in an:
                        lv_4.append(c+cc+ccc+cccc)
        if bruteforce == 1:
            wordlist = lv_1 + lv_2
        elif  bruteforce == 2:
            wordlist = lv_1 + lv_2 + lv_3
        elif bruteforce == 3:
            wordlist = lv_1 + lv_2 + lv_3 + lv_4
        else:
            print "invalid bruteforce value"
            exit(1)
        
    
    

    go(url, payload, n, tn, wordlist, blackList)

debug = 0
main()










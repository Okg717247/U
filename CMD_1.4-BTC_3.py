# Edited by Alpha Century to work with 
# https://github.com/mingfunwong/all-bitcoin-private-key
# 12.04.2021

import sys
import os
import re
from requests_html import HTMLSession
import random

pages = 0
print("Loaded All Bitcoin Private Keys - CMD VERSION 1.4.3")
print("Started search...")


def run():
    try:
        while 5 > 1:
            #webUrl = urllib.request.urlopen('http://localhost:4200/#/home?page=1')
            pageNum = random.randrange(1,7237005577332262213973186563042994240829374041602535252466099000494570602496)
            fullurl = 'http://localhost:4200/#/home?page='+str(pageNum)
            session = HTMLSession()
            webUrl = session.get(fullurl)
            #time.sleep(10)
            webUrl.html.render()
            #html = webUrl.content
            data = webUrl.html.html
            result = re.findall("[+-]?\d+\.\d+", str(data))
            for i in result:
                if str(i) + " btc" in str(data):
                    if float(i) > 0:
                        with open('ValidWalletsBTC.txt', 'a') as appendFile:
                            appendFile.write('{} btc\n'.format(str(i)))
                            appendFile.write('{}\n'.format(fullurl))
            global pages
            pages = pages + 1
            sys.stdout.write("\rPages read: {}".format(str(pages)))
            sys.stdout.flush()
            session.close()
            webUrl.close()
    except:
        run()


#for i in range(int(threadCount)):
    #thread = threading.Thread(target=run)
    #thread.start()
run()
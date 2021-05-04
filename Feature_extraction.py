from urllib.parse import urlparse
#from urlparse import urlparse
import re
#import urllib2
import urllib
import urllib.request
from xml.dom import minidom
import csv
import pygeoip
import webbrowser
import unicodedata
webbrowser.get("C:/Program Files/Mozilla Firefox/firefox.exe %s").open('http://google.com', new=2)
nf=-1

def Tokenise(url):

        if url=='':
            return [0,0,0]
        token_word=re.split('\W+',url)
      
        no_ele=sum_len=largest=0
        for ele in token_word:
                l=len(ele)
                sum_len+=l
                if l>0:                      
                        no_ele+=1
                if largest<l:
                        largest=l
        try:
            return [float(sum_len)/no_ele,no_ele,largest]
        except:
            return [0,no_ele,largest]


def find_ele_with_attribute(dom,ele,attribute):
    for subelement in dom.getElementsByTagName(ele):
        if subelement.hasAttribute(attribute):
            return subelement.attributes[attribute].value
    return nf
        

def sitepopularity(host):

        xmlpath='http://data.alexa.com/data?cli=10&dat=snbamz&url='+host
        
        try:
            xml= urllib.request.urlopen(xmlpath)
            dom =minidom.parse(xml)
            rank_host=find_ele_with_attribute(dom,'REACH','RANK')
           
            rank_country=find_ele_with_attribute(dom,'COUNTRY','RANK')
            return [rank_host,rank_country]

        except:
            return [nf,nf]


def Security_sensitive(tokens_words):

    sec_sen_words=['confirm', 'account', 'banking', 'secure', 'ebayisapi', 'webscr', 'login', 'signin']
    cnt=0
    for ele in sec_sen_words:
        if(ele in tokens_words):
            cnt+=1;

    return cnt

def exe_in_url(url):
    if url.find('.exe')!=-1:
        return 1
    return 0

def Check_IPaddress(tokens_words):

    cnt=0;
    for ele in tokens_words:
        
        if ele.isnumeric():
            cnt+=1
        else:
            if cnt>=4 :
                return 1
            else:
                cnt=0;
    if cnt>=4:
        return 1
    return 0
    
def getASN(host):
    try:
        g = pygeoip.GeoIP('GeoIPASNum.dat')
        
        asn=int(g.asn_by_name(host).split()[0][2:])
        print(asn)
        return asn
    except:
        return  nf




def safebrowsing(url):
    api_key = "ABQIAAAA8C6Tfr7tocAe04vXo5uYqRTEYoRzLFR0-nQ3fRl5qJUqcubbrw"
    name = "URL_check"
    ver = "1.0"

    req = {}
    req["client"] = name
    req["apikey"] = api_key
    req["appver"] = ver
    req["pver"] = "3.0"
    req["url"] = url #change to check type of url

    try:
       
        for u in [url]:
                connection = urllib.request.urlopen(url)
                r=connection.getcode()
                connection.close()
        if r==204:
             print ("safe")
             return 0
        elif r==200:
             #print ("The queried URL is either phishing, malware or both, see the response body for the specific type.")
             return 0
        elif r==204:
            print ("The requested URL is legitimate, no response body returned.")
        elif r==400:
            print ("Bad Request The HTTP request was not correctly formed.")
        elif r==401:
            print ("Not Authorized The apikey is not authorized")
        else:
            print ("Service Unavailable The server cannot handle the request. Besides the normal server failures, it could also indicate that the client has been throttled by sending too many requests")
    except:
        return -1

def feature_extract(url_input):

        Feature={}
        tokens_words=re.split('\W+',url_input) 
       
        token_delimit1=re.split('[./?=-_]',url_input)
        
        obj=urlparse(url_input)
        
        host=obj.netloc
        path=obj.path

        Feature['URL']=url_input

        Feature['rank_host'],Feature['rank_country'] =sitepopularity(host)

        Feature['host']=obj.netloc
        Feature['path']=obj.path

        Feature['Length_of_url']=len(url_input)
        Feature['Length_of_host']=len(host)
        Feature['No_of_dots']=url_input.count('.')

        Feature['avg_token_length'],Feature['token_count'],Feature['largest_token'] = Tokenise(url_input)
        Feature['avg_domain_token_length'],Feature['domain_token_count'],Feature['largest_domain'] = Tokenise(host)
        Feature['avg_path_token'],Feature['path_token_count'],Feature['largest_path'] = Tokenise(path)

        Feature['sec_sen_word_cnt'] = Security_sensitive(tokens_words)
        Feature['IPaddress_presence'] = Check_IPaddress(tokens_words)
        
      
        Feature['ASNno']=getASN(host)
        Feature['safebrowsing']=safebrowsing(url_input)
       
        
        return Feature

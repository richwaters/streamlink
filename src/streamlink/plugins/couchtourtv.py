import logging
import re
import time

from streamlink import PluginError
from streamlink.plugin.plugin import parse_url_params
from streamlink.stream import AkamaiHDStream
from streamlink.utils import update_scheme

from streamlink.plugin import Plugin, PluginArgument, PluginArguments
from streamlink.plugin.api import useragents
from streamlink.stream import HLSStream
from streamlink.stream import HTTPStream
from streamlink.stream import RTMPStream
from urllib.parse import quote

log = logging.getLogger(__name__)


from selenium import webdriver
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options

options = Options()
options.headless = True
options.add_argument("--enable-javascript")

#options = webdriver.ChromeOptions()
#options.add_argument("--user-agent=New User Agent")
#driver = webdriver.Chrome(chrome_options=options)

#driver = webdriver.Chrome( options=options )
#driver = webdriver.Safari() #( options=options )
#driver.implicitly_wait(10)

profile = webdriver.FirefoxProfile()
userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15"
#userAgent = "Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.20 (KHTML, like Gecko) Mobile/7B298g"
profile.set_preference("general.useragent.override", userAgent )
driver = webdriver.Firefox( firefox_profile=profile, options=options )
sleepTime = 2.0


#<video preload="auto" controls="" controlslist="nodownload" disablepictureinpicture="" playertype="file" style="width: 100%; height: 100%;" playsinline="" webkit-playsinline="" x5-playsinline="" src="https://d0bca9b68a812ed71b07e4247e1836c1.egress.mediapackage-vod.us-east-1.amazonaws.com/out/v1/b323210a4b514ee9be6ab7ced8ce0b65/8ffa49d6e66f45c89f1bff09e08a908f/4bb3c45cd2df4693bbead2a9c6201e58/index.m3u8"></video>

time.sleep( sleepTime)

class CouchTourTv(Plugin):
    _url_re = re.compile(r'https?://player\.couchtour\.tv')
    _siteId_re = re.compile(r'.*?"siteId":"([^"]*)"',re.MULTILINE|re.DOTALL)
    _jwt_re = re.compile(r'.*?"jwt":"([^"]*)"',re.MULTILINE|re.DOTALL)

    _m3u8_re = re.compile(r'''['"](http.+\.m3u8.*?)['"]''')
    _authed_re = re.compile( r'''<title>Login | nugs.net</title>''' )
    _verificationToken_re = re.compile( r'''.*?<input name="__RequestVerificationToken"[^>]*?value="([^"]+)".*''',  re.MULTILINE|re.DOTALL)
    TIME_SESSION = 60 * 60 * 24 * 30

    def __init__(self, url):
        super().__init__(url)
        self.jsonHeaders = {
            'User-Agent': useragents.SAFARI,
            #'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            "Accept": "application/json",
            "Content-Type": "application/json",
            #'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        self.headers = {
            'User-Agent': useragents.SAFARI,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }

    arguments = PluginArguments(
        PluginArgument(
            "email",
            True,
            requires=["password"],
            metavar="EMAIL",
            help="""
            The email associated with your nugs.net account,
            required to access any nugs stream.
            """),
        PluginArgument(
            "password",
            sensitive=True,
            metavar="PASSWORD",
            help="""
            A nugs.net account password to use with --nugs-email.
            """),
        PluginArgument(
            "purge-credentials",
            action="store_true",
            help="""
            Purge cached nugs.net credentials to initiate a new session
            and reauthenticate.
bt            """)
    )

    @classmethod
    def can_handle_url(cls, url):
        return cls._url_re.match(url) is not None

    def _get_streams(self):

        #return HLSStream.parse_variant_playlist(self.session, "https://d0bca9b68a812ed71b07e4247e1836c1.egress.mediapackage-vod.us-east-1.amazonaws.com/out/v1/b323210a4b514ee9be6ab7ced8ce0b65/8ffa49d6e66f45c89f1bff09e08a908f/4bb3c45cd2df4693bbead2a9c6201e58/index.m3u8" )
        
        if self.options.get("purge_credentials"):
            self.clear_cookies()
            log.info("Credentials purged")

        email = self.get_option('email')
        password = self.get_option('password')
        if not email or not password:
            log.error("nugsnet requires authentication, use --nugsnet-email "
                      "and --nugsnet-password to set your email/password combination")
            return

        #streamUrl = self._login(email, password)
        #log.debug( "Streamurl " + str(streamUrl) )
        
        params = {
            'Input.Email': email,
            'Input.Password': password,
            'Input.RememberLogin' : 'false'
        }

        try:
            #res = self._doRequest( "GET", self.url, self.headers, {} )

            driver.get(self.url) 
            time.sleep( sleepTime )

            #div =  driver.find_element_by_id("site-content")
            #loginBtn = div.find_element_by_tag_name("button")

            btns = driver.find_elements_by_tag_name( "button" )
            for btn in btns:
                log.debug( "Checking driver btn " + btn.text + "attr " + str(btn.get_attribute( "data-testid") ))
                if btn.text == "ACCEPT":
                    log.debug( "clicking " + btn.text )
                    btn.click()
                    time.sleep(sleepTime)
                    break

            btns = driver.find_elements_by_tag_name( "button" )
            for btn in btns:
                log.debug( "Checking btn " + btn.text + " attr " + str(btn.get_attribute( "data-testid") ))

                if btn.get_attribute( "data-testid" ) == "user-login-action":
                    log.debug( "clicking " + btn.text )
                    btn.click()
                    time.sleep(sleepTime)
                    break


            btns = driver.find_elements_by_tag_name( "button" )
            for btn in btns:
                log.debug( "Checking btn " + btn.text + "attr " + str(btn.get_attribute( "data-testid") ))
                if btn.get_attribute( "data-testid" ) == "register-view-login-toggle-btn":
                    log.debug( "clicking " + btn.text )
                    btn.click()
                    time.sleep(sleepTime)


            emailInput = driver.find_element_by_name( "email")
            emailInput.send_keys(email)

            passwordInput = driver.find_element_by_name( "password")
            passwordInput.send_keys(password)


            btns = driver.find_elements_by_tag_name( "button" )
            for btn in btns:
                log.debug( "Checking btn " + btn.text + "attr " + str(btn.get_attribute( "data-testid") ))
                if btn.get_attribute( "data-testid" ) == "login-view-form-submit-btn":
                    log.debug( "clicking " + btn.text )
                    btn.click()
                    time.sleep(sleepTime)
                    break

            videoDiv = driver.find_element_by_id( "video-player" )
            video = videoDiv.find_element_by_tag_name( "video" )
            #log.debug( "GOOTTTT " + driver.page_source )
            streamUrl = video.get_attribute("src")
            log.debug( "GOOTTTT " + streamUrl )
            #driver.get( streamUrl )
            #time.sleep(sleepTime)

            #log.debug( "GOOTTTT " + driver.pageSource )

            #streamUrl = "https://d0bca9b68a812ed71b07e4247e1836c1.egress.mediapackage-vod.us-east-1.amazonaws.com/out/v1/b323210a4b514ee9be6ab7ced8ce0b65/8ffa49d6e66f45c89f1bff09e08a908f/4bb3c45cd2df4693bbead2a9c6201e58/index.m3u8"

            cookies = driver.get_cookies()
            for cookie in cookies:
                log.debug( 'cookie name' + cookie['name'] )
                self.session.http.cookies.set( cookie['name'], cookie['value'] )
            
            #streamUrl = "https://d227g91y7tnu85.cloudfront.net/out/v1/721b452e666448f8898613602c22928a/index.m3u"
                
            streamUrl = streamUrl.replace( "blob:", "" )
            #return HLSStream.parse_variant_playlist(self.session, streamUrl)
                
            streams = {}
            stream = HTTPStream(self.session, streamUrl )
            #stream = AkamaiHDStream(self.session, streamUrl )
            name = "best"
            streams[name] = stream

            return streams



            siteId = self._siteId_re.match(res.text).group(1)


            
            #log.debug( "siteID " + siteId )

            #//data='{"email":"rich@waters.io","password":"lhfs-xefr-lfpq-vutp-gjM4","siteId":"5f627f6ae63761002c65fcd6"}'
            #//res = self._doRequest( "POST" , "https://api.maestro.io/auth/v2/login", self.jsonHeaders, data )

            jwt = self._jwt_re.match(res.text).group(1)
            log.debug( "jwt " + jwt )
            
            #self.url += "&accessToken=" + jwt
            data = '{"accessToken" : "' + jwt + '"}'
            
            res = self._doRequest( "GET", self.url, self.headers, data )

            log.debug( "GOT " + res.text )
            exit(1)
            exit(1)
            
            if not self._authed_re.search( res.text ):
                log.info( "Already logged in" )
                return True

            log.info( "Logging in as: " + email )
            headers = self.headers
            headers['Referer'] = res.url
            verificationToken = self._verificationToken_re.match(res.text).group(1)
            params["__RequestVerificationToken"] = verificationToken
            postUrl = res.url
            res = self._doRequest( "POST", postUrl, headers, params )
            if self._authed_re.search( res.text ):
                log.error( "Login failed -- check username/password")
                return False


        except Exception as e:
            if '400 Client Error' in str(e):
                raise PluginError(
                    'Failed to login, check your username/password')
            raise e


        log.debug('Login succeeded')
        self.save_cookies(default_expires=self.TIME_SESSION)
        return True
    

    def _watch(self):
        page = self._doRequest( "GET",  self.url, self.headers, {} )
        match = self._m3u8_re.search(page.text)
        if match:
            stream_url = match.group(1)
            log.debug( "Found stream " + str( stream_url ) )
            return HLSStream.parse_variant_playlist(self.session, stream_url)

        log.error("Stream not found")


    def _doRequest(self, method, url, headers, params ):
        log.debug( method + " " + url + " " + str(headers) + " " + str( params ))
        if method == "GET" :
            return self.session.http.get(url, headers=headers, data=params)

        return self.session.http.post(url, headers=headers, data=params)


        

__plugin__ = CouchTourTv

import logging
import re

from streamlink import PluginError
from streamlink.plugin.plugin import parse_url_params
from streamlink.stream import AkamaiHDStream
from streamlink.utils import update_scheme

from streamlink.plugin import Plugin, PluginArgument, PluginArguments
from streamlink.plugin.api import useragents
from streamlink.stream import HLSStream
from urllib.parse import quote

log = logging.getLogger(__name__)



class NugsNet(Plugin):
    _url_re = re.compile(r'https?://(?:www\.)?nugs\.net')
    _m3u8_re = re.compile(r'''['"](http.+\.m3u8.*?)['"]''')
    _authed_re = re.compile( r'''<title>Login | nugs.net</title>''' )
    _verificationToken_re = re.compile( r'''.*?<input name="__RequestVerificationToken"[^>]*?value="([^"]+)".*''',  re.MULTILINE|re.DOTALL)
    TIME_SESSION = 60 * 60 * 24 * 30

    def __init__(self, url):
        super().__init__(url)
        self.headers = {
            'User-Agent': useragents.SAFARI,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Referer': 'https://id.nugs.net'
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
            """)
    )

    @classmethod
    def can_handle_url(cls, url):
        return cls._url_re.match(url) is not None

    def _get_streams(self):
        if self.options.get("purge_credentials"):
            self.clear_cookies()
            log.info("Credentials purged")

        email = self.get_option('email')
        password = self.get_option('password')
        if not email or not password:
            log.error("nugsnet requires authentication, use --nugsnet-email "
                      "and --nugsnet-password to set your email/password combination")
            return
        
        if not self._login(email, password):
            return False
        
        stream = self._watch()
        return stream

    def _login(self, email, password):
        
        params = {
            'Input.Email': email,
            'Input.Password': password,
            'Input.RememberLogin' : 'false'
        }

        try:
            res = self._doRequest( "GET", self.url, self.headers, {} )
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


        

__plugin__ = NugsNet

from streamlink.plugins.nugsnet import NugsNet
from tests.plugins import PluginCanHandleUrl


class TestPluginCanHandleUrlAnimeLab(PluginCanHandleUrl):
    __plugin__ = NugsNet

    should_match = [
        'https://www.nugs.net/',
        'https://www.nugs.net/on/demandware.store/Sites-NugsNet-Site/default/Stash-QueueVideo?skuID=543669&showID=25903&perfDate=01-16-2021&artistName=The%20Radiators&location=1-16-2021%20Tipitina%27s%20New%20Orleans%2c%20LA'
    ]

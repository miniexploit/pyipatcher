# from tihmstar's libipatcher

import requests
import re
from pyquery import PyQuery
import json




wiki = "https://www.theiphonewiki.com"


def getFirmwareKeysPage(device, buildnum):
    r = requests.get(wiki + "/w/index.php", params={'search': buildnum + " " + device})
    html = r.text
    link = re.search("\/wiki\/.*_" + buildnum + "_\(" + device + "\)", html)
    pagelink = wiki + link.group()
    return pagelink


def getkeys(device, buildnum):
    rsp = {}
    pagelink = getFirmwareKeysPage(device, buildnum)
    r = requests.get(pagelink)
    html = r.text

    rsp["identifier"] = device
    rsp["buildid"] = buildnum
    rsp["codename"] = pagelink.split("_")[0].split("/")[-1]
    rsp["updateramdiskexists"] = False
    rsp["restoreramdiskexists"] = False

    pq = PyQuery(html)
    keys = []
    for span in pq.items('span.mw-headline'):
        id = span.attr["id"]
        if id == "Update_Ramdisk":
            rsp["updateramdiskexists"] = True
        if id == "Restore_Ramdisk":
            rsp["restoreramdiskexists"] = True

        key = {}
        name = span.text()
        if name == "Root Filesystem":
            name = "RootFS"
        fname = span.parent().next("* > span.keypage-filename").text()

        iv = span.parent().siblings("*>*>code#keypage-" + name.lower() + "-iv").text()
        key_ = span.parent().siblings("*>*>code#keypage-" + name.lower() + "-key").text()
        kbag = span.parent().siblings("*>*>code#keypage-" + name.lower() + "-kbag").text()

        key["image"] = name
        key[
            "filename"] = fname  # WARNING This is the wrong format! (usually this would be full path instead of just the filename)

        key["iv"] = iv
        key["key"] = key_
        key["kbag"] = kbag

        keys.append(key)
    rsp["keys"] = keys
    return json.dumps(rsp)

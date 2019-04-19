#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# Author: 7z1
# Blog: http://www.7z1.xyz
import glob
import os
import sys
from copy import deepcopy

import requests
from requests import urllib3

urllib3.disable_warnings()
from config import BASE_DIR, headers, WAF_ATTACK_VECTORS, WAF_KEYWORD_VECTORS, WAF_PRODUCT_NAME

waf_path = BASE_DIR + '/waf/'

sys.path.insert(0, waf_path)


class WafCheck(object):
    def __init__(self, url):
        
        self.finger = ''
        self.nowaf = ''
        self.url = url
        self.waf_list = []
        self.init()
    
    def init(self):
        for found in glob.glob(os.path.join(waf_path, "*.py")):
            dirname, filename = os.path.split(found)
            if filename == "__init__.py":
                continue
            self.waf_list.append(__import__(filename.split('.')[0]))
        if 'http' not in self.url:
            print('python main.py http://www.xxx.com')
            print('请检查url格式是否正确!')
            sys.exit(0)

        if not self.url.endswith('/'):
            self.url = self.url + '/'
    
    def run(self):
        self.scan_site()
    
    def report_waf(self):
        print("[+] 发现网站防火墙 : " + self.finger + "\r\n")
    
    def scan_site(self):
        for vector in range(0, len(WAF_ATTACK_VECTORS)):
            turl = ''
            turl = deepcopy(self.url)
            
            add_url = WAF_ATTACK_VECTORS[vector]

            turl = turl + add_url
            
            try:
                resp = requests.get(turl, headers=headers, timeout=3, allow_redirects=True, verify=False)
            except Exception as e:
                print("连接目标失败：", e)
                continue
            
            if self.identify_waf(resp):
                self.report_waf()
                return True
            elif resp.status_code != 200:
                self.nowaf = "payload：{}，状态码：{}!!!".format(add_url, resp.status_code)
                print("[+] 网站未检测到防火墙或指纹识别失败: " + self.nowaf + "\r\n")
            else:
                self.nowaf = "payload：{}，状态码：{}!!!".format(add_url, resp.status_code)
                print("[+] 网站未检测到防火墙或指纹识别失败: " + self.nowaf + "\r\n")
        return False
    
    def check_resp(self, resp):
        content = ''
        if len(resp.text) != 0:
            content = resp.text.strip()
        for waf_keyword in range(0, len(WAF_KEYWORD_VECTORS)):
            if WAF_KEYWORD_VECTORS[waf_keyword] in content:
                self.finger = WAF_PRODUCT_NAME[waf_keyword]
                return True
            else:
                self.nowaf = "网站未检测到防火墙或指纹识别失败!!!"
        return False
    
    def identify_waf(self, resp):
        if not resp.text:
            return
        for waf_mod in self.waf_list:
            if waf_mod.detect(resp):
                self.finger = waf_mod.__product__
                return True
            else:
                self.nowaf = "[+] 站点未检测到防火墙或指纹识别失败!!!"
        
        if self.check_resp(resp):
            return True
        return False


if __name__ == '__main__':
    args = sys.argv
    if len(args) != 2:
        print('usage: python main.py http://www.xxx.com')
        sys.exit(0)
    wafidentify = WafCheck(args[1])
    wafidentify.run()

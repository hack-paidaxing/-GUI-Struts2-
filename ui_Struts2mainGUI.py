# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'ui_Struts2mainGUI.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(860, 753)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.layoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.layoutWidget.setGeometry(QtCore.QRect(0, 0, 851, 701))
        self.layoutWidget.setObjectName("layoutWidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.layoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.frame = QtWidgets.QFrame(self.layoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frame.sizePolicy().hasHeightForWidth())
        self.frame.setSizePolicy(sizePolicy)
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.pushButton = QtWidgets.QPushButton(self.frame)
        self.pushButton.setGeometry(QtCore.QRect(20, 110, 93, 28))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.frame)
        self.pushButton_2.setGeometry(QtCore.QRect(20, 160, 93, 28))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_6 = QtWidgets.QPushButton(self.frame)
        self.pushButton_6.setGeometry(QtCore.QRect(20, 210, 93, 28))
        self.pushButton_6.setObjectName("pushButton_6")
        self.horizontalLayout.addWidget(self.frame)
        self.frame_2 = QtWidgets.QFrame(self.layoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(5)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frame_2.sizePolicy().hasHeightForWidth())
        self.frame_2.setSizePolicy(sizePolicy)
        self.frame_2.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_2.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_2.setObjectName("frame_2")
        self.stackedWidget = QtWidgets.QStackedWidget(self.frame_2)
        self.stackedWidget.setGeometry(QtCore.QRect(0, 0, 701, 701))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.stackedWidget.sizePolicy().hasHeightForWidth())
        self.stackedWidget.setSizePolicy(sizePolicy)
        self.stackedWidget.setObjectName("stackedWidget")
        self.page = QtWidgets.QWidget()
        self.page.setObjectName("page")
        self.lineEdit = QtWidgets.QLineEdit(self.page)
        self.lineEdit.setGeometry(QtCore.QRect(50, 20, 391, 25))
        self.lineEdit.setObjectName("lineEdit")
        self.label = QtWidgets.QLabel(self.page)
        self.label.setGeometry(QtCore.QRect(10, 18, 81, 31))
        self.label.setObjectName("label")
        self.pushButton_4 = QtWidgets.QPushButton(self.page)
        self.pushButton_4.setGeometry(QtCore.QRect(600, 20, 93, 28))
        self.pushButton_4.setObjectName("pushButton_4")
        self.comboBox = QtWidgets.QComboBox(self.page)
        self.comboBox.setGeometry(QtCore.QRect(470, 20, 93, 28))
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.page)
        self.lineEdit_2.setGeometry(QtCore.QRect(60, 60, 231, 25))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.label_2 = QtWidgets.QLabel(self.page)
        self.label_2.setGeometry(QtCore.QRect(0, 65, 72, 15))
        self.label_2.setObjectName("label_2")
        self.label_4 = QtWidgets.QLabel(self.page)
        self.label_4.setGeometry(QtCore.QRect(300, 65, 72, 15))
        self.label_4.setObjectName("label_4")
        self.lineEdit_4 = QtWidgets.QLineEdit(self.page)
        self.lineEdit_4.setGeometry(QtCore.QRect(340, 60, 31, 25))
        self.lineEdit_4.setObjectName("lineEdit_4")
        self.pushButton_5 = QtWidgets.QPushButton(self.page)
        self.pushButton_5.setGeometry(QtCore.QRect(500, 60, 93, 28))
        self.pushButton_5.setObjectName("pushButton_5")
        self.pushButton_7 = QtWidgets.QPushButton(self.page)
        self.pushButton_7.setGeometry(QtCore.QRect(600, 60, 93, 28))
        self.pushButton_7.setObjectName("pushButton_7")
        self.textBrowser = QtWidgets.QTextBrowser(self.page)
        self.textBrowser.setGeometry(QtCore.QRect(0, 110, 701, 561))
        self.textBrowser.setObjectName("textBrowser")
        self.pushButton_14 = QtWidgets.QPushButton(self.page)
        self.pushButton_14.setGeometry(QtCore.QRect(390, 60, 93, 28))
        self.pushButton_14.setObjectName("pushButton_14")
        self.progressBar = QtWidgets.QProgressBar(self.page)
        self.progressBar.setGeometry(QtCore.QRect(0, 675, 701, 21))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName("progressBar")
        self.stackedWidget.addWidget(self.page)
        self.page_2 = QtWidgets.QWidget()
        self.page_2.setObjectName("page_2")
        self.lineEdit_5 = QtWidgets.QLineEdit(self.page_2)
        self.lineEdit_5.setGeometry(QtCore.QRect(50, 20, 391, 25))
        self.lineEdit_5.setObjectName("lineEdit_5")
        self.label_5 = QtWidgets.QLabel(self.page_2)
        self.label_5.setGeometry(QtCore.QRect(10, 18, 81, 31))
        self.label_5.setObjectName("label_5")
        self.comboBox_2 = QtWidgets.QComboBox(self.page_2)
        self.comboBox_2.setGeometry(QtCore.QRect(470, 20, 93, 28))
        self.comboBox_2.setObjectName("comboBox_2")
        self.comboBox_2.addItem("")
        self.comboBox_2.addItem("")
        self.comboBox_2.addItem("")
        self.comboBox_2.addItem("")
        self.comboBox_2.addItem("")
        self.comboBox_2.addItem("")
        self.comboBox_2.addItem("")
        self.lineEdit_6 = QtWidgets.QLineEdit(self.page_2)
        self.lineEdit_6.setGeometry(QtCore.QRect(50, 60, 391, 25))
        self.lineEdit_6.setObjectName("lineEdit_6")
        self.label_6 = QtWidgets.QLabel(self.page_2)
        self.label_6.setGeometry(QtCore.QRect(0, 65, 72, 15))
        self.label_6.setObjectName("label_6")
        self.pushButton_8 = QtWidgets.QPushButton(self.page_2)
        self.pushButton_8.setGeometry(QtCore.QRect(590, 20, 93, 28))
        self.pushButton_8.setObjectName("pushButton_8")
        self.pushButton_10 = QtWidgets.QPushButton(self.page_2)
        self.pushButton_10.setGeometry(QtCore.QRect(470, 60, 93, 28))
        self.pushButton_10.setObjectName("pushButton_10")
        self.pushButton_13 = QtWidgets.QPushButton(self.page_2)
        self.pushButton_13.setGeometry(QtCore.QRect(590, 60, 93, 28))
        self.pushButton_13.setObjectName("pushButton_13")
        self.textBrowser_3 = QtWidgets.QTextBrowser(self.page_2)
        self.textBrowser_3.setGeometry(QtCore.QRect(0, 110, 701, 581))
        self.textBrowser_3.setObjectName("textBrowser_3")
        self.stackedWidget.addWidget(self.page_2)
        self.page_3 = QtWidgets.QWidget()
        self.page_3.setObjectName("page_3")
        self.pushButton_3 = QtWidgets.QPushButton(self.page_3)
        self.pushButton_3.setGeometry(QtCore.QRect(550, 20, 93, 28))
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_9 = QtWidgets.QPushButton(self.page_3)
        self.pushButton_9.setGeometry(QtCore.QRect(440, 20, 93, 28))
        self.pushButton_9.setObjectName("pushButton_9")
        self.label_7 = QtWidgets.QLabel(self.page_3)
        self.label_7.setGeometry(QtCore.QRect(10, 18, 81, 31))
        self.label_7.setObjectName("label_7")
        self.lineEdit_7 = QtWidgets.QLineEdit(self.page_3)
        self.lineEdit_7.setGeometry(QtCore.QRect(50, 20, 351, 25))
        self.lineEdit_7.setObjectName("lineEdit_7")
        self.label_9 = QtWidgets.QLabel(self.page_3)
        self.label_9.setGeometry(QtCore.QRect(10, 65, 72, 15))
        self.label_9.setObjectName("label_9")
        self.lineEdit_9 = QtWidgets.QLineEdit(self.page_3)
        self.lineEdit_9.setGeometry(QtCore.QRect(50, 60, 171, 25))
        self.lineEdit_9.setObjectName("lineEdit_9")
        self.pushButton_11 = QtWidgets.QPushButton(self.page_3)
        self.pushButton_11.setGeometry(QtCore.QRect(440, 60, 93, 28))
        self.pushButton_11.setObjectName("pushButton_11")
        self.pushButton_12 = QtWidgets.QPushButton(self.page_3)
        self.pushButton_12.setGeometry(QtCore.QRect(310, 60, 93, 28))
        self.pushButton_12.setObjectName("pushButton_12")
        self.textBrowser_2 = QtWidgets.QTextBrowser(self.page_3)
        self.textBrowser_2.setGeometry(QtCore.QRect(0, 110, 701, 591))
        self.textBrowser_2.setObjectName("textBrowser_2")
        self.stackedWidget.addWidget(self.page_3)
        self.horizontalLayout.addWidget(self.frame_2)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 860, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.stackedWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.pushButton.setText(_translate("MainWindow", "检测"))
        self.pushButton_2.setText(_translate("MainWindow", "执行"))
        self.pushButton_6.setText(_translate("MainWindow", "批量"))
        self.label.setText(_translate("MainWindow", "URL："))
        self.pushButton_4.setText(_translate("MainWindow", "-> 执行"))
        self.comboBox.setItemText(0, _translate("MainWindow", "一键检测"))
        self.comboBox.setItemText(1, _translate("MainWindow", "S2-005"))
        self.comboBox.setItemText(2, _translate("MainWindow", "S2-008"))
        self.comboBox.setItemText(3, _translate("MainWindow", "S2-009"))
        self.comboBox.setItemText(4, _translate("MainWindow", "S2-016"))
        self.comboBox.setItemText(5, _translate("MainWindow", "S2-019"))
        self.comboBox.setItemText(6, _translate("MainWindow", "S2-032"))
        self.comboBox.setItemText(7, _translate("MainWindow", "S2-045"))
        self.label_2.setText(_translate("MainWindow", "Cookie:"))
        self.label_4.setText(_translate("MainWindow", "超时："))
        self.pushButton_5.setText(_translate("MainWindow", "清空"))
        self.pushButton_7.setText(_translate("MainWindow", "导出"))
        self.pushButton_14.setText(_translate("MainWindow", "导入"))
        self.label_5.setText(_translate("MainWindow", "URL："))
        self.comboBox_2.setItemText(0, _translate("MainWindow", "S2-005"))
        self.comboBox_2.setItemText(1, _translate("MainWindow", "S2-008"))
        self.comboBox_2.setItemText(2, _translate("MainWindow", "S2-009"))
        self.comboBox_2.setItemText(3, _translate("MainWindow", "S2-016"))
        self.comboBox_2.setItemText(4, _translate("MainWindow", "S2-019"))
        self.comboBox_2.setItemText(5, _translate("MainWindow", "S2-032"))
        self.comboBox_2.setItemText(6, _translate("MainWindow", "S2-045"))
        self.label_6.setText(_translate("MainWindow", "Code:"))
        self.pushButton_8.setText(_translate("MainWindow", "-> 执行"))
        self.pushButton_10.setText(_translate("MainWindow", "导出"))
        self.pushButton_13.setText(_translate("MainWindow", "清空"))
        self.pushButton_3.setText(_translate("MainWindow", "导入"))
        self.pushButton_9.setText(_translate("MainWindow", "执行"))
        self.label_7.setText(_translate("MainWindow", "路径："))
        self.label_9.setText(_translate("MainWindow", "超时："))
        self.pushButton_11.setText(_translate("MainWindow", "导出"))
        self.pushButton_12.setText(_translate("MainWindow", "清空"))


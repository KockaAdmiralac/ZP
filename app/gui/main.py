# Form implementation generated from reading ui file './main.ui'
#
# Created by: PyQt6 UI code generator 6.4.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(515, 496)
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.keyList = QtWidgets.QListWidget(parent=self.centralwidget)
        self.keyList.setGeometry(QtCore.QRect(10, 10, 231, 401))
        self.keyList.setObjectName("keyList")
        item = QtWidgets.QListWidgetItem()
        font = QtGui.QFont()
        font.setBold(True)
        item.setFont(font)
        item.setFlags(QtCore.Qt.ItemFlag.ItemIsDragEnabled|QtCore.Qt.ItemFlag.ItemIsUserCheckable|QtCore.Qt.ItemFlag.ItemIsEnabled)
        self.keyList.addItem(item)
        item = QtWidgets.QListWidgetItem()
        self.keyList.addItem(item)
        item = QtWidgets.QListWidgetItem()
        self.keyList.addItem(item)
        item = QtWidgets.QListWidgetItem()
        item.setFlags(QtCore.Qt.ItemFlag.ItemIsDragEnabled|QtCore.Qt.ItemFlag.ItemIsUserCheckable|QtCore.Qt.ItemFlag.ItemIsEnabled)
        self.keyList.addItem(item)
        item = QtWidgets.QListWidgetItem()
        font = QtGui.QFont()
        font.setBold(True)
        item.setFont(font)
        item.setFlags(QtCore.Qt.ItemFlag.ItemIsDragEnabled|QtCore.Qt.ItemFlag.ItemIsUserCheckable|QtCore.Qt.ItemFlag.ItemIsEnabled)
        self.keyList.addItem(item)
        item = QtWidgets.QListWidgetItem()
        self.keyList.addItem(item)
        item = QtWidgets.QListWidgetItem()
        self.keyList.addItem(item)
        self.buttonNew = QtWidgets.QPushButton(parent=self.centralwidget)
        self.buttonNew.setGeometry(QtCore.QRect(10, 420, 51, 25))
        self.buttonNew.setObjectName("buttonNew")
        self.buttonImport = QtWidgets.QPushButton(parent=self.centralwidget)
        self.buttonImport.setGeometry(QtCore.QRect(130, 420, 51, 25))
        self.buttonImport.setObjectName("buttonImport")
        self.buttonExport = QtWidgets.QPushButton(parent=self.centralwidget)
        self.buttonExport.setGeometry(QtCore.QRect(190, 420, 51, 25))
        self.buttonExport.setObjectName("buttonExport")
        self.tbKeyName = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.tbKeyName.setGeometry(QtCore.QRect(340, 20, 151, 25))
        self.tbKeyName.setReadOnly(True)
        self.tbKeyName.setObjectName("tbKeyName")
        self._l1 = QtWidgets.QLabel(parent=self.centralwidget)
        self._l1.setGeometry(QtCore.QRect(260, 20, 55, 17))
        self._l1.setObjectName("_l1")
        self._l2 = QtWidgets.QLabel(parent=self.centralwidget)
        self._l2.setGeometry(QtCore.QRect(260, 60, 55, 17))
        self._l2.setObjectName("_l2")
        self.tbKeyEmail = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.tbKeyEmail.setGeometry(QtCore.QRect(340, 60, 151, 25))
        self.tbKeyEmail.setReadOnly(True)
        self.tbKeyEmail.setObjectName("tbKeyEmail")
        self._l3 = QtWidgets.QLabel(parent=self.centralwidget)
        self._l3.setGeometry(QtCore.QRect(260, 100, 61, 17))
        self._l3.setObjectName("_l3")
        self.tbKeyAlgorithm = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.tbKeyAlgorithm.setGeometry(QtCore.QRect(340, 100, 151, 25))
        self.tbKeyAlgorithm.setReadOnly(True)
        self.tbKeyAlgorithm.setObjectName("tbKeyAlgorithm")
        self.buttonDelete = QtWidgets.QPushButton(parent=self.centralwidget)
        self.buttonDelete.setGeometry(QtCore.QRect(70, 420, 51, 25))
        self.buttonDelete.setObjectName("buttonDelete")
        self.tbCreatedAt = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.tbCreatedAt.setGeometry(QtCore.QRect(340, 140, 151, 25))
        self.tbCreatedAt.setReadOnly(True)
        self.tbCreatedAt.setObjectName("tbCreatedAt")
        self._l4 = QtWidgets.QLabel(parent=self.centralwidget)
        self._l4.setGeometry(QtCore.QRect(260, 140, 71, 17))
        self._l4.setObjectName("_l4")
        self.tbKeyId = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.tbKeyId.setGeometry(QtCore.QRect(340, 180, 151, 25))
        self.tbKeyId.setText("")
        self.tbKeyId.setReadOnly(True)
        self.tbKeyId.setObjectName("tbKeyId")
        self._l5 = QtWidgets.QLabel(parent=self.centralwidget)
        self._l5.setGeometry(QtCore.QRect(260, 180, 71, 17))
        self._l5.setObjectName("_l5")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 515, 22))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(parent=self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuMessage = QtWidgets.QMenu(parent=self.menubar)
        self.menuMessage.setObjectName("menuMessage")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionImport = QtGui.QAction(parent=MainWindow)
        self.actionImport.setObjectName("actionImport")
        self.actionExport = QtGui.QAction(parent=MainWindow)
        self.actionExport.setObjectName("actionExport")
        self.actionNew = QtGui.QAction(parent=MainWindow)
        self.actionNew.setObjectName("actionNew")
        self.actionSend = QtGui.QAction(parent=MainWindow)
        self.actionSend.setObjectName("actionSend")
        self.actionReceive = QtGui.QAction(parent=MainWindow)
        self.actionReceive.setObjectName("actionReceive")
        self.menuFile.addAction(self.actionNew)
        self.menuFile.addAction(self.actionImport)
        self.menuMessage.addAction(self.actionSend)
        self.menuMessage.addAction(self.actionReceive)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuMessage.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "ZP projekat"))
        __sortingEnabled = self.keyList.isSortingEnabled()
        self.keyList.setSortingEnabled(False)
        item = self.keyList.item(0)
        item.setText(_translate("MainWindow", "Public keyring"))
        item = self.keyList.item(1)
        item.setText(_translate("MainWindow", "    Katarina <katarina@gmail.com>"))
        item = self.keyList.item(2)
        item.setText(_translate("MainWindow", "    PuK2"))
        item = self.keyList.item(3)
        item.setText(_translate("MainWindow", "--------------------------------------------------------"))
        item = self.keyList.item(4)
        item.setText(_translate("MainWindow", "Private keyring"))
        item = self.keyList.item(5)
        item.setText(_translate("MainWindow", "    Katarina <katarina@gmail.com>"))
        item = self.keyList.item(6)
        item.setText(_translate("MainWindow", "    PrK2"))
        self.keyList.setSortingEnabled(__sortingEnabled)
        self.buttonNew.setText(_translate("MainWindow", "New"))
        self.buttonImport.setText(_translate("MainWindow", "Import"))
        self.buttonExport.setText(_translate("MainWindow", "Export"))
        self._l1.setText(_translate("MainWindow", "Name:"))
        self._l2.setText(_translate("MainWindow", "Email:"))
        self._l3.setText(_translate("MainWindow", "Algorithm:"))
        self.buttonDelete.setText(_translate("MainWindow", "Delete"))
        self._l4.setText(_translate("MainWindow", "Created at:"))
        self._l5.setText(_translate("MainWindow", "Key ID:"))
        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuMessage.setTitle(_translate("MainWindow", "Message"))
        self.actionImport.setText(_translate("MainWindow", "Import"))
        self.actionImport.setToolTip(_translate("MainWindow", "Import a PEM file with your key."))
        self.actionImport.setShortcut(_translate("MainWindow", "Ctrl+I"))
        self.actionExport.setText(_translate("MainWindow", "Export"))
        self.actionNew.setText(_translate("MainWindow", "New"))
        self.actionNew.setToolTip(_translate("MainWindow", "Create a new key pair."))
        self.actionNew.setShortcut(_translate("MainWindow", "Ctrl+N"))
        self.actionSend.setText(_translate("MainWindow", "Send"))
        self.actionSend.setToolTip(_translate("MainWindow", "Send a PGP message."))
        self.actionSend.setShortcut(_translate("MainWindow", "Ctrl+S"))
        self.actionReceive.setText(_translate("MainWindow", "Receive"))
        self.actionReceive.setToolTip(_translate("MainWindow", "Receive a PGP message."))
        self.actionReceive.setShortcut(_translate("MainWindow", "Ctrl+R"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())

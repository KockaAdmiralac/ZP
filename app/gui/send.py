# Form implementation generated from reading ui file './send.ui'
#
# Created by: PyQt6 UI code generator 6.4.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_SendMessageDialog(object):
    def setupUi(self, SendMessageDialog):
        SendMessageDialog.setObjectName("SendMessageDialog")
        SendMessageDialog.resize(469, 373)
        self.buttonBox = QtWidgets.QDialogButtonBox(parent=SendMessageDialog)
        self.buttonBox.setGeometry(QtCore.QRect(110, 330, 341, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Orientation.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.StandardButton.Cancel|QtWidgets.QDialogButtonBox.StandardButton.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.checkBase64 = QtWidgets.QCheckBox(parent=SendMessageDialog)
        self.checkBase64.setGeometry(QtCore.QRect(10, 260, 121, 23))
        self.checkBase64.setObjectName("checkBase64")
        self.checkSign = QtWidgets.QCheckBox(parent=SendMessageDialog)
        self.checkSign.setGeometry(QtCore.QRect(10, 220, 82, 23))
        self.checkSign.setObjectName("checkSign")
        self.comboSigningKey = QtWidgets.QComboBox(parent=SendMessageDialog)
        self.comboSigningKey.setGeometry(QtCore.QRect(280, 260, 171, 25))
        self.comboSigningKey.setObjectName("comboSigningKey")
        self.comboSigningKey.addItem("")
        self.comboSigningKey.addItem("")
        self.checkEncrypt = QtWidgets.QCheckBox(parent=SendMessageDialog)
        self.checkEncrypt.setGeometry(QtCore.QRect(10, 200, 82, 23))
        self.checkEncrypt.setObjectName("checkEncrypt")
        self._l1 = QtWidgets.QLabel(parent=SendMessageDialog)
        self._l1.setGeometry(QtCore.QRect(10, 10, 55, 17))
        self._l1.setObjectName("_l1")
        self._l2 = QtWidgets.QLabel(parent=SendMessageDialog)
        self._l2.setGeometry(QtCore.QRect(150, 260, 121, 20))
        self._l2.setObjectName("_l2")
        self.tbMessage = QtWidgets.QTextEdit(parent=SendMessageDialog)
        self.tbMessage.setGeometry(QtCore.QRect(10, 40, 451, 151))
        self.tbMessage.setObjectName("tbMessage")
        self.checkCompress = QtWidgets.QCheckBox(parent=SendMessageDialog)
        self.checkCompress.setGeometry(QtCore.QRect(10, 240, 82, 23))
        self.checkCompress.setObjectName("checkCompress")
        self.comboEncryptionKey = QtWidgets.QComboBox(parent=SendMessageDialog)
        self.comboEncryptionKey.setGeometry(QtCore.QRect(280, 200, 171, 25))
        self.comboEncryptionKey.setObjectName("comboEncryptionKey")
        self.comboEncryptionKey.addItem("")
        self.comboEncryptionKey.addItem("")
        self._l3 = QtWidgets.QLabel(parent=SendMessageDialog)
        self._l3.setGeometry(QtCore.QRect(150, 200, 121, 20))
        self._l3.setObjectName("_l3")
        self.comboEncryptionAlgorithm = QtWidgets.QComboBox(parent=SendMessageDialog)
        self.comboEncryptionAlgorithm.setGeometry(QtCore.QRect(280, 230, 171, 25))
        self.comboEncryptionAlgorithm.setObjectName("comboEncryptionAlgorithm")
        self.comboEncryptionAlgorithm.addItem("")
        self.comboEncryptionAlgorithm.addItem("")
        self._l4 = QtWidgets.QLabel(parent=SendMessageDialog)
        self._l4.setGeometry(QtCore.QRect(150, 230, 121, 20))
        self._l4.setObjectName("_l4")
        self._l5 = QtWidgets.QLabel(parent=SendMessageDialog)
        self._l5.setGeometry(QtCore.QRect(150, 290, 121, 20))
        self._l5.setObjectName("_l5")
        self.tbPassphrase = QtWidgets.QLineEdit(parent=SendMessageDialog)
        self.tbPassphrase.setGeometry(QtCore.QRect(282, 290, 171, 25))
        self.tbPassphrase.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.tbPassphrase.setObjectName("tbPassphrase")

        self.retranslateUi(SendMessageDialog)
        self.buttonBox.accepted.connect(SendMessageDialog.accept) # type: ignore
        self.buttonBox.rejected.connect(SendMessageDialog.reject) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(SendMessageDialog)

    def retranslateUi(self, SendMessageDialog):
        _translate = QtCore.QCoreApplication.translate
        SendMessageDialog.setWindowTitle(_translate("SendMessageDialog", "Send message"))
        self.checkBase64.setText(_translate("SendMessageDialog", "Radix-64 encode"))
        self.checkSign.setText(_translate("SendMessageDialog", "Sign"))
        self.comboSigningKey.setItemText(0, _translate("SendMessageDialog", "PrK1"))
        self.comboSigningKey.setItemText(1, _translate("SendMessageDialog", "PrK2"))
        self.checkEncrypt.setText(_translate("SendMessageDialog", "Encrypt"))
        self._l1.setText(_translate("SendMessageDialog", "Message:"))
        self._l2.setText(_translate("SendMessageDialog", "Signing key:"))
        self.checkCompress.setText(_translate("SendMessageDialog", "Compress"))
        self.comboEncryptionKey.setItemText(0, _translate("SendMessageDialog", "PuK1"))
        self.comboEncryptionKey.setItemText(1, _translate("SendMessageDialog", "PuK2"))
        self._l3.setText(_translate("SendMessageDialog", "Encryption key:"))
        self.comboEncryptionAlgorithm.setItemText(0, _translate("SendMessageDialog", "AES-128"))
        self.comboEncryptionAlgorithm.setItemText(1, _translate("SendMessageDialog", "IDEA"))
        self._l4.setText(_translate("SendMessageDialog", "Encryption algorithm:"))
        self._l5.setText(_translate("SendMessageDialog", "Signing passphrase:"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    SendMessageDialog = QtWidgets.QDialog()
    ui = Ui_SendMessageDialog()
    ui.setupUi(SendMessageDialog)
    SendMessageDialog.show()
    sys.exit(app.exec())

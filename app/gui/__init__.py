from sys import path
from PyQt6.QtWidgets import QDialog, QFileDialog, QMainWindow
from .create import Ui_NewKeyPairDialog
from .main import Ui_MainWindow
from .send import Ui_SendMessageDialog
from lib import KeyAlgorithms

path.append('..')

class ZPApp(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.connect()

    def connect(self):
        self.buttonNew.clicked.connect(self.newKeyPair)
        self.buttonDelete.clicked.connect(self.deleteKeyPair)
        self.buttonImport.clicked.connect(self.importKeyPair)
        self.buttonExport.clicked.connect(self.exportKeyPair)
        self.actionNew.triggered.connect(self.newKeyPair)
        self.actionImport.triggered.connect(self.importKeyPair)
        self.actionSend.triggered.connect(self.sendMessage)
        self.actionReceive.triggered.connect(self.receiveMessage)

    def newKeyPair(self):
        self.keypairDialog = NewKeyPairDialog(self)
        self.keypairDialog.accepted.connect(self.createKeyPair)
        self.keypairDialog.exec()
        self.keypairDialog = None

    def deleteKeyPair(self):
        # deleteKeyPair(...)
        self.statusbar.showMessage('Deleted key pair', 3000)

    def createKeyPair(self):
        if self.keypairDialog is None:
            return
        name = self.keypairDialog.tbName.text()
        email = self.keypairDialog.tbEmail.text()
        algorithm = [KeyAlgorithms.RSA, KeyAlgorithms.DSAElGamal][self.keypairDialog.comboAlgorithm.currentIndex()]
        size = [1024, 2048][self.keypairDialog.comboSize.currentIndex()]
        password = self.keypairDialog.tbPassword.text()
        # createKeyPair(name, email, algorithm, size, password)
        self.statusbar.showMessage(f'Created new key pair for {name} <{email}>', 3000)

    def importKeyPair(self):
        pemFilename, _ = QFileDialog.getOpenFileName(self, 'Select PEM file to import', filter='PEM files (*.pem)')
        if pemFilename == '':
            return
        # importKeyPair(pemFilename)
        self.statusbar.showMessage(f'Imported key pair from {pemFilename}', 3000)

    def exportKeyPair(self):
        pemFilename, _ = QFileDialog.getSaveFileName(self, 'Select the location for your exported keys', filter='PEM files (*.pem)')
        if pemFilename == '':
            return
        # exportKeyPair(..., pemFilename)
        self.statusbar.showMessage(f'Exported key pair to {pemFilename}', 3000)

    def sendMessage(self):
        dialog = SendMessageDialog(self)
        dialog.exec()

    def receiveMessage(self):
        pass

class SendMessageDialog(QDialog, Ui_SendMessageDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

class NewKeyPairDialog(QDialog, Ui_NewKeyPairDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

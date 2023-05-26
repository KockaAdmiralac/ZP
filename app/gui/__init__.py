from sys import path
from PyQt6 import QtGui
from PyQt6.QtWidgets import QDialog, QFileDialog, QMainWindow, QTableWidgetItem
from lib import Key
from lib.manage import find_key_by_keyID
from lib.pem import import_key, export_key
from lib.manage import create_key_pair, delete_key_pair, populate_private_keyring_table, find_key_by_keyID
from lib.keyring import Session
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
        self.populatePrivateKeyring()

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

    def _find_selected_key_id(self):
        selected_items = self.tablePrivateKeyring.selectedItems()
        found = -1
        key_id_column = 0
        if selected_items:
            selected_row = selected_items[0].row()
            item = self.tablePrivateKeyring.item(selected_row, key_id_column)
            if item:
                key_id = item.text()
                return key_id
        return found
    
    def deleteKeyPair(self):
        message = "Deleted key pair"
        key_id = self._find_selected_key_id()
        if key_id == -1:
            message = "No key selected."
        else:
            message += f" with keyID {key_id}"
            delete_key_pair(key_id=key_id)

        self.statusbar.showMessage(message, 3000)
        self.populatePrivateKeyring()

    def createKeyPair(self):
        if self.keypairDialog is None:
            return
        name = self.keypairDialog.tbName.text()
        email = self.keypairDialog.tbEmail.text()
        algorithm = [KeyAlgorithms.RSA, KeyAlgorithms.DSAElGamal][self.keypairDialog.comboAlgorithm.currentIndex()]
        size = [1024, 2048][self.keypairDialog.comboSize.currentIndex()]
        password = self.keypairDialog.tbPassword.text()
        create_key_pair(name, email, algorithm, size, password)
        self.statusbar.showMessage(f'Created new key pair for {name} <{email}>', 3000)
        self.populatePrivateKeyring()

    def populatePrivateKeyring(self):
        populate_private_keyring_table(self.tablePrivateKeyring)

    def importKeyPair(self):
        pemFilename, _ = QFileDialog.getOpenFileName(self, 'Select PEM file to import', filter='PEM files (*.pem)')
        if pemFilename == '':
            return
        import_key(filename=pemFilename)
        self.statusbar.showMessage(f'Imported key pair from {pemFilename}', 3000)

    def exportKeyPair(self):
        pemFilename, _ = QFileDialog.getSaveFileName(self, 'Select the location for your exported keys', filter='PEM files (*.pem)')
        if pemFilename == '':
            return
        
        key_id = self._find_selected_key_id()
        if key_id == -1:
            return
        else:
            key: Key = find_key_by_keyID(key_id)
            export_key(filename=pemFilename, key=key)
            self.statusbar.showMessage(f'Exported key pair to {pemFilename}', 3000)

    def sendMessage(self):
        dialog = SendMessageDialog(self)
        dialog.exec()

    def receiveMessage(self):
        pass

    def closeEvent(self, a0) -> None:
        session = Session()
        session.close()
        return super().closeEvent(a0)
    

class SendMessageDialog(QDialog, Ui_SendMessageDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

class NewKeyPairDialog(QDialog, Ui_NewKeyPairDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

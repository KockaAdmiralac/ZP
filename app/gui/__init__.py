from sys import path
from typing import Optional
from PyQt6.QtWidgets import QDialog, QFileDialog, QMainWindow, QMessageBox, QTableWidgetItem
from lib import Key, KeyAlgorithms
from lib.pem import import_key, export_key
from lib.manage import create_key_pair, delete_key_pair, find_key_by_key_id, get_all_keys
from lib.keyring import Session
from traceback import format_exception
from .create import Ui_NewKeyPairDialog
from .main import Ui_MainWindow
from .passphrase import Ui_PassphraseDialog
from .send import Ui_SendMessageDialog

path.append('..')

class ZPApp(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.connect()
        self.populatePrivateKeyring()
        self.passphrase = None

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

    def findSelectedKeyID(self):
        selectedItems = self.tablePrivateKeyring.selectedItems()
        if len(selectedItems) == 0:
            return -1
        selectedRow = selectedItems[0].row()
        item = self.tablePrivateKeyring.item(selectedRow, 0)
        return item.text()
    
    def deleteKeyPair(self):
        key_id = self.findSelectedKeyID()
        if key_id == -1:
            message = 'No key selected.'
        else:
            message = f'Deleted key pair with ID {key_id}.'
            try:
                delete_key_pair(key_id=key_id)
            except Exception as error:
                self.showError('An error occurred while deleting a key pair.', error)
                return
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
        try:
            create_key_pair(name, email, algorithm, size, password)
            self.statusbar.showMessage(f'Created new key pair for {name} <{email}>', 3000)
            self.populatePrivateKeyring()
        except Exception as error:
            self.showError('An error occurred while creating a key pair.', error)

    def populatePrivateKeyring(self):
        self.tablePrivateKeyring.clearContents()
        self.tablePrivateKeyring.setRowCount(0)
        private_keys = get_all_keys()
        for index, key_pair in enumerate(private_keys):
            self.tablePrivateKeyring.insertRow(index)
            self.tablePrivateKeyring.setItem(index, 0, QTableWidgetItem(str(key_pair.key_id)))
            self.tablePrivateKeyring.setItem(index, 1, QTableWidgetItem(str(key_pair.name)))
            self.tablePrivateKeyring.setItem(index, 2, QTableWidgetItem(str(key_pair.user_id)))
            self.tablePrivateKeyring.setItem(index, 3, QTableWidgetItem(str(key_pair.timestamp)))

    def importKeyPair(self):
        pemFilename, _ = QFileDialog.getOpenFileName(self, 'Select PEM file to import', filter='PEM files (*.pem)')
        if pemFilename == '':
            return
        passphrase = self.enterPassphrase()
        if passphrase is None:
            # User cancelled action.
            return
        import_key(pemFilename, None if passphrase == '' else passphrase)
        self.statusbar.showMessage(f'Imported key pair from {pemFilename}', 3000)

    def exportKeyPair(self):
        key_id = self.findSelectedKeyID()
        if key_id == -1:
            self.statusbar.showMessage('Ne key selected.', 3000)
            return
        pemFilename, _ = QFileDialog.getSaveFileName(self, 'Select the location for your exported keys', filter='PEM files (*.pem)')
        if pemFilename == '':
            return
        passphrase = self.enterPassphrase()
        if passphrase is None:
            # User cancelled action.
            return
        key = find_key_by_key_id(key_id)
        try:
            if passphrase == '':
                export_key(pemFilename, key.get_public_key_obj())
            else:
                # TODO: Export with a different passphrase? Export with no passphrase?
                export_key(pemFilename, key.get_private_key_obj(passphrase), passphrase)
            self.statusbar.showMessage(f'Exported key pair to {pemFilename}', 3000)
        except Exception as error:
            self.showError('Exporting key failed. Check whether the passphrase you entered is correct.', error)

    def sendMessage(self):
        dialog = SendMessageDialog(self)
        dialog.exec()

    def receiveMessage(self):
        pass

    def closeEvent(self, a0) -> None:
        session = Session()
        session.close()
        return super().closeEvent(a0)

    def showError(self, message: str, error: Exception):
        errorMsg = QMessageBox()
        errorMsg.setIcon(QMessageBox.Icon.Critical)
        errorMsg.setWindowTitle('Error')
        errorMsg.setText(message)
        errorMsg.setInformativeText(''.join(format_exception(error)))
        errorMsg.exec()

    def enterPassphrase(self) -> Optional[str]:
        self.passphraseDialog = PassphraseDialog()
        self.passphraseDialog.accepted.connect(self.enteredPassphrase)
        self.passphraseDialog.exec()
        self.passphraseDialog = None
        passphrase = self.passphrase
        self.passphrase = None
        return passphrase

    def enteredPassphrase(self):
        if self.passphraseDialog is not None:
            self.passphrase = self.passphraseDialog.tbPassphrase.text()

class SendMessageDialog(QDialog, Ui_SendMessageDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

class NewKeyPairDialog(QDialog, Ui_NewKeyPairDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

class PassphraseDialog(QDialog, Ui_PassphraseDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

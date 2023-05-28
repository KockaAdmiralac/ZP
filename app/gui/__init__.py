from sys import path
from typing import Optional, Tuple
from PyQt6.QtWidgets import QDialog, QFileDialog, QMainWindow, QMessageBox, QTableWidgetItem
from PyQt6 import QtCore, QtGui, QtWidgets
from lib.mail import Message
from lib import Cipher, Key, KeyAlgorithms
from lib.pem import import_key, export_key
from lib.manage import create_key_pair, delete_key_pair, get_all_keys_from_private_keyring, \
    get_all_keys_from_public_keyring, insert_imported_key
from lib.keyring import Session
from traceback import format_exception
from .create import Ui_NewKeyPairDialog
from .main import Ui_MainWindow
from .passphrase import Ui_PassphraseDialog
from .send import Ui_SendMessageDialog
from .importkey import Ui_ImportDialog

path.append('..')

class ZPApp(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.connect()
        self.boundaryIndex = 0
        self.viewKeysDict = {}
        self.passphrase = None
        self.name = None
        self.email = None
        self.populateKeyrings()

    def connect(self):
        self.buttonNew.clicked.connect(self.newKeyPair)
        self.buttonDelete.clicked.connect(self.deleteKeyPair)
        self.buttonImport.clicked.connect(self.importKeyPair)
        self.buttonExport.clicked.connect(self.exportKeyPair)
        self.actionNew.triggered.connect(self.newKeyPair)
        self.actionImport.triggered.connect(self.importKeyPair)
        self.actionSend.triggered.connect(self.sendMessage)
        self.actionReceive.triggered.connect(self.receiveMessage)
        self.keyList.itemSelectionChanged.connect(self.onKeySelected)

    def findSelectedKey(self):
        selected_items = self.keyList.selectedItems()
        if selected_items:
            selected_item = selected_items[0]
            index = self.keyList.row(selected_item)
            return index
        return -1
    
    def setKeyFields(self, name='', email='', timestamp='', key_id='', algorithm=''):
        self.tbKeyName.setText(name)
        self.tbKeyEmail.setText(email)
        self.tbCreatedAt.setText(timestamp)
        self.tbKeyId.setText(key_id)
        self.tbKeyAlgorithm.setText(algorithm)
    
    def onKeySelected(self):
        index = self.findSelectedKey()
        if index != -1:
            key = self.viewKeysDict[index]
            self.setKeyFields(name=key.name, email=key.user_id, timestamp=str(key.timestamp), \
                                 key_id=key.key_id, algorithm=key.algorithm)

    def newKeyPair(self):
        self.keypairDialog = NewKeyPairDialog(self)
        self.keypairDialog.accepted.connect(self.createKeyPair)
        self.keypairDialog.exec()
        self.keypairDialog = None

    def deleteKeyPair(self):
        index = self.findSelectedKey()
        if index != -1:
            key = self.viewKeysDict[index]
            delete_key_pair(key_id=key.key_id)
            message = f'Deleted key pair {key}.'
            self.setKeyFields()
        else:
            message = 'No key selected.'
        self.statusbar.showMessage(message, 3000)
        self.populateKeyrings()

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
            self.populateKeyrings()
        except Exception as error:
            self.showError('An error occurred while creating a key pair.', error)

    def createListItem(self, text: str, font = False, flags = False):
        item = QtWidgets.QListWidgetItem()
        if font:
            font = QtGui.QFont()
            font.setBold(True)
            item.setFont(font)
        if flags:
            item.setFlags(QtCore.Qt.ItemFlag.ItemIsDragEnabled|QtCore.Qt.ItemFlag.ItemIsUserCheckable|QtCore.Qt.ItemFlag.ItemIsEnabled)
        item.setText(text)
        self.keyList.addItem(item)

    def populateKeyrings(self):
        self.keyList.clear()
        self.createListItem('Public keyring', font=True, flags=True)
        self.viewKeysDict.clear()
        index = 1
        public_keyring_keys = get_all_keys_from_public_keyring()
        for key in public_keyring_keys:
            self.createListItem(text=f'    {key}')
            self.viewKeysDict[index] = key
            index += 1

        self.boundaryIndex = index
        self.createListItem(text='--------------------------------------', flags=True)
        self.createListItem('Private keyring', font=True, flags=True)
        index += 2
        private_keyring_keys = get_all_keys_from_private_keyring()
        for key in private_keyring_keys:
            self.createListItem(text=f'    {key}')
            self.viewKeysDict[index] = key
            index += 1

    def importKeyPair(self):
        pemFilename, _ = QFileDialog.getOpenFileName(self, 'Select PEM file to import', filter='PEM files (*.pem)')
        if pemFilename == '':
            return
        passphrase, name, email = self.enterOtherKeyAttributes()
        if passphrase is None or name is None or email is None:
            self.statusbar.showMessage(f'User canceled import dialog.', 3000)
            return
        key = import_key(pemFilename, None if passphrase == '' else passphrase)
        insert_imported_key(key=key, name=name, email=email, passphrase=passphrase)
        self.statusbar.showMessage(f'Imported key pair from {pemFilename}', 3000)
        self.populateKeyrings()

    def exportKeyPair(self):
        index = self.findSelectedKey()
        if index == -1:
            self.statusbar.showMessage('No key selected.', 3000)
            return
        pemFilename, _ = QFileDialog.getSaveFileName(self, 'Select the location for your exported keys', filter='PEM files (*.pem)')
        if pemFilename == '':
            return
        if index > self.boundaryIndex: # we selected a private key
            passphrase = self.enterPassphrase()
            if passphrase is None:
                self.statusbar.showMessage(f'User canceled export dialog.', 3000)
                return
        else:
            passphrase = ''
        key = self.viewKeysDict[index]
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
        try:
            dialog = SendMessageDialog(self)
            dialog.exec()
        except Exception as error:
            self.showError('Sending message failed. Check whether the passphrase you entered is correct.', error)

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

    def enterOtherKeyAttributes(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        self.otherKeyAttributesDialog = OtherKeyAttributesDialog()
        self.otherKeyAttributesDialog.accepted.connect(self.enteredOtherKeyAttributes)
        self.otherKeyAttributesDialog.exec()
        self.otherKeyAttributesDialog = None
        passphrase, name, email = self.passphrase, self.name, self.email
        self.passphrase = None
        self.name = None
        self.email = None
        return passphrase, name, email

    def enteredOtherKeyAttributes(self):
        if self.otherKeyAttributesDialog is not None:
            self.passphrase = self.otherKeyAttributesDialog.tbPassphrase.text()
            self.name = self.otherKeyAttributesDialog.tbKeyName.text()
            self.email = self.otherKeyAttributesDialog.tbKeyEmail.text()

class SendMessageDialog(QDialog, Ui_SendMessageDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.accepted.connect(self.sendMessage)
        self.publicKeys = get_all_keys_from_public_keyring()
        self.privateKeys = get_all_keys_from_private_keyring()
        self.comboEncryptionKey.clear()
        self.comboSigningKey.clear()
        if len(self.publicKeys) == 0:
            self.checkEncrypt.setCheckable(False)
        else:
            self.comboEncryptionKey.addItems([str(key) for key in self.publicKeys])
        if len(self.privateKeys) == 0:
            self.checkSign.setCheckable(False)
            self.tbPassphrase.setReadOnly(True)
        else:
            self.comboSigningKey.addItems([str(key) for key in self.privateKeys])

    def sendMessage(self):
        messageFilename, _ = QFileDialog.getSaveFileName(self, 'Select the location for your message', filter='MSG files (*.msg)')
        if messageFilename == '':
            return
        doEncrypt = self.checkEncrypt.isChecked()
        doSign = self.checkSign.isChecked()
        doCompress = self.checkCompress.isChecked()
        doBase64 = self.checkBase64.isChecked()
        message = self.tbMessage.toPlainText()
        publicKey = None
        publicKeyId = None
        privateKey = None
        privateKeyId = None
        cipher = [Cipher.AES128, Cipher.TripleDES][self.comboEncryptionAlgorithm.currentIndex()]
        if doEncrypt:
            publicKeyIndex = self.comboEncryptionKey.currentIndex()
            publicKeyData = self.publicKeys[publicKeyIndex]
            publicKey = publicKeyData.get_public_key_obj()
            publicKeyId = str(publicKeyData.key_id)
        if doSign:
            privateKeyIndex = self.comboSigningKey.currentIndex()
            privateKeyPassphrase = self.tbPassphrase.text()
            privateKeyData = self.privateKeys[privateKeyIndex]
            privateKey = privateKeyData.get_private_key_obj(privateKeyPassphrase)
            privateKeyId = str(privateKeyData.key_id)
        msg = Message(message, doCompress, doBase64, publicKey, publicKeyId, cipher, privateKey, privateKeyId)
        msg.write(messageFilename)
        # TODO:
        print(Message.read(messageFilename, '123'))

class NewKeyPairDialog(QDialog, Ui_NewKeyPairDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

class PassphraseDialog(QDialog, Ui_PassphraseDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

class OtherKeyAttributesDialog(QDialog, Ui_ImportDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
    

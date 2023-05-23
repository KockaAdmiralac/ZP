from sys import argv, exit
from PyQt6.QtWidgets import QApplication
from gui import ZPApp
from lib.keyring import databaseStartUp

if __name__ == '__main__':
    databaseStartUp()
    app = QApplication(argv)
    win = ZPApp()
    win.show()
    exit(app.exec())
    

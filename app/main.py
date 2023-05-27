from sys import argv, exit
from PyQt6.QtWidgets import QApplication
from gui import ZPApp
from lib.keyring import database_start_up

if __name__ == '__main__':
    database_start_up()
    app = QApplication(argv)
    win = ZPApp()
    win.show()
    exit(app.exec())

from sys import argv, exit
from PyQt6.QtWidgets import QApplication
from gui import ZPApp

if __name__ == '__main__':
    app = QApplication(argv)
    win = ZPApp()
    win.show()
    exit(app.exec())

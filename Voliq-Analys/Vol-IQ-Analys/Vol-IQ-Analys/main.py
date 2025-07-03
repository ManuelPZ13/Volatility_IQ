import sys
from PyQt6.QtWidgets import QApplication
from gui.mainwindow import MainWindow, set_dark_purple_theme

def main():
    app = QApplication(sys.argv)
    set_dark_purple_theme(app)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

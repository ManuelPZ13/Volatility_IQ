import sys
from gui.volatility_gui import VolatilityGUI
from PyQt6.QtWidgets import QApplication

def main():
    app = QApplication(sys.argv)
    gui = VolatilityGUI()
    gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

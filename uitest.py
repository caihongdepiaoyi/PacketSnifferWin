from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QToolBar, QMenu, QToolButton
from PyQt5.QtCore import Qt

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        # 创建工具栏
        toolbar = QToolBar("My Toolbar")
        self.addToolBar(Qt.LeftToolBarArea, toolbar) # 将工具栏添加到左上角

        # 添加动作到工具栏
        action = QAction("Action 1", self)
        toolbar.addAction(action)

        # 创建菜单
        menu = QMenu("Menu", self)
        menu.addAction("Action 2")
        menu.addAction("Action 3")

        # 创建工具按钮并将菜单添加到其中
        tool_button = QToolButton(self)
        tool_button.setPopupMode(QToolButton.MenuButtonPopup)
        tool_button.setMenu(menu)
        tool_button.setText("Menu")
        toolbar.addWidget(tool_button)

        # 设置主窗口
        self.setGeometry(100, 100, 800, 600)
        self.setWindowTitle("My Application")

if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()
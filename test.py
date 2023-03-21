from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel
import sys

app = QApplication(sys.argv)

# 创建窗口和垂直布局
window = QWidget()
layout = QVBoxLayout()
window.setLayout(layout)

# 创建标签和按钮，并添加到布局中
label = QLabel('Hello, PyQt5!')
button = QPushButton('Click me!')
layout.addWidget(label)
layout.addWidget(button)

# 显示窗口
window.show()

sys.exit(app.exec_())
# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'alert_panel_qt5.ui'
##
## Created by: Qt User Interface Compiler version 6.9.1
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (
    QCoreApplication,
    QMetaObject,
    QSize,
    Qt,
)
from PySide6.QtGui import (
    QFont,
    QPixmap,
)
from PySide6.QtWidgets import (
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
)


class Ui_AlertPanel(object):
    def setupUi(self, AlertPanel):
        if not AlertPanel.objectName():
            AlertPanel.setObjectName("AlertPanel")
        AlertPanel.resize(420, 360)
        AlertPanel.setMinimumSize(QSize(420, 360))
        AlertPanel.setMaximumSize(QSize(420, 360))
        AlertPanel.setStyleSheet(
            "\n"
            "    QGroupBox{font-weight:600;margin-top:8px;}\n"
            "    QGroupBox::title{subcontrol-origin: margin; left: 6px; padding:2px 4px;}\n"
            "    QLineEdit{border:1px solid #3c3f44;border-radius:6px;padding:6px;}\n"
            "    QLineEdit:focus{border-color:#5865f2;}\n"
            "    QPushButton{border:1px solid #3c3f44;border-radius:8px;padding:6px 12px;}\n"
            "    QPushButton:hover{border-color:#5865f2;}\n"
            "    #okButton{background:rgb(35,144,236);color:white;border:0;border-radius:8px;padding:6px 12px;}\n"
            "    #cancelButton{background:rgb(153,12,25);color:white;border:0;border-radius:8px;padding:6px 12px;}\n"
            "   "
        )
        self.rootLayout = QVBoxLayout(AlertPanel)
        self.rootLayout.setSpacing(10)
        self.rootLayout.setObjectName("rootLayout")
        self.rootLayout.setContentsMargins(12, 12, 12, 12)
        self.header = QFrame(AlertPanel)
        self.header.setObjectName("header")
        self.header.setFrameShape(QFrame.NoFrame)
        self.headerLayout = QHBoxLayout(self.header)
        self.headerLayout.setSpacing(12)
        self.headerLayout.setObjectName("headerLayout")
        self.logoArea = QLabel(self.header)
        self.logoArea.setObjectName("logoArea")
        self.logoArea.setMinimumSize(QSize(72, 72))
        self.logoArea.setMaximumSize(QSize(96, 96))
        self.logoArea.setFrameShape(QFrame.NoFrame)
        self.logoArea.setPixmap(QPixmap("../../resources/reveng_ai_logo.jpg"))
        self.logoArea.setScaledContents(True)

        self.headerLayout.addWidget(self.logoArea)

        self.titleLayout = QVBoxLayout()
        self.titleLayout.setObjectName("titleLayout")
        self.titleLabel = QLabel(self.header)
        self.titleLabel.setObjectName("titleLabel")
        self.titleLabel.setStyleSheet("font-size:18px;font-weight:600;")

        self.titleLayout.addWidget(self.titleLabel)

        self.subtitleLabel = QLabel(self.header)
        self.subtitleLabel.setObjectName("subtitleLabel")
        self.subtitleLabel.setAutoFillBackground(False)
        self.subtitleLabel.setStyleSheet("color: palette(mid);")

        self.titleLayout.addWidget(self.subtitleLabel)

        self.headerLayout.addLayout(self.titleLayout)

        self.rootLayout.addWidget(self.header)

        self.groupEndpoints = QGroupBox(AlertPanel)
        self.groupEndpoints.setObjectName("groupEndpoints")
        self.groupEndpoints.setMinimumSize(QSize(0, 150))
        self.errorLayout = QVBoxLayout(self.groupEndpoints)
        self.errorLayout.setSpacing(6)
        self.errorLayout.setObjectName("errorLayout")
        self.message = QLabel(self.groupEndpoints)
        self.message.setObjectName("message")
        sizePolicy = QSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.message.sizePolicy().hasHeightForWidth())
        self.message.setSizePolicy(sizePolicy)
        font = QFont()
        font.setPointSize(13)
        font.setItalic(True)
        self.message.setFont(font)
        self.message.setAutoFillBackground(False)
        self.message.setStyleSheet(
            "padding:6px;border:1px solid #3c3f44;border-radius:6px;"
        )
        self.message.setFrameShape(QFrame.NoFrame)
        self.message.setLineWidth(10)
        self.message.setTextFormat(Qt.MarkdownText)
        self.message.setScaledContents(False)
        self.message.setAlignment(Qt.AlignLeading | Qt.AlignLeft | Qt.AlignTop)
        self.message.setWordWrap(True)
        self.message.setMargin(5)
        self.message.setIndent(5)
        self.message.setTextInteractionFlags(Qt.NoTextInteraction)

        self.errorLayout.addWidget(self.message)

        self.rootLayout.addWidget(self.groupEndpoints)

        self.linkRow = QHBoxLayout()
        self.linkRow.setObjectName("linkRow")
        self.hspacer = QSpacerItem(
            0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding
        )

        self.linkRow.addItem(self.hspacer)

        self.rootLayout.addLayout(self.linkRow)

        self.buttonsRow = QHBoxLayout()
        self.buttonsRow.setObjectName("buttonsRow")
        self.horizontalSpacer = QSpacerItem(
            20, 40, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.buttonsRow.addItem(self.horizontalSpacer)

        self.okButton = QPushButton(AlertPanel)
        self.okButton.setObjectName("okButton")
        self.okButton.setMinimumSize(QSize(60, 30))
        self.okButton.setMaximumSize(QSize(60, 30))

        self.buttonsRow.addWidget(self.okButton)

        self.buttonsSpacer = QSpacerItem(
            0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.buttonsRow.addItem(self.buttonsSpacer)

        self.rootLayout.addLayout(self.buttonsRow)

        self.retranslateUi(AlertPanel)

        QMetaObject.connectSlotsByName(AlertPanel)

    # setupUi

    def retranslateUi(self, AlertPanel):
        AlertPanel.setWindowTitle(
            QCoreApplication.translate("AlertPanel", "RevEng.AI \u2014 Alert", None)
        )
        self.logoArea.setText("")
        self.titleLabel.setText(
            QCoreApplication.translate("AlertPanel", "RevEng.AI \u2014 Log", None)
        )
        self.subtitleLabel.setText(
            QCoreApplication.translate("AlertPanel", "Service Logs & Messages", None)
        )
        self.groupEndpoints.setTitle(
            QCoreApplication.translate("AlertPanel", "Log", None)
        )
        self.message.setText(
            QCoreApplication.translate("AlertPanel", "```Message```", None)
        )
        self.okButton.setText(QCoreApplication.translate("AlertPanel", "OK", None))

    # retranslateUi

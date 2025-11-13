# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'ai_decomp_panel_qt5.ui'
##
## Created by: Qt User Interface Compiler version 6.9.1
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (
    QCoreApplication,
    QMetaObject,
    QSize,
)
from PySide6.QtGui import (
    QIcon,
    QPixmap,
)
from PySide6.QtWidgets import (
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
)


class Ui_AiDecompPanel(object):
    def setupUi(self, AiDecompPanel):
        if not AiDecompPanel.objectName():
            AiDecompPanel.setObjectName("AiDecompPanel")
        AiDecompPanel.resize(900, 800)
        AiDecompPanel.setMinimumSize(QSize(900, 800))
        AiDecompPanel.setMaximumSize(QSize(900, 800))
        AiDecompPanel.setStyleSheet(
            "\n"
            "    QGroupBox{font-weight:600;margin-top:8px;}\n"
            "    QGroupBox::title{subcontrol-origin: margin; left: 6px; padding:2px 4px;}\n"
            "    QLineEdit{border:1px solid #3c3f44;border-radius:6px;padding:6px;}\n"
            "    QLineEdit:focus{border-color:#5865f2;}\n"
            "    QPushButton{border:1px solid #3c3f44;border-radius:8px;padding:6px 12px;}\n"
            "    QPushButton:hover{border-color:#5865f2;}\n"
            "    #okButton{background:rgb(35,144,236);color:white;border:0;border-radius:8px;padding:6px 12px;}\n"
            "    #cancelButton{background:rgb(153,12,25);color:white;border:0;border-radius:8px;padding:6px 12px;}\n"
            "\n"
            "    /* thumbs styling (requires SVGs that use currentColor) */\n"
            "    QPushButton#buttonThumbsUp { color: palette(text); }\n"
            "    QPushButton#buttonThumbsUp:checked { color: #16a34a; } /* green */\n"
            "\n"
            "    QPushButton#buttonThumbsDown { color: palette(text); }\n"
            "    QPushButton#buttonThumbsDown:checked { color: #dc2626; } /* red */\n"
            "   "
        )
        self.rootLayout = QVBoxLayout(AiDecompPanel)
        self.rootLayout.setSpacing(10)
        self.rootLayout.setObjectName("rootLayout")
        self.rootLayout.setContentsMargins(12, 12, 12, 12)
        self.header = QFrame(AiDecompPanel)
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
        self.subtitleLabel.setStyleSheet("color: palette(text);")

        self.titleLayout.addWidget(self.subtitleLabel)

        self.headerLayout.addLayout(self.titleLayout)

        self.horizontalSpacer_2 = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.headerLayout.addItem(self.horizontalSpacer_2)

        self.ratingLayout = QHBoxLayout()
        self.ratingLayout.setObjectName("ratingLayout")
        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QLabel(self.header)
        self.label.setObjectName("label")
        self.label.setStyleSheet("color: palette(text);")

        self.verticalLayout.addWidget(self.label)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.buttonThumbsDown = QPushButton(self.header)
        self.buttonThumbsDown.setObjectName("buttonThumbsDown")
        self.buttonThumbsDown.setMinimumSize(QSize(60, 0))
        icon = QIcon()
        icon.addFile(
            "../../resources/thumb_down.svg",
            QSize(),
            QIcon.Mode.Normal,
            QIcon.State.Off,
        )
        self.buttonThumbsDown.setIcon(icon)
        self.buttonThumbsDown.setIconSize(QSize(24, 24))
        self.buttonThumbsDown.setCheckable(True)

        self.horizontalLayout_2.addWidget(self.buttonThumbsDown)

        self.buttonThumbsUp = QPushButton(self.header)
        self.buttonThumbsUp.setObjectName("buttonThumbsUp")
        self.buttonThumbsUp.setMinimumSize(QSize(60, 0))
        icon1 = QIcon()
        icon1.addFile(
            "../../resources/thumb_up.svg", QSize(), QIcon.Mode.Normal, QIcon.State.Off
        )
        self.buttonThumbsUp.setIcon(icon1)
        self.buttonThumbsUp.setIconSize(QSize(24, 24))
        self.buttonThumbsUp.setCheckable(True)

        self.horizontalLayout_2.addWidget(self.buttonThumbsUp)

        self.horizontalSpacer = QSpacerItem(
            20, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.horizontalLayout_2.addItem(self.horizontalSpacer)

        self.verticalLayout.addLayout(self.horizontalLayout_2)

        self.ratingLayout.addLayout(self.verticalLayout)

        self.headerLayout.addLayout(self.ratingLayout)

        self.rootLayout.addWidget(self.header)

        self.groupEndpoints = QGroupBox(AiDecompPanel)
        self.groupEndpoints.setObjectName("groupEndpoints")
        self.groupEndpoints.setMinimumSize(QSize(0, 150))
        self.errorLayout = QVBoxLayout(self.groupEndpoints)
        self.errorLayout.setSpacing(6)
        self.errorLayout.setObjectName("errorLayout")
        self.codeEditor = QPlainTextEdit(self.groupEndpoints)
        self.codeEditor.setObjectName("codeEditor")
        sizePolicy = QSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.codeEditor.sizePolicy().hasHeightForWidth())
        self.codeEditor.setSizePolicy(sizePolicy)
        self.codeEditor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.codeEditor.setReadOnly(True)

        self.errorLayout.addWidget(self.codeEditor)

        self.rootLayout.addWidget(self.groupEndpoints)

        self.linkRow = QHBoxLayout()
        self.linkRow.setObjectName("linkRow")

        self.rootLayout.addLayout(self.linkRow)

        self.retranslateUi(AiDecompPanel)

        QMetaObject.connectSlotsByName(AiDecompPanel)

    # setupUi

    def retranslateUi(self, AiDecompPanel):
        AiDecompPanel.setWindowTitle(
            QCoreApplication.translate(
                "AiDecompPanel", "RevEng.AI \u2014 Ai Decomp", None
            )
        )
        self.logoArea.setText("")
        self.titleLabel.setText(
            QCoreApplication.translate(
                "AiDecompPanel", "RevEng.AI \u2014 AI Decomp", None
            )
        )
        self.subtitleLabel.setText(
            QCoreApplication.translate("AiDecompPanel", "AI Decompilation", None)
        )
        self.label.setText(
            QCoreApplication.translate(
                "AiDecompPanel", "Rate the AI-Decompilation", None
            )
        )
        self.buttonThumbsDown.setText("")
        self.buttonThumbsUp.setText("")
        self.groupEndpoints.setTitle(
            QCoreApplication.translate("AiDecompPanel", "Log", None)
        )

    # retranslateUi

# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'auth_panel_qt5.ui'
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
    QPixmap,
)
from PySide6.QtWidgets import (
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
)


class Ui_AuthPanel(object):
    def setupUi(self, AuthPanel):
        if not AuthPanel.objectName():
            AuthPanel.setObjectName("AuthPanel")
        AuthPanel.resize(420, 360)
        AuthPanel.setMinimumSize(QSize(420, 360))
        AuthPanel.setMaximumSize(QSize(420, 360))
        AuthPanel.setAutoFillBackground(False)
        AuthPanel.setStyleSheet(
            "\n"
            "    QGroupBox{font-weight:600;margin-top:8px;}\n"
            "    QGroupBox::title{subcontrol-origin: margin; left: 6px; padding:2px 4px;}\n"
            "    QLineEdit{border:1px solid #3c3f44;border-radius:6px;padding:6px;}\n"
            "    QLineEdit:focus{border-color:#5865f2;}\n"
            "    QPushButton{border:1px solid #3c3f44;border-radius:8px;padding:6px 12px;}\n"
            "    QPushButton:hover{border-color:#5865f2;}\n"
            "    #okButton {\n"
            "      background:rgb(35, 144, 236); color:white; border:0; border-radius:8px; padding:6px 12px;\n"
            "    }\n"
            "    #cancelButton {\n"
            "      background:rgb(153, 12, 25); color:white; border:0; border-radius:8px; padding:6px 12px;\n"
            "    }\n"
            "   "
        )
        self.rootLayout = QVBoxLayout(AuthPanel)
        self.rootLayout.setSpacing(10)
        self.rootLayout.setObjectName("rootLayout")
        self.rootLayout.setContentsMargins(12, 12, 12, 12)
        self.header = QFrame(AuthPanel)
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

        self.rootLayout.addWidget(self.header)

        self.groupEndpoints = QGroupBox(AuthPanel)
        self.groupEndpoints.setObjectName("groupEndpoints")
        self.formLayout = QFormLayout(self.groupEndpoints)
        self.formLayout.setObjectName("formLayout")
        self.formLayout.setLabelAlignment(Qt.AlignRight)
        self.labelApiUrl = QLabel(self.groupEndpoints)
        self.labelApiUrl.setObjectName("labelApiUrl")

        self.formLayout.setWidget(0, QFormLayout.ItemRole.LabelRole, self.labelApiUrl)

        self.apiUrlEdit = QLineEdit(self.groupEndpoints)
        self.apiUrlEdit.setObjectName("apiUrlEdit")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.apiUrlEdit.sizePolicy().hasHeightForWidth())
        self.apiUrlEdit.setSizePolicy(sizePolicy)
        self.apiUrlEdit.setMinimumSize(QSize(296, 32))
        self.apiUrlEdit.setMaximumSize(QSize(296, 32))

        self.formLayout.setWidget(0, QFormLayout.ItemRole.FieldRole, self.apiUrlEdit)

        self.labelPortalUrl = QLabel(self.groupEndpoints)
        self.labelPortalUrl.setObjectName("labelPortalUrl")

        self.formLayout.setWidget(
            1, QFormLayout.ItemRole.LabelRole, self.labelPortalUrl
        )

        self.portalUrlEdit = QLineEdit(self.groupEndpoints)
        self.portalUrlEdit.setObjectName("portalUrlEdit")
        sizePolicy.setHeightForWidth(
            self.portalUrlEdit.sizePolicy().hasHeightForWidth()
        )
        self.portalUrlEdit.setSizePolicy(sizePolicy)
        self.portalUrlEdit.setMinimumSize(QSize(296, 32))
        self.portalUrlEdit.setMaximumSize(QSize(296, 32))

        self.formLayout.setWidget(1, QFormLayout.ItemRole.FieldRole, self.portalUrlEdit)

        self.labelApiKey = QLabel(self.groupEndpoints)
        self.labelApiKey.setObjectName("labelApiKey")

        self.formLayout.setWidget(2, QFormLayout.ItemRole.LabelRole, self.labelApiKey)

        self.apiKeyEdit = QLineEdit(self.groupEndpoints)
        self.apiKeyEdit.setObjectName("apiKeyEdit")
        sizePolicy.setHeightForWidth(self.apiKeyEdit.sizePolicy().hasHeightForWidth())
        self.apiKeyEdit.setSizePolicy(sizePolicy)
        self.apiKeyEdit.setMinimumSize(QSize(296, 32))
        self.apiKeyEdit.setMaximumSize(QSize(296, 32))
        self.apiKeyEdit.setEchoMode(QLineEdit.Normal)

        self.formLayout.setWidget(2, QFormLayout.ItemRole.FieldRole, self.apiKeyEdit)

        self.rootLayout.addWidget(self.groupEndpoints)

        self.linkRow = QHBoxLayout()
        self.linkRow.setObjectName("linkRow")
        self.hspacer = QSpacerItem(
            0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.linkRow.addItem(self.hspacer)

        self.getKeyLink = QLabel(AuthPanel)
        self.getKeyLink.setObjectName("getKeyLink")
        self.getKeyLink.setStyleSheet("color: palette(highlight);")
        self.getKeyLink.setOpenExternalLinks(True)
        self.getKeyLink.setTextInteractionFlags(Qt.LinksAccessibleByMouse)

        self.linkRow.addWidget(self.getKeyLink)

        self.rootLayout.addLayout(self.linkRow)

        self.buttonsRow = QHBoxLayout()
        self.buttonsRow.setObjectName("buttonsRow")
        self.horizontalSpacer = QSpacerItem(
            40, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding
        )

        self.buttonsRow.addItem(self.horizontalSpacer)

        self.cancelButton = QPushButton(AuthPanel)
        self.cancelButton.setObjectName("cancelButton")

        self.buttonsRow.addWidget(self.cancelButton)

        self.okButton = QPushButton(AuthPanel)
        self.okButton.setObjectName("okButton")

        self.buttonsRow.addWidget(self.okButton)

        self.buttonsSpacer = QSpacerItem(
            0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding
        )

        self.buttonsRow.addItem(self.buttonsSpacer)

        self.rootLayout.addLayout(self.buttonsRow)

        # if QT_CONFIG(shortcut)
        self.labelApiUrl.setBuddy(self.apiUrlEdit)
        self.labelPortalUrl.setBuddy(self.portalUrlEdit)
        self.labelApiKey.setBuddy(self.apiKeyEdit)
        # endif // QT_CONFIG(shortcut)

        self.retranslateUi(AuthPanel)

        QMetaObject.connectSlotsByName(AuthPanel)

    # setupUi

    def retranslateUi(self, AuthPanel):
        AuthPanel.setWindowTitle(
            QCoreApplication.translate("AuthPanel", "RevEng.AI \u2014 Connection", None)
        )
        self.logoArea.setText("")
        self.titleLabel.setText(
            QCoreApplication.translate(
                "AuthPanel", "RevEng.AI \u2014 Configuration", None
            )
        )
        self.subtitleLabel.setText(
            QCoreApplication.translate(
                "AuthPanel", "Configure service endpoints and credentials", None
            )
        )
        self.groupEndpoints.setTitle(
            QCoreApplication.translate("AuthPanel", "Endpoints", None)
        )
        self.labelApiUrl.setText(
            QCoreApplication.translate("AuthPanel", "API URL", None)
        )
        self.apiUrlEdit.setText(
            QCoreApplication.translate("AuthPanel", "https://api.reveng.ai", None)
        )
        self.apiUrlEdit.setPlaceholderText(
            QCoreApplication.translate("AuthPanel", "https://api.reveng.ai", None)
        )
        self.labelPortalUrl.setText(
            QCoreApplication.translate("AuthPanel", "Portal URL", None)
        )
        self.portalUrlEdit.setText(
            QCoreApplication.translate("AuthPanel", "https://portal.reveng.ai", None)
        )
        self.portalUrlEdit.setPlaceholderText(
            QCoreApplication.translate("AuthPanel", "https://portal.reveng.ai", None)
        )
        self.labelApiKey.setText(
            QCoreApplication.translate("AuthPanel", "API Key", None)
        )
        self.apiKeyEdit.setPlaceholderText(
            QCoreApplication.translate("AuthPanel", "Paste your API key\u2026", None)
        )
        # if QT_CONFIG(tooltip)
        self.getKeyLink.setToolTip(
            QCoreApplication.translate(
                "AuthPanel",
                "Open the RevEng.AI portal to create or view your API key",
                None,
            )
        )
        # endif // QT_CONFIG(tooltip)
        self.getKeyLink.setText(
            QCoreApplication.translate(
                "AuthPanel", '<a href="#">Get an API key</a>', None
            )
        )
        self.cancelButton.setText(
            QCoreApplication.translate("AuthPanel", "Cancel", None)
        )
        self.okButton.setText(QCoreApplication.translate("AuthPanel", "OK", None))

    # retranslateUi

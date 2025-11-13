# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'analyse_panel_qt5.ui'
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
    QRadioButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
)


class Ui_AuthPanel(object):
    def setupUi(self, AuthPanel):
        if not AuthPanel.objectName():
            AuthPanel.setObjectName("AuthPanel")
        AuthPanel.resize(520, 420)
        AuthPanel.setMinimumSize(QSize(520, 420))
        AuthPanel.setMaximumSize(QSize(520, 420))
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
        self.subtitleLabel.setStyleSheet("color: palette(placeholderText);")

        self.titleLayout.addWidget(self.subtitleLabel)

        self.headerLayout.addLayout(self.titleLayout)

        self.rootLayout.addWidget(self.header)

        self.groupEndpoints = QGroupBox(AuthPanel)
        self.groupEndpoints.setObjectName("groupEndpoints")
        self.groupEndpoints.setMinimumSize(QSize(496, 200))
        self.groupEndpoints.setMaximumSize(QSize(496, 200))
        self.formLayout = QFormLayout(self.groupEndpoints)
        self.formLayout.setObjectName("formLayout")
        self.formLayout.setLabelAlignment(Qt.AlignRight)
        self.horizontalSpacer_2 = QSpacerItem(
            1, 1, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.formLayout.setItem(
            0, QFormLayout.ItemRole.FieldRole, self.horizontalSpacer_2
        )

        self.labelFileName = QLabel(self.groupEndpoints)
        self.labelFileName.setObjectName("labelFileName")

        self.formLayout.setWidget(1, QFormLayout.ItemRole.LabelRole, self.labelFileName)

        self.apiFileName = QLineEdit(self.groupEndpoints)
        self.apiFileName.setObjectName("apiFileName")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.apiFileName.sizePolicy().hasHeightForWidth())
        self.apiFileName.setSizePolicy(sizePolicy)
        self.apiFileName.setMinimumSize(QSize(296, 32))
        self.apiFileName.setMaximumSize(QSize(296, 32))

        self.formLayout.setWidget(1, QFormLayout.ItemRole.FieldRole, self.apiFileName)

        self.labelTags = QLabel(self.groupEndpoints)
        self.labelTags.setObjectName("labelTags")

        self.formLayout.setWidget(2, QFormLayout.ItemRole.LabelRole, self.labelTags)

        self.apiTags = QLineEdit(self.groupEndpoints)
        self.apiTags.setObjectName("apiTags")
        sizePolicy.setHeightForWidth(self.apiTags.sizePolicy().hasHeightForWidth())
        self.apiTags.setSizePolicy(sizePolicy)
        self.apiTags.setMinimumSize(QSize(296, 32))
        self.apiTags.setMaximumSize(QSize(296, 32))

        self.formLayout.setWidget(2, QFormLayout.ItemRole.FieldRole, self.apiTags)

        self.labelDebugFile = QLabel(self.groupEndpoints)
        self.labelDebugFile.setObjectName("labelDebugFile")

        self.formLayout.setWidget(
            3, QFormLayout.ItemRole.LabelRole, self.labelDebugFile
        )

        self.debugFileLayout = QHBoxLayout()
        self.debugFileLayout.setSpacing(6)
        self.debugFileLayout.setObjectName("debugFileLayout")
        self.debugFileLayout.setContentsMargins(0, 0, 0, 0)
        self.apiDebugFile = QLineEdit(self.groupEndpoints)
        self.apiDebugFile.setObjectName("apiDebugFile")
        sizePolicy.setHeightForWidth(self.apiDebugFile.sizePolicy().hasHeightForWidth())
        self.apiDebugFile.setSizePolicy(sizePolicy)
        self.apiDebugFile.setMinimumSize(QSize(296, 32))
        self.apiDebugFile.setMaximumSize(QSize(296, 32))
        self.apiDebugFile.setEchoMode(QLineEdit.Normal)
        self.apiDebugFile.setReadOnly(True)

        self.debugFileLayout.addWidget(self.apiDebugFile)

        self.btnBrowseDebug = QPushButton(self.groupEndpoints)
        self.btnBrowseDebug.setObjectName("btnBrowseDebug")

        self.debugFileLayout.addWidget(self.btnBrowseDebug)

        self.formLayout.setLayout(
            3, QFormLayout.ItemRole.FieldRole, self.debugFileLayout
        )

        self.labelScope = QLabel(self.groupEndpoints)
        self.labelScope.setObjectName("labelScope")

        self.formLayout.setWidget(4, QFormLayout.ItemRole.LabelRole, self.labelScope)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.radioButton_2 = QRadioButton(self.groupEndpoints)
        self.radioButton_2.setObjectName("radioButton_2")
        self.radioButton_2.setChecked(True)

        self.horizontalLayout.addWidget(self.radioButton_2)

        self.radioButton = QRadioButton(self.groupEndpoints)
        self.radioButton.setObjectName("radioButton")

        self.horizontalLayout.addWidget(self.radioButton)

        self.formLayout.setLayout(
            4, QFormLayout.ItemRole.FieldRole, self.horizontalLayout
        )

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
        self.labelFileName.setBuddy(self.apiFileName)
        self.labelTags.setBuddy(self.apiTags)
        self.labelDebugFile.setBuddy(self.apiDebugFile)
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
            QCoreApplication.translate("AuthPanel", "RevEng.AI \u2014 Analysis", None)
        )
        self.subtitleLabel.setText(
            QCoreApplication.translate(
                "AuthPanel", "Analyse your binary with RevEng.AI", None
            )
        )
        self.groupEndpoints.setTitle(
            QCoreApplication.translate("AuthPanel", "Analysis Config", None)
        )
        self.labelFileName.setText(
            QCoreApplication.translate("AuthPanel", "File Name", None)
        )
        self.apiFileName.setText("")
        self.apiFileName.setPlaceholderText(
            QCoreApplication.translate("AuthPanel", "File Name", None)
        )
        self.labelTags.setText(QCoreApplication.translate("AuthPanel", "Tags", None))
        self.apiTags.setText("")
        self.apiTags.setPlaceholderText(
            QCoreApplication.translate("AuthPanel", "tag1,  tag2,  tag3", None)
        )
        self.labelDebugFile.setText(
            QCoreApplication.translate("AuthPanel", "Debug File", None)
        )
        self.apiDebugFile.setPlaceholderText(
            QCoreApplication.translate("AuthPanel", "File Name", None)
        )
        # if QT_CONFIG(tooltip)
        self.btnBrowseDebug.setToolTip(
            QCoreApplication.translate("AuthPanel", "Browse for debug file", None)
        )
        # endif // QT_CONFIG(tooltip)
        self.btnBrowseDebug.setText(
            QCoreApplication.translate("AuthPanel", "Browse\u2026", None)
        )
        self.labelScope.setText(QCoreApplication.translate("AuthPanel", "Scope", None))
        self.radioButton_2.setText(
            QCoreApplication.translate("AuthPanel", "Public", None)
        )
        self.radioButton.setText(
            QCoreApplication.translate("AuthPanel", "Private", None)
        )
        self.cancelButton.setText(
            QCoreApplication.translate("AuthPanel", "Cancel", None)
        )
        self.okButton.setText(QCoreApplication.translate("AuthPanel", "OK", None))

    # retranslateUi

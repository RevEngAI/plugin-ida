# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'auto_unstrip_panel_qt5.ui'
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
    QFont,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)


class Ui_AutoUnstripPanel(object):
    def setupUi(self, AutoUnstripPanel):
        if not AutoUnstripPanel.objectName():
            AutoUnstripPanel.setObjectName("AutoUnstripPanel")
        AutoUnstripPanel.resize(600, 400)
        AutoUnstripPanel.setMinimumSize(QSize(600, 400))
        AutoUnstripPanel.setMaximumSize(QSize(600, 400))
        AutoUnstripPanel.setAutoFillBackground(False)
        AutoUnstripPanel.setStyleSheet(
            "\n"
            "    QGroupBox{font-weight:600;margin-top:8px;}\n"
            "    QGroupBox::title{subcontrol-origin: margin; left: 6px; padding:2px 4px;}\n"
            "    QLineEdit{border:1px solid #3c3f44;border-radius:6px;padding:6px;}\n"
            "    QLineEdit:focus{border-color:#5865f2;}\n"
            "    QPushButton{border:1px solid #3c3f44;border-radius:8px;padding:6px 12px;}\n"
            "    QPushButton:hover{border-color:#5865f2;}\n"
            "    #okButton { background:rgb(35,144,236); color:white; border:0; border-radius:8px; padding:6px 12px; }\n"
            "    #cancelButton { background:rgb(153,12,25); color:white; border:0; border-radius:8px; padding:6px 12px; }\n"
            "   "
        )
        self.rootLayout = QVBoxLayout(AutoUnstripPanel)
        self.rootLayout.setSpacing(10)
        self.rootLayout.setObjectName("rootLayout")
        self.rootLayout.setContentsMargins(12, 12, 12, 12)
        self.header = QFrame(AutoUnstripPanel)
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

        self.groupRenames = QGroupBox(AutoUnstripPanel)
        self.groupRenames.setObjectName("groupRenames")
        self.groupLayout = QVBoxLayout(self.groupRenames)
        self.groupLayout.setSpacing(8)
        self.groupLayout.setObjectName("groupLayout")
        self.tableRenames = QTableWidget(self.groupRenames)
        if self.tableRenames.columnCount() < 4:
            self.tableRenames.setColumnCount(4)
        font = QFont()
        font.setBold(True)
        __qtablewidgetitem = QTableWidgetItem()
        __qtablewidgetitem.setFont(font)
        self.tableRenames.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        __qtablewidgetitem1.setFont(font)
        self.tableRenames.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        __qtablewidgetitem2.setFont(font)
        self.tableRenames.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        __qtablewidgetitem3.setFont(font)
        self.tableRenames.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        self.tableRenames.setObjectName("tableRenames")
        self.tableRenames.setMinimumSize(QSize(550, 0))
        self.tableRenames.setMaximumSize(QSize(550, 16777215))
        self.tableRenames.setEditTriggers(
            QAbstractItemView.DoubleClicked | QAbstractItemView.EditKeyPressed
        )
        self.tableRenames.setAlternatingRowColors(True)
        self.tableRenames.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tableRenames.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableRenames.setSortingEnabled(True)
        self.tableRenames.setWordWrap(True)
        self.tableRenames.setRowCount(0)
        self.tableRenames.setColumnCount(4)
        self.tableRenames.horizontalHeader().setVisible(True)
        self.tableRenames.horizontalHeader().setCascadingSectionResizes(True)
        self.tableRenames.horizontalHeader().setMinimumSectionSize(10)
        self.tableRenames.horizontalHeader().setDefaultSectionSize(110)
        self.tableRenames.horizontalHeader().setStretchLastSection(True)
        self.tableRenames.verticalHeader().setVisible(False)

        self.groupLayout.addWidget(self.tableRenames)

        self.rootLayout.addWidget(self.groupRenames)

        self.buttonsRow = QHBoxLayout()
        self.buttonsRow.setObjectName("buttonsRow")
        self.buttonsLeftSpacer = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.buttonsRow.addItem(self.buttonsLeftSpacer)

        self.okButton = QPushButton(AutoUnstripPanel)
        self.okButton.setObjectName("okButton")

        self.buttonsRow.addWidget(self.okButton)

        self.buttonsRightSpacer = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.buttonsRow.addItem(self.buttonsRightSpacer)

        self.rootLayout.addLayout(self.buttonsRow)

        self.retranslateUi(AutoUnstripPanel)

        self.okButton.setDefault(True)

        QMetaObject.connectSlotsByName(AutoUnstripPanel)

    # setupUi

    def retranslateUi(self, AutoUnstripPanel):
        AutoUnstripPanel.setWindowTitle(
            QCoreApplication.translate(
                "AutoUnstripPanel", "RevEng.AI \u2014 Auto Unstrip", None
            )
        )
        self.logoArea.setText("")
        self.titleLabel.setText(
            QCoreApplication.translate(
                "AutoUnstripPanel", "RevEng.AI \u2014 Auto Unstrip", None
            )
        )
        self.subtitleLabel.setText(
            QCoreApplication.translate(
                "AutoUnstripPanel", "Automatically rename unknown functions.", None
            )
        )
        self.groupRenames.setTitle(
            QCoreApplication.translate("AutoUnstripPanel", "Applied Names", None)
        )
        ___qtablewidgetitem = self.tableRenames.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(
            QCoreApplication.translate("AutoUnstripPanel", "Select", None)
        )
        ___qtablewidgetitem1 = self.tableRenames.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(
            QCoreApplication.translate("AutoUnstripPanel", "Virtual Address", None)
        )
        ___qtablewidgetitem2 = self.tableRenames.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(
            QCoreApplication.translate("AutoUnstripPanel", "Current Name", None)
        )
        ___qtablewidgetitem3 = self.tableRenames.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(
            QCoreApplication.translate("AutoUnstripPanel", "Suggested Name", None)
        )
        self.okButton.setText(
            QCoreApplication.translate("AutoUnstripPanel", "OK", None)
        )

    # retranslateUi

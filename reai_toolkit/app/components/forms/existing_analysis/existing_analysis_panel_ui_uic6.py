# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'existing_analysis_panel.ui'
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
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractScrollArea,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class Ui_ExistingAnalysesPanel(object):
    def setupUi(self, ExistingAnalysesPanel):
        if not ExistingAnalysesPanel.objectName():
            ExistingAnalysesPanel.setObjectName("ExistingAnalysesPanel")
        ExistingAnalysesPanel.resize(800, 800)
        ExistingAnalysesPanel.setMinimumSize(QSize(800, 800))
        ExistingAnalysesPanel.setMaximumSize(QSize(800, 800))
        ExistingAnalysesPanel.setAutoFillBackground(False)
        ExistingAnalysesPanel.setStyleSheet(
            "\n"
            "    QGroupBox{font-weight:600;margin-top:8px;}\n"
            "    QGroupBox::title{subcontrol-origin: margin; left: 6px; padding:2px 4px;}\n"
            "    QLineEdit{border:1px solid #3c3f44;border-radius:6px;padding:6px;}\n"
            "    QLineEdit:focus{border-color:#5865f2;}\n"
            "    QPushButton{border:1px solid #3c3f44;border-radius:8px;padding:6px 12px;}\n"
            "    QPushButton:hover{border-color:#5865f2;}\n"
            "    #okButton { background:rgb(35,144,236); color:white; border:0; border-radius:8px; padding:6px 12px; }\n"
            "    #cancelButton { background:rgb(153,12,25); color:white; border:0; border-radius:8px; padding:6px 12px; }\n"
            "    /* Popup styling */\n"
            "    #collectionsPopupFrame { background:#1b1c20; border:1px solid #3c3f44; border-radius:10px; }\n"
            "    #collectionsPopupHeader { font-weight:600; padding:6px 8px; }\n"
            "    #binariesPopupFrame { background:#1b1c20; border:1px solid #3c3f44; border-radius:10px; }\n"
            "    #binariesPopupHeader { font-weight:600; padding:6px 8px; }\n"
            "   "
        )
        self.rootLayout = QVBoxLayout(ExistingAnalysesPanel)
        self.rootLayout.setSpacing(10)
        self.rootLayout.setObjectName("rootLayout")
        self.rootLayout.setContentsMargins(12, 12, 12, 12)
        self.header = QFrame(ExistingAnalysesPanel)
        self.header.setObjectName("header")
        self.header.setFrameShape(QFrame.NoFrame)
        self.headerLayout = QHBoxLayout(self.header)
        self.headerLayout.setSpacing(12)
        self.headerLayout.setObjectName("headerLayout")
        self.logoArea = QLabel(self.header)
        self.logoArea.setObjectName("logoArea")
        self.logoArea.setMinimumSize(QSize(96, 96))
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
        self.subtitleLabel.setStyleSheet("color: palette(placeholderText);")

        self.titleLayout.addWidget(self.subtitleLabel)

        self.headerLayout.addLayout(self.titleLayout)

        self.rootLayout.addWidget(self.header)

        self.stack = QStackedWidget(ExistingAnalysesPanel)
        self.stack.setObjectName("stack")
        self.pageSelect = QWidget()
        self.pageSelect.setObjectName("pageSelect")
        self.pageSelectLayout = QVBoxLayout(self.pageSelect)
        self.pageSelectLayout.setObjectName("pageSelectLayout")
        self.groupSelect = QGroupBox(self.pageSelect)
        self.groupSelect.setObjectName("groupSelect")
        self.groupSelectLayout = QVBoxLayout(self.groupSelect)
        self.groupSelectLayout.setObjectName("groupSelectLayout")
        self.tableAnalyses = QTableWidget(self.groupSelect)
        if self.tableAnalyses.columnCount() < 4:
            self.tableAnalyses.setColumnCount(4)
        __qtablewidgetitem = QTableWidgetItem()
        self.tableAnalyses.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.tableAnalyses.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        self.tableAnalyses.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        self.tableAnalyses.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        self.tableAnalyses.setObjectName("tableAnalyses")
        self.tableAnalyses.setMinimumSize(QSize(550, 0))
        self.tableAnalyses.setMaximumSize(QSize(16777215, 16777215))
        self.tableAnalyses.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
        self.tableAnalyses.setAlternatingRowColors(True)
        self.tableAnalyses.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tableAnalyses.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableAnalyses.setSortingEnabled(True)
        self.tableAnalyses.setWordWrap(True)
        self.tableAnalyses.setRowCount(0)
        self.tableAnalyses.setColumnCount(4)
        self.tableAnalyses.horizontalHeader().setVisible(False)
        self.tableAnalyses.horizontalHeader().setCascadingSectionResizes(True)
        self.tableAnalyses.horizontalHeader().setDefaultSectionSize(110)
        self.tableAnalyses.horizontalHeader().setStretchLastSection(False)
        self.tableAnalyses.verticalHeader().setVisible(False)

        self.groupSelectLayout.addWidget(self.tableAnalyses)

        self.pageSelectLayout.addWidget(self.groupSelect)

        self.loadingBar = QProgressBar(self.pageSelect)
        self.loadingBar.setObjectName("loadingBar")
        self.loadingBar.setVisible(False)
        self.loadingBar.setMinimum(0)
        self.loadingBar.setMaximum(0)
        self.loadingBar.setValue(-1)
        self.loadingBar.setTextVisible(True)

        self.pageSelectLayout.addWidget(self.loadingBar)

        self.buttonsRowSelect = QHBoxLayout()
        self.buttonsRowSelect.setObjectName("buttonsRowSelect")
        self.buttonsLeftSpacer1 = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.buttonsRowSelect.addItem(self.buttonsLeftSpacer1)

        self.cancelButton = QPushButton(self.pageSelect)
        self.cancelButton.setObjectName("cancelButton")

        self.buttonsRowSelect.addWidget(self.cancelButton)

        self.okButton = QPushButton(self.pageSelect)
        self.okButton.setObjectName("okButton")

        self.buttonsRowSelect.addWidget(self.okButton)

        self.buttonsRightSpacer1 = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.buttonsRowSelect.addItem(self.buttonsRightSpacer1)

        self.pageSelectLayout.addLayout(self.buttonsRowSelect)

        self.stack.addWidget(self.pageSelect)
        self.pageResults = QWidget()
        self.pageResults.setObjectName("pageResults")
        self.pageResultsLayout = QVBoxLayout(self.pageResults)
        self.pageResultsLayout.setObjectName("pageResultsLayout")
        self.stack.addWidget(self.pageResults)

        self.rootLayout.addWidget(self.stack)

        self.retranslateUi(ExistingAnalysesPanel)

        self.stack.setCurrentIndex(0)
        self.okButton.setDefault(True)

        QMetaObject.connectSlotsByName(ExistingAnalysesPanel)

    # setupUi

    def retranslateUi(self, ExistingAnalysesPanel):
        ExistingAnalysesPanel.setWindowTitle(
            QCoreApplication.translate(
                "ExistingAnalysesPanel", "RevEng.AI \u2014 Ann", None
            )
        )
        self.logoArea.setText("")
        self.titleLabel.setText(
            QCoreApplication.translate(
                "ExistingAnalysesPanel", "RevEng.AI \u2014 Existing Analyses", None
            )
        )
        self.subtitleLabel.setText(
            QCoreApplication.translate(
                "ExistingAnalysesPanel",
                "Select an existing analysis to attach to",
                None,
            )
        )
        self.groupSelect.setTitle(
            QCoreApplication.translate(
                "ExistingAnalysesPanel", "Analysis Selection", None
            )
        )
        ___qtablewidgetitem = self.tableAnalyses.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(
            QCoreApplication.translate("ExistingAnalysesPanel", "Select", None)
        )
        ___qtablewidgetitem1 = self.tableAnalyses.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(
            QCoreApplication.translate("ExistingAnalysesPanel", "Virtual Address", None)
        )
        ___qtablewidgetitem2 = self.tableAnalyses.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(
            QCoreApplication.translate("ExistingAnalysesPanel", "Current Name", None)
        )
        ___qtablewidgetitem3 = self.tableAnalyses.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(
            QCoreApplication.translate(
                "ExistingAnalysesPanel", "Current Mangled Name", None
            )
        )
        self.loadingBar.setFormat(
            QCoreApplication.translate(
                "ExistingAnalysesPanel", "Processing\u2026", None
            )
        )
        self.cancelButton.setText(
            QCoreApplication.translate("ExistingAnalysesPanel", "Cancel", None)
        )
        self.okButton.setText(
            QCoreApplication.translate("ExistingAnalysesPanel", "OK", None)
        )

    # retranslateUi

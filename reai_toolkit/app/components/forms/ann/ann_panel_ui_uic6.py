# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'ann_panel.ui'
##
## Created by: Qt User Interface Compiler version 6.10.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (
    QCoreApplication,
    QMetaObject,
    QRect,
    QSize,
)
from PySide6.QtGui import (
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractScrollArea,
    QCheckBox,
    QDoubleSpinBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)


class Ui_MatchingPanel(object):
    def setupUi(self, MatchingPanel):
        if not MatchingPanel.objectName():
            MatchingPanel.setObjectName("MatchingPanel")
        MatchingPanel.resize(800, 800)
        MatchingPanel.setMinimumSize(QSize(800, 800))
        MatchingPanel.setMaximumSize(QSize(800, 800))
        MatchingPanel.setAutoFillBackground(False)
        MatchingPanel.setStyleSheet(
            "\n"
            "    QGroupBox{font-weight:600;margin-top:8px;}\n"
            "    QGroupBox::title{subcontrol-origin: margin; left: 6px; padding:2px 4px;}\n"
            "    QLineEdit{border:1px solid #3c3f44;border-radius:6px;padding:6px;}\n"
            "    QLineEdit:focus{border-color:#5865f2;}\n"
            "    QPushButton{border:1px solid #3c3f44;border-radius:8px;padding:6px 12px;}\n"
            "    QPushButton:hover{border-color:#5865f2;}\n"
            "    #okButton { background:rgb(35,144,236); color:white; border:0; border-radius:8px; padding:6px 12px; }\n"
            "	#okRenameButton { background:rgb(35,144,236); color:white; border:0; border-radius:8px; padding:6px 12px; }\n"
            "	#okRunButton { background:rgb(35,144,236); color:white; border:0; border-radius:8px; padding:6px 12px; }\n"
            "	#okBinariesButton { background:rgb(35,144,236); color:white; border:0; border-radius:8px; padding:6px 12px; }\n"
            "	#okCollectionButton { background:rgb(35,144,236); color:white; border:0; border-radius:8px; padding:6px 12px; }\n"
            "    #cancelButton { background:rgb(153,12,25); color:white; border:0; "
            "border-radius:8px; padding:6px 12px; }\n"
            "    /* Popup styling */\n"
            "    #collectionsPopupFrame { background:#1b1c20; border:1px solid #3c3f44; border-radius:10px; }\n"
            "    #collectionsPopupHeader { font-weight:600; padding:6px 8px; }\n"
            "    #binariesPopupFrame { background:#1b1c20; border:1px solid #3c3f44; border-radius:10px; }\n"
            "    #binariesPopupHeader { font-weight:600; padding:6px 8px; }\n"
            "   "
        )
        self.collectionsPopup = QWidget(MatchingPanel)
        self.collectionsPopup.setObjectName("collectionsPopup")
        self.collectionsPopup.setGeometry(QRect(200, 150, 420, 320))
        self.collectionsPopup.setVisible(False)
        self.collectionsPopupLayout = QVBoxLayout(self.collectionsPopup)
        self.collectionsPopupLayout.setObjectName("collectionsPopupLayout")
        self.collectionsPopupLayout.setContentsMargins(6, 6, 6, 6)
        self.collectionsPopupFrame = QFrame(self.collectionsPopup)
        self.collectionsPopupFrame.setObjectName("collectionsPopupFrame")
        self.collectionsPopupFrame.setFrameShape(QFrame.NoFrame)
        self.collectionsPopupFrameLayout = QVBoxLayout(self.collectionsPopupFrame)
        self.collectionsPopupFrameLayout.setSpacing(6)
        self.collectionsPopupFrameLayout.setObjectName("collectionsPopupFrameLayout")
        self.collectionsPopupHeader = QHBoxLayout()
        self.collectionsPopupHeader.setSpacing(6)
        self.collectionsPopupHeader.setObjectName("collectionsPopupHeader")
        self.collectionsPopupHeader1 = QLabel(self.collectionsPopupFrame)
        self.collectionsPopupHeader1.setObjectName("collectionsPopupHeader1")

        self.collectionsPopupHeader.addWidget(self.collectionsPopupHeader1)

        self.collectionsPopupHeaderSpacer = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.collectionsPopupHeader.addItem(self.collectionsPopupHeaderSpacer)

        self.collectionsPopupFrameLayout.addLayout(self.collectionsPopupHeader)

        self.collectionsPopupView = QTreeWidget(self.collectionsPopupFrame)
        self.collectionsPopupView.setObjectName("collectionsPopupView")
        self.collectionsPopupView.setAlternatingRowColors(True)
        self.collectionsPopupView.setIconSize(QSize(16, 16))
        self.collectionsPopupView.setRootIsDecorated(False)
        self.collectionsPopupView.setUniformRowHeights(True)
        self.collectionsPopupView.setItemsExpandable(False)
        self.collectionsPopupView.setExpandsOnDoubleClick(False)
        self.collectionsPopupView.header().setVisible(False)
        self.collectionsPopupView.header().setCascadingSectionResizes(True)
        self.collectionsPopupView.header().setDefaultSectionSize(120)
        self.collectionsPopupView.header().setStretchLastSection(True)

        self.collectionsPopupFrameLayout.addWidget(self.collectionsPopupView)

        self.collectionsPopupButtons = QHBoxLayout()
        self.collectionsPopupButtons.setObjectName("collectionsPopupButtons")
        self.collectionsPopupButtonsLeftSpacer = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.collectionsPopupButtons.addItem(self.collectionsPopupButtonsLeftSpacer)

        self.okCollectionButton = QPushButton(self.collectionsPopupFrame)
        self.okCollectionButton.setObjectName("okCollectionButton")

        self.collectionsPopupButtons.addWidget(self.okCollectionButton)

        self.collectionsPopupButtonsRightSpacer = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.collectionsPopupButtons.addItem(self.collectionsPopupButtonsRightSpacer)

        self.collectionsPopupFrameLayout.addLayout(self.collectionsPopupButtons)

        self.collectionsPopupLayout.addWidget(self.collectionsPopupFrame)

        self.binariesPopup = QWidget(MatchingPanel)
        self.binariesPopup.setObjectName("binariesPopup")
        self.binariesPopup.setGeometry(QRect(240, 190, 520, 340))
        self.binariesPopup.setVisible(False)
        self.binariesPopupLayout = QVBoxLayout(self.binariesPopup)
        self.binariesPopupLayout.setObjectName("binariesPopupLayout")
        self.binariesPopupLayout.setContentsMargins(6, 6, 6, 6)
        self.binariesPopupFrame = QFrame(self.binariesPopup)
        self.binariesPopupFrame.setObjectName("binariesPopupFrame")
        self.binariesPopupFrame.setFrameShape(QFrame.NoFrame)
        self.binariesPopupFrameLayout = QVBoxLayout(self.binariesPopupFrame)
        self.binariesPopupFrameLayout.setSpacing(6)
        self.binariesPopupFrameLayout.setObjectName("binariesPopupFrameLayout")
        self.binariesPopupHeader = QHBoxLayout()
        self.binariesPopupHeader.setSpacing(6)
        self.binariesPopupHeader.setObjectName("binariesPopupHeader")
        self.binariesPopupHeader1 = QLabel(self.binariesPopupFrame)
        self.binariesPopupHeader1.setObjectName("binariesPopupHeader1")

        self.binariesPopupHeader.addWidget(self.binariesPopupHeader1)

        self.binariesPopupHeaderSpacer = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.binariesPopupHeader.addItem(self.binariesPopupHeaderSpacer)

        self.binariesPopupFrameLayout.addLayout(self.binariesPopupHeader)

        self.binariesPopupView = QTreeWidget(self.binariesPopupFrame)
        self.binariesPopupView.setObjectName("binariesPopupView")
        self.binariesPopupView.setAlternatingRowColors(True)
        self.binariesPopupView.setIconSize(QSize(16, 16))
        self.binariesPopupView.setRootIsDecorated(False)
        self.binariesPopupView.setUniformRowHeights(True)
        self.binariesPopupView.setItemsExpandable(False)
        self.binariesPopupView.setExpandsOnDoubleClick(False)
        self.binariesPopupView.header().setVisible(False)
        self.binariesPopupView.header().setCascadingSectionResizes(True)
        self.binariesPopupView.header().setDefaultSectionSize(140)
        self.binariesPopupView.header().setStretchLastSection(True)

        self.binariesPopupFrameLayout.addWidget(self.binariesPopupView)

        self.binariesPopupButtons = QHBoxLayout()
        self.binariesPopupButtons.setObjectName("binariesPopupButtons")
        self.binariesPopupButtonsLeftSpacer = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.binariesPopupButtons.addItem(self.binariesPopupButtonsLeftSpacer)

        self.okBinariesButton = QPushButton(self.binariesPopupFrame)
        self.okBinariesButton.setObjectName("okBinariesButton")

        self.binariesPopupButtons.addWidget(self.okBinariesButton)

        self.binariesPopupButtonsRightSpacer = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.binariesPopupButtons.addItem(self.binariesPopupButtonsRightSpacer)

        self.binariesPopupFrameLayout.addLayout(self.binariesPopupButtons)

        self.binariesPopupLayout.addWidget(self.binariesPopupFrame)

        self.rootLayout = QVBoxLayout(MatchingPanel)
        self.rootLayout.setSpacing(10)
        self.rootLayout.setObjectName("rootLayout")
        self.rootLayout.setContentsMargins(12, 12, 12, 12)
        self.header = QFrame(MatchingPanel)
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

        self.stack = QStackedWidget(MatchingPanel)
        self.stack.setObjectName("stack")
        self.pageSelect = QWidget()
        self.pageSelect.setObjectName("pageSelect")
        self.pageSelectLayout = QVBoxLayout(self.pageSelect)
        self.pageSelectLayout.setObjectName("pageSelectLayout")
        self.groupSelect = QGroupBox(self.pageSelect)
        self.groupSelect.setObjectName("groupSelect")
        self.groupSelectLayout = QVBoxLayout(self.groupSelect)
        self.groupSelectLayout.setObjectName("groupSelectLayout")
        self.searchRow = QHBoxLayout()
        self.searchRow.setObjectName("searchRow")
        self.searchFunctions = QLineEdit(self.groupSelect)
        self.searchFunctions.setObjectName("searchFunctions")

        self.searchRow.addWidget(self.searchFunctions)

        self.btnSelectAll = QPushButton(self.groupSelect)
        self.btnSelectAll.setObjectName("btnSelectAll")

        self.searchRow.addWidget(self.btnSelectAll)

        self.btnClearSelection = QPushButton(self.groupSelect)
        self.btnClearSelection.setObjectName("btnClearSelection")

        self.searchRow.addWidget(self.btnClearSelection)

        self.groupSelectLayout.addLayout(self.searchRow)

        self.groupFilters = QGroupBox(self.groupSelect)
        self.groupFilters.setObjectName("groupFilters")
        self.advancedGrid = QGridLayout(self.groupFilters)
        self.advancedGrid.setObjectName("advancedGrid")
        self.advancedGrid.setHorizontalSpacing(12)
        self.advancedGrid.setVerticalSpacing(8)
        self.lblCollections = QLabel(self.groupFilters)
        self.lblCollections.setObjectName("lblCollections")

        self.advancedGrid.addWidget(self.lblCollections, 0, 0, 1, 1)

        self.editCollections = QLineEdit(self.groupFilters)
        self.editCollections.setObjectName("editCollections")

        self.advancedGrid.addWidget(self.editCollections, 0, 1, 1, 1)

        self.lblBinaries = QLabel(self.groupFilters)
        self.lblBinaries.setObjectName("lblBinaries")

        self.advancedGrid.addWidget(self.lblBinaries, 0, 2, 1, 1)

        self.editBinaries = QLineEdit(self.groupFilters)
        self.editBinaries.setObjectName("editBinaries")

        self.advancedGrid.addWidget(self.editBinaries, 0, 3, 1, 1)

        self.lblConfidence = QLabel(self.groupFilters)
        self.lblConfidence.setObjectName("lblConfidence")

        self.advancedGrid.addWidget(self.lblConfidence, 1, 0, 1, 1)

        self.spinConfidence = QDoubleSpinBox(self.groupFilters)
        self.spinConfidence.setObjectName("spinConfidence")
        self.spinConfidence.setDecimals(0)
        self.spinConfidence.setMinimum(0.000000000000000)
        self.spinConfidence.setMaximum(100.000000000000000)
        self.spinConfidence.setValue(85.000000000000000)

        self.advancedGrid.addWidget(self.spinConfidence, 1, 1, 1, 1)

        self.lblDebugSymbols = QLabel(self.groupFilters)
        self.lblDebugSymbols.setObjectName("lblDebugSymbols")

        self.advancedGrid.addWidget(self.lblDebugSymbols, 1, 2, 1, 1)

        self.chkDebugSymbols = QCheckBox(self.groupFilters)
        self.chkDebugSymbols.setObjectName("chkDebugSymbols")

        self.advancedGrid.addWidget(self.chkDebugSymbols, 1, 3, 1, 1)

        self.lblUserDebugSymbols = QLabel(self.groupFilters)
        self.lblUserDebugSymbols.setObjectName("lblUserDebugSymbols")

        self.advancedGrid.addWidget(self.lblUserDebugSymbols, 2, 2, 1, 1)

        self.chkUserDebugSymbols = QCheckBox(self.groupFilters)
        self.chkUserDebugSymbols.setObjectName("chkUserDebugSymbols")

        self.advancedGrid.addWidget(self.chkUserDebugSymbols, 2, 3, 1, 1)

        self.filtersRow = QHBoxLayout()
        self.filtersRow.setObjectName("filtersRow")
        self.btnResetFilters = QPushButton(self.groupFilters)
        self.btnResetFilters.setObjectName("btnResetFilters")

        self.filtersRow.addWidget(self.btnResetFilters)

        self.filtersSpacer = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.filtersRow.addItem(self.filtersSpacer)

        self.advancedGrid.addLayout(self.filtersRow, 2, 0, 1, 2)

        self.groupSelectLayout.addWidget(self.groupFilters)

        self.tableFunctions = QTableWidget(self.groupSelect)
        if self.tableFunctions.columnCount() < 4:
            self.tableFunctions.setColumnCount(4)
        __qtablewidgetitem = QTableWidgetItem()
        self.tableFunctions.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.tableFunctions.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        self.tableFunctions.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        self.tableFunctions.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        self.tableFunctions.setObjectName("tableFunctions")
        self.tableFunctions.setMinimumSize(QSize(550, 0))
        self.tableFunctions.setMaximumSize(QSize(16777215, 16777215))
        self.tableFunctions.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
        self.tableFunctions.setAlternatingRowColors(True)
        self.tableFunctions.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tableFunctions.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableFunctions.setSortingEnabled(True)
        self.tableFunctions.setWordWrap(True)
        self.tableFunctions.setRowCount(0)
        self.tableFunctions.setColumnCount(4)
        self.tableFunctions.horizontalHeader().setVisible(False)
        self.tableFunctions.horizontalHeader().setCascadingSectionResizes(True)
        self.tableFunctions.horizontalHeader().setDefaultSectionSize(110)
        self.tableFunctions.horizontalHeader().setStretchLastSection(False)
        self.tableFunctions.verticalHeader().setVisible(False)

        self.groupSelectLayout.addWidget(self.tableFunctions)

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

        self.okRunButton = QPushButton(self.pageSelect)
        self.okRunButton.setObjectName("okRunButton")

        self.buttonsRowSelect.addWidget(self.okRunButton)

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
        self.groupResults = QGroupBox(self.pageResults)
        self.groupResults.setObjectName("groupResults")
        self.groupResultsLayout = QVBoxLayout(self.groupResults)
        self.groupResultsLayout.setObjectName("groupResultsLayout")
        self.resultSearchLayout = QHBoxLayout()
        self.resultSearchLayout.setObjectName("resultSearchLayout")
        self.resultFunctionSearch = QLineEdit(self.groupResults)
        self.resultFunctionSearch.setObjectName("resultFunctionSearch")

        self.resultSearchLayout.addWidget(self.resultFunctionSearch)

        self.btnResultSelectAll = QPushButton(self.groupResults)
        self.btnResultSelectAll.setObjectName("btnResultSelectAll")

        self.resultSearchLayout.addWidget(self.btnResultSelectAll)

        self.btnResultClearAll = QPushButton(self.groupResults)
        self.btnResultClearAll.setObjectName("btnResultClearAll")

        self.resultSearchLayout.addWidget(self.btnResultClearAll)

        self.groupResultsLayout.addLayout(self.resultSearchLayout)

        self.tableResults = QTableWidget(self.groupResults)
        if self.tableResults.columnCount() < 6:
            self.tableResults.setColumnCount(6)
        __qtablewidgetitem4 = QTableWidgetItem()
        self.tableResults.setHorizontalHeaderItem(0, __qtablewidgetitem4)
        __qtablewidgetitem5 = QTableWidgetItem()
        self.tableResults.setHorizontalHeaderItem(1, __qtablewidgetitem5)
        __qtablewidgetitem6 = QTableWidgetItem()
        self.tableResults.setHorizontalHeaderItem(2, __qtablewidgetitem6)
        __qtablewidgetitem7 = QTableWidgetItem()
        self.tableResults.setHorizontalHeaderItem(3, __qtablewidgetitem7)
        __qtablewidgetitem8 = QTableWidgetItem()
        self.tableResults.setHorizontalHeaderItem(4, __qtablewidgetitem8)
        __qtablewidgetitem9 = QTableWidgetItem()
        self.tableResults.setHorizontalHeaderItem(5, __qtablewidgetitem9)
        self.tableResults.setObjectName("tableResults")
        self.tableResults.setMinimumSize(QSize(550, 0))
        self.tableResults.setMaximumSize(QSize(16777215, 16777215))
        self.tableResults.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
        self.tableResults.setAlternatingRowColors(True)
        self.tableResults.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tableResults.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableResults.setSortingEnabled(True)
        self.tableResults.setWordWrap(True)
        self.tableResults.setRowCount(0)
        self.tableResults.setColumnCount(6)
        self.tableResults.horizontalHeader().setVisible(False)
        self.tableResults.horizontalHeader().setCascadingSectionResizes(True)
        self.tableResults.horizontalHeader().setDefaultSectionSize(110)
        self.tableResults.horizontalHeader().setStretchLastSection(True)
        self.tableResults.verticalHeader().setVisible(False)

        self.groupResultsLayout.addWidget(self.tableResults)

        self.pageResultsLayout.addWidget(self.groupResults)

        self.buttonsRowResults = QHBoxLayout()
        self.buttonsRowResults.setObjectName("buttonsRowResults")
        self.buttonsLeftSpacer2 = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.buttonsRowResults.addItem(self.buttonsLeftSpacer2)

        self.cancelButton1 = QPushButton(self.pageResults)
        self.cancelButton1.setObjectName("cancelButton1")

        self.buttonsRowResults.addWidget(self.cancelButton1)

        self.okRenameButton = QPushButton(self.pageResults)
        self.okRenameButton.setObjectName("okRenameButton")

        self.buttonsRowResults.addWidget(self.okRenameButton)

        self.buttonsRightSpacer2 = QSpacerItem(
            40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.buttonsRowResults.addItem(self.buttonsRightSpacer2)

        self.pageResultsLayout.addLayout(self.buttonsRowResults)

        self.stack.addWidget(self.pageResults)

        self.rootLayout.addWidget(self.stack)

        self.retranslateUi(MatchingPanel)

        self.okCollectionButton.setDefault(True)
        self.okBinariesButton.setDefault(True)
        self.stack.setCurrentIndex(0)
        self.okRunButton.setDefault(True)
        self.okRenameButton.setDefault(True)

        QMetaObject.connectSlotsByName(MatchingPanel)

    # setupUi

    def retranslateUi(self, MatchingPanel):
        MatchingPanel.setWindowTitle(
            QCoreApplication.translate(
                "MatchingPanel", "RevEng.AI \u2014 Function Matching", None
            )
        )
        # if QT_CONFIG(tooltip)
        self.collectionsPopup.setToolTip(
            QCoreApplication.translate("MatchingPanel", "Collections", None)
        )
        # endif // QT_CONFIG(tooltip)
        self.collectionsPopupHeader1.setText(
            QCoreApplication.translate("MatchingPanel", "Collections", None)
        )
        ___qtreewidgetitem = self.collectionsPopupView.headerItem()
        ___qtreewidgetitem.setText(
            4, QCoreApplication.translate("MatchingPanel", "Created", None)
        )
        ___qtreewidgetitem.setText(
            3, QCoreApplication.translate("MatchingPanel", "Model", None)
        )
        ___qtreewidgetitem.setText(
            2, QCoreApplication.translate("MatchingPanel", "Owner", None)
        )
        ___qtreewidgetitem.setText(
            1, QCoreApplication.translate("MatchingPanel", "Scope", None)
        )
        ___qtreewidgetitem.setText(
            0, QCoreApplication.translate("MatchingPanel", "Collection", None)
        )
        self.okCollectionButton.setText(
            QCoreApplication.translate("MatchingPanel", "Select", None)
        )
        # if QT_CONFIG(tooltip)
        self.binariesPopup.setToolTip(
            QCoreApplication.translate("MatchingPanel", "Binaries", None)
        )
        # endif // QT_CONFIG(tooltip)
        self.binariesPopupHeader1.setText(
            QCoreApplication.translate("MatchingPanel", "Binaries", None)
        )
        ___qtreewidgetitem1 = self.binariesPopupView.headerItem()
        ___qtreewidgetitem1.setText(
            5, QCoreApplication.translate("MatchingPanel", "Created", None)
        )
        ___qtreewidgetitem1.setText(
            4, QCoreApplication.translate("MatchingPanel", "Model", None)
        )
        ___qtreewidgetitem1.setText(
            3, QCoreApplication.translate("MatchingPanel", "Owner", None)
        )
        ___qtreewidgetitem1.setText(
            2, QCoreApplication.translate("MatchingPanel", "SHA-256", None)
        )
        ___qtreewidgetitem1.setText(
            1, QCoreApplication.translate("MatchingPanel", "Binary Name", None)
        )
        ___qtreewidgetitem1.setText(
            0, QCoreApplication.translate("MatchingPanel", "Select", None)
        )
        self.okBinariesButton.setText(
            QCoreApplication.translate("MatchingPanel", "Select", None)
        )
        self.logoArea.setText("")
        self.titleLabel.setText(
            QCoreApplication.translate(
                "MatchingPanel", "RevEng.AI \u2014 Function matching", None
            )
        )
        self.subtitleLabel.setText(
            QCoreApplication.translate(
                "MatchingPanel",
                "Select functions and match with RevEng; review results per function.",
                None,
            )
        )
        self.groupSelect.setTitle(
            QCoreApplication.translate("MatchingPanel", "Function Selection", None)
        )
        self.searchFunctions.setPlaceholderText(
            QCoreApplication.translate("MatchingPanel", "Search functions\u2026", None)
        )
        self.btnSelectAll.setText(
            QCoreApplication.translate("MatchingPanel", "Select All", None)
        )
        self.btnClearSelection.setText(
            QCoreApplication.translate("MatchingPanel", "Clear", None)
        )
        self.groupFilters.setTitle(
            QCoreApplication.translate("MatchingPanel", "Filters", None)
        )
        self.lblCollections.setText(
            QCoreApplication.translate("MatchingPanel", "Collections", None)
        )
        self.editCollections.setPlaceholderText(
            QCoreApplication.translate("MatchingPanel", "Search Collections", None)
        )
        self.lblBinaries.setText(
            QCoreApplication.translate("MatchingPanel", "Binaries", None)
        )
        self.editBinaries.setPlaceholderText(
            QCoreApplication.translate("MatchingPanel", "Search Analyses", None)
        )
        self.lblConfidence.setText(
            QCoreApplication.translate("MatchingPanel", "Confidence", None)
        )
        self.spinConfidence.setSuffix(
            QCoreApplication.translate("MatchingPanel", " %", None)
        )
        self.lblDebugSymbols.setText(
            QCoreApplication.translate("MatchingPanel", "Debug Symbols", None)
        )
        self.chkDebugSymbols.setText(
            QCoreApplication.translate("MatchingPanel", "Enable", None)
        )
        self.lblUserDebugSymbols.setText(
            QCoreApplication.translate("MatchingPanel", "User Debug Symbols", None)
        )
        self.chkUserDebugSymbols.setText(
            QCoreApplication.translate("MatchingPanel", "Enable", None)
        )
        self.btnResetFilters.setText(
            QCoreApplication.translate("MatchingPanel", "Reset", None)
        )
        ___qtablewidgetitem = self.tableFunctions.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(
            QCoreApplication.translate("MatchingPanel", "Select", None)
        )
        ___qtablewidgetitem1 = self.tableFunctions.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(
            QCoreApplication.translate("MatchingPanel", "Virtual Address", None)
        )
        ___qtablewidgetitem2 = self.tableFunctions.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(
            QCoreApplication.translate("MatchingPanel", "Current Name", None)
        )
        ___qtablewidgetitem3 = self.tableFunctions.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(
            QCoreApplication.translate("MatchingPanel", "Current Mangled Name", None)
        )
        self.loadingBar.setFormat(
            QCoreApplication.translate("MatchingPanel", "Processing\u2026", None)
        )
        self.cancelButton.setText(
            QCoreApplication.translate("MatchingPanel", "Cancel", None)
        )
        self.okRunButton.setText(
            QCoreApplication.translate("MatchingPanel", "Function Matching", None)
        )
        self.groupResults.setTitle(
            QCoreApplication.translate("MatchingPanel", "Matching Results", None)
        )
        self.resultFunctionSearch.setPlaceholderText(
            QCoreApplication.translate("MatchingPanel", "Search functions\u2026", None)
        )
        self.btnResultSelectAll.setText(
            QCoreApplication.translate("MatchingPanel", "Select All", None)
        )
        self.btnResultClearAll.setText(
            QCoreApplication.translate("MatchingPanel", "Clear", None)
        )
        ___qtablewidgetitem4 = self.tableResults.horizontalHeaderItem(0)
        ___qtablewidgetitem4.setText(
            QCoreApplication.translate("MatchingPanel", "Select", None)
        )
        ___qtablewidgetitem5 = self.tableResults.horizontalHeaderItem(1)
        ___qtablewidgetitem5.setText(
            QCoreApplication.translate("MatchingPanel", "Origin Function Name", None)
        )
        ___qtablewidgetitem6 = self.tableResults.horizontalHeaderItem(2)
        ___qtablewidgetitem6.setText(
            QCoreApplication.translate("MatchingPanel", "Score", None)
        )
        ___qtablewidgetitem7 = self.tableResults.horizontalHeaderItem(3)
        ___qtablewidgetitem7.setText(
            QCoreApplication.translate("MatchingPanel", "Matched Function Name", None)
        )
        ___qtablewidgetitem8 = self.tableResults.horizontalHeaderItem(4)
        ___qtablewidgetitem8.setText(
            QCoreApplication.translate("MatchingPanel", "Matched Binary Name", None)
        )
        ___qtablewidgetitem9 = self.tableResults.horizontalHeaderItem(5)
        ___qtablewidgetitem9.setText(
            QCoreApplication.translate("MatchingPanel", "Link", None)
        )
        self.cancelButton1.setText(
            QCoreApplication.translate("MatchingPanel", "Back", None)
        )
        self.okRenameButton.setText(
            QCoreApplication.translate("MatchingPanel", "Rename", None)
        )

    # retranslateUi

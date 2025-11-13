# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'about_panel_qt5.ui'
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
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QTextBrowser,
    QVBoxLayout,
)


class Ui_AboutPanel(object):
    def setupUi(self, AboutPanel):
        if not AboutPanel.objectName():
            AboutPanel.setObjectName("AboutPanel")
        AboutPanel.resize(600, 800)
        AboutPanel.setMinimumSize(QSize(600, 800))
        AboutPanel.setMaximumSize(QSize(600, 800))
        AboutPanel.setStyleSheet(
            "\n"
            "    QGroupBox{font-weight:600;margin-top:8px;}\n"
            "    QGroupBox::title{subcontrol-origin: margin; left: 6px; padding:2px 4px;}\n"
            "    QLineEdit{border:1px solid #3c3f44;border-radius:6px;padding:6px;}\n"
            "    QLineEdit:focus{border-color:#5865f2;}\n"
            "    QPushButton{border:1px solid #3c3f44;border-radius:8px;padding:6px 12px;}\n"
            "    QPushButton:hover{border-color:#5865f2;}\n"
            "    #okButton{background:rgb(35,144,236);color:white;border:0;border-radius:8px;padding:6px 12px;}\n"
            "    #cancelButton{background:rgb(153,12,25);color:white;border:0;border-radius:8px;padding:6px 12px;}\n"
            "	#btnDiscord{background:rgb(83, 54, 228); color:white;border:0;border-radius:8px;padding:6px 12px;}\n"
            "	#btnEmail{background:rgb(218, 73, 59); color:white;border:0;border-radius:8px;padding:6px 12px;}\n"
            "   "
        )
        self.rootLayout = QVBoxLayout(AboutPanel)
        self.rootLayout.setSpacing(10)
        self.rootLayout.setObjectName("rootLayout")
        self.rootLayout.setContentsMargins(12, 12, 12, 12)
        self.header = QFrame(AboutPanel)
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

        self.groupEndpoints = QGroupBox(AboutPanel)
        self.groupEndpoints.setObjectName("groupEndpoints")
        self.groupEndpoints.setMinimumSize(QSize(0, 150))
        self.errorLayout = QVBoxLayout(self.groupEndpoints)
        self.errorLayout.setSpacing(6)
        self.errorLayout.setObjectName("errorLayout")
        self.textBrowser = QTextBrowser(self.groupEndpoints)
        self.textBrowser.setObjectName("textBrowser")
        self.textBrowser.setOpenExternalLinks(True)

        self.errorLayout.addWidget(self.textBrowser)

        self.supportGroupBox = QGroupBox(self.groupEndpoints)
        self.supportGroupBox.setObjectName("supportGroupBox")
        self.supportGroupBox.setMinimumSize(QSize(0, 60))
        self.supportGroupBox.setMaximumSize(QSize(16777215, 60))
        self.supportLayout = QHBoxLayout(self.supportGroupBox)
        self.supportLayout.setSpacing(8)
        self.supportLayout.setObjectName("supportLayout")
        self.supportSpacerLeft = QSpacerItem(
            20, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.supportLayout.addItem(self.supportSpacerLeft)

        self.btnDiscord = QPushButton(self.supportGroupBox)
        self.btnDiscord.setObjectName("btnDiscord")

        self.supportLayout.addWidget(self.btnDiscord)

        self.btnEmail = QPushButton(self.supportGroupBox)
        self.btnEmail.setObjectName("btnEmail")

        self.supportLayout.addWidget(self.btnEmail)

        self.supportSpacerRight = QSpacerItem(
            20, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.supportLayout.addItem(self.supportSpacerRight)

        self.errorLayout.addWidget(self.supportGroupBox)

        self.rootLayout.addWidget(self.groupEndpoints)

        self.buttonsRow = QHBoxLayout()
        self.buttonsRow.setObjectName("buttonsRow")
        self.horizontalSpacer = QSpacerItem(
            20, 40, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.buttonsRow.addItem(self.horizontalSpacer)

        self.okButton = QPushButton(AboutPanel)
        self.okButton.setObjectName("okButton")
        self.okButton.setMinimumSize(QSize(80, 25))
        self.okButton.setMaximumSize(QSize(80, 25))

        self.buttonsRow.addWidget(self.okButton)

        self.buttonsSpacer = QSpacerItem(
            0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        self.buttonsRow.addItem(self.buttonsSpacer)

        self.rootLayout.addLayout(self.buttonsRow)

        self.retranslateUi(AboutPanel)

        QMetaObject.connectSlotsByName(AboutPanel)

    # setupUi

    def retranslateUi(self, AboutPanel):
        AboutPanel.setWindowTitle(
            QCoreApplication.translate("AboutPanel", "RevEng.AI \u2014 About", None)
        )
        self.logoArea.setText("")
        self.titleLabel.setText(QCoreApplication.translate("AboutPanel", "Help", None))
        self.subtitleLabel.setText(
            QCoreApplication.translate(
                "AboutPanel", "Documentation for the options in the menu bar", None
            )
        )
        self.groupEndpoints.setTitle(
            QCoreApplication.translate("AboutPanel", "RevEng.AI", None)
        )
        self.textBrowser.setHtml(
            QCoreApplication.translate(
                "AboutPanel",
                '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n'
                '<html><head><meta name="qrichtext" content="1" /><style type="text/css">\n'
                "p, li { white-space: pre-wrap; }\n"
                "</style></head><body style=\" font-family:'.AppleSystemUIFont'; font-size:13pt; font-weight:400; font-style:normal;\">\n"
                '<h2 style=" margin-top:16px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><a name="welcome-to-reveng-ai"></a><span style=" font-size:x-large; font-weight:600;">W</span><span style=" font-size:x-large; font-weight:600;">elcome to RevEng.AI</span></h2>\n'
                '<p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">This panel provides an overview of features available from the RevEng.AI menu.</p>\n'
                '<h2 style=" margin-top:16px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><a name="quick-start"></a><span '
                'style=" font-size:x-large; font-weight:600;">Q</span><span style=" font-size:x-large; font-weight:600;">uick Start</span></h2>\n'
                '<ol style="margin-top: 0px; margin-bottom: 0px; margin-left: 0px; margin-right: 0px; -qt-list-indent: 1;"><li style="" style=" margin-top:12px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">Authenticate via: RevEng.AI \u2192 Configure</li>\n'
                '<li style="" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">Analyse the current binary with RevEng.AI via: RevEng.AI \u2192 Analysis \u2192 Create New</li>\n'
                '<li style="" style=" margin-top:0px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">Use other RevEng.AI Features to improve your analysis!</li></ol>\n'
                '<h2 style=" margin-top:16px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><a name="full-feature-list"></a>'
                '<span style=" font-size:x-large; font-weight:600;">F</span><span style=" font-size:x-large; font-weight:600;">ull Feature List</span></h2>\n'
                '<h3 style=" margin-top:14px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><a name="analysis"></a><span style=" font-size:large; font-weight:600;">A</span><span style=" font-size:large; font-weight:600;">nalysis</span></h3>\n'
                '<p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">To use the RevEng.AI platform we need to run an analysis on the binary you are currently working with in our portal. Use this section to create and manage this analysis.<br />This section is only available after the plugin has been configured.</p>\n'
                '<ul style="margin-top: 0px; margin-bottom: 0px; margin-left: 0px; margin-right: 0px; -qt-list-indent: 1;"><li style="" style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent'
                ':0; text-indent:0px;"><span style=" font-weight:600;">Create new</span><br />Creates a new analysis in the RevEng.AI portal and attaches to it.</li>\n'
                '<li style="" style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600;">Attach to existing</span><br />List matching portal analyses and allow selecting one to attach to.</li>\n'
                '<li style="" style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600;">Detach</span><br />Detach from portal analysis.</li>\n'
                '<li style="" style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600;">Check status</span><br />Checks the status of a running analysis.</li></ul>\n'
                '<h3 style=" margin-top:14px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:'
                '0px;"><a name="auto-unstrip"></a><span style=" font-size:large; font-weight:600;">A</span><span style=" font-size:large; font-weight:600;">uto Unstrip</span></h3>\n'
                '<p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">This option will run an automatic unstrip process on the current binary using the RevEng.AI API.<br />The process uses a high confidence threshold to rename functions and variables.<br />This option is only available when an analysis is attached and has completed processing.</p>\n'
                '<h3 style=" margin-top:14px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><a name="function-matching"></a><span style=" font-size:large; font-weight:600;">F</span><span style=" font-size:large; font-weight:600;">unction Matching</span></h3>\n'
                '<p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">Run a function match'
                " against the RevEng.AI API to identify functions that were not renamed during the automatic unstrip process.<br />This option is configurable to run against specific target binaries by using specific filters.<br />This option is only available when an analysis is attached and has completed processing.</p>\n"
                '<h3 style=" margin-top:14px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><a name="configure"></a><span style=" font-size:large; font-weight:600;">C</span><span style=" font-size:large; font-weight:600;">onfigure</span></h3>\n'
                '<p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">Configure the API endpoint and API key.</p>\n'
                '<h3 style=" margin-top:14px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><a name="help"></a><span style=" font-size:large; font-weight:600;">H</span><span style=" font-size:large; font-weight:600;">elp'
                "</span></h3>\n"
                '<p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">Display this page.</p>\n'
                '<h3 style=" margin-top:14px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><a name="about"></a><span style=" font-size:large; font-weight:600;">A</span><span style=" font-size:large; font-weight:600;">bout</span></h3>\n'
                '<p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">Display plugin version.</p>\n'
                "<hr />\n"
                '<h3 style=" margin-top:14px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><a name="secondary-click-on-a-function"></a><span style=" font-size:large; font-weight:600;">S</span><span style=" font-size:large; font-weight:600;">econdary click on a function</span></h3>\n'
                '<p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-bl'
                'ock-indent:0; text-indent:0px;">Documentation for the options available on secondary click on a specific function.</p>\n'
                '<ul style="margin-top: 0px; margin-bottom: 0px; margin-left: 0px; margin-right: 0px; -qt-list-indent: 1;"><li style="" style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600;">AI Decompilation</span><br />Decompile function using the RevEng.AI proprietary decompiler.</li>\n'
                '<li style="" style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600;">Match function</span><br />Run a match against the RevEng.AI API for this function.<br />Only available for non-debug functions. </li></ul></body></html>',
                None,
            )
        )
        self.supportGroupBox.setTitle(
            QCoreApplication.translate("AboutPanel", "Support/Contact", None)
        )
        # if QT_CONFIG(tooltip)
        self.btnDiscord.setToolTip(
            QCoreApplication.translate("AboutPanel", "Join our Discord", None)
        )
        # endif // QT_CONFIG(tooltip)
        self.btnDiscord.setText(
            QCoreApplication.translate("AboutPanel", "Discord", None)
        )
        # if QT_CONFIG(tooltip)
        self.btnEmail.setToolTip(
            QCoreApplication.translate("AboutPanel", "Contact us via email", None)
        )
        # endif // QT_CONFIG(tooltip)
        self.btnEmail.setText(QCoreApplication.translate("AboutPanel", "Email", None))
        self.okButton.setText(QCoreApplication.translate("AboutPanel", "Dismiss", None))

    # retranslateUi

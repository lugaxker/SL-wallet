#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Low-level transaction maker. '''

from transaction import *

from PyQt5.QtCore import Qt
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

class inputTab(QWidget):
    
    def __init__(self):
        super().__init__()
        
        self.initUI()
        
    def initUI(self):

        self.mainVLayout = QVBoxLayout()
        
        # Type
        self.typeHLayout = QHBoxLayout()
        self.typeLabel = QLabel("Type")
        self.typeLabel.setAlignment(Qt.AlignCenter)
        self.typeHLayout.addWidget(self.typeLabel)
        self.typeComboBox = QComboBox()
        self.typeComboBox.addItems(["P2PKH"])
        self.typeHLayout.addWidget(self.typeComboBox)
        self.mainVLayout.addLayout(self.typeHLayout)
        
        # Previous output
        self.prevoutHLayout = QHBoxLayout()
        self.prevoutLabel = QLabel("Previous Output")
        self.prevoutLabel.setAlignment(Qt.AlignCenter)
        self.prevoutHLayout.addWidget(self.prevoutLabel)
        self.prevoutTxidLabel = QLabel("TXID")
        self.prevoutTxidLabel.setAlignment(Qt.AlignCenter)
        self.prevoutHLayout.addWidget(self.prevoutTxidLabel)
        self.prevoutTxidEdit = QLineEdit()
        self.prevoutHLayout.addWidget(self.prevoutTxidEdit)
        self.prevoutIndexLabel = QLabel("Index")
        self.prevoutIndexLabel.setAlignment(Qt.AlignCenter)
        self.prevoutHLayout.addWidget(self.prevoutIndexLabel)
        self.prevoutIndexEdit = QLineEdit()
        self.prevoutHLayout.addWidget(self.prevoutIndexEdit)
        self.prevoutValueLabel = QLabel("Value")
        self.prevoutValueLabel.setAlignment(Qt.AlignCenter)
        self.prevoutHLayout.addWidget(self.prevoutValueLabel)
        self.prevoutValueEdit = QLineEdit()
        self.prevoutHLayout.addWidget(self.prevoutValueEdit)
        self.mainVLayout.addLayout(self.prevoutHLayout)
        
        # Private and Public Key 
        self.keysHLayout = QHBoxLayout()
        self.privateKeyCheckBox = QCheckBox("Private Key (WIF)")
        self.privateKeyCheckBox.clicked.connect(self.enable_private_key_edit)
        self.keysHLayout.addWidget(self.privateKeyCheckBox)
        self.privateKeyEdit = QLineEdit()
        #self.privateKeyEdit.setDisabled(True)
        self.privateKeyEdit.setReadOnly(True)
        self.keysHLayout.addWidget(self.privateKeyEdit)
        self.pubKeyLabel = QLabel("Public Key")
        self.pubKeyLabel.setAlignment(Qt.AlignCenter)
        self.keysHLayout.addWidget(self.pubKeyLabel)
        self.publicKeyEdit = QLineEdit()
        self.keysHLayout.addWidget(self.publicKeyEdit)
        self.mainVLayout.addLayout(self.keysHLayout)
        
        # Signature
        self.signatureHLayout = QHBoxLayout()
        self.signatureLabel = QLabel("Signature")
        self.signatureLabel.setAlignment(Qt.AlignCenter)
        self.signatureHLayout.addWidget(self.signatureLabel)
        self.signatureEdit = QLineEdit()
        self.signatureHLayout.addWidget(self.signatureEdit)
        self.mainVLayout.addLayout(self.signatureHLayout)
        
        # Unlocking script
        self.unlockingScriptHLayout = QHBoxLayout()
        self.unlockingScriptLabel = QLabel("Unlocking Script")
        self.unlockingScriptLabel.setAlignment(Qt.AlignCenter)
        self.unlockingScriptHLayout.addWidget(self.unlockingScriptLabel)
        self.unlockingScriptEdit = QLineEdit()
        self.unlockingScriptEdit.setReadOnly(True)
        self.unlockingScriptHLayout.addWidget(self.unlockingScriptEdit)
        self.unlockingScriptCheckBox = QCheckBox("Edit")
        self.unlockingScriptCheckBox.clicked.connect(self.enable_unlocking_script_edit)
        self.unlockingScriptHLayout.addWidget(self.unlockingScriptCheckBox)
        self.mainVLayout.addLayout(self.unlockingScriptHLayout)
        
        # Sequence
        self.sequenceHLayout = QHBoxLayout()
        self.sequenceLabel = QLabel("Sequence Number")
        self.sequenceLabel.setAlignment(Qt.AlignCenter)
        self.sequenceHLayout.addWidget(self.sequenceLabel)
        self.sequenceEdit = QLineEdit()
        self.sequenceHLayout.addWidget(self.sequenceEdit)
        self.relativeTimeLockCheckbox = QCheckBox("Enable Relative Time Lock")
        self.sequenceHLayout.addWidget(self.relativeTimeLockCheckbox)
        self.relativeTimeLockEdit = QLineEdit()
        self.sequenceHLayout.addWidget(self.relativeTimeLockEdit)
        self.relativeTimeLockComboBox = QComboBox()
        self.relativeTimeLockComboBox.addItems(["blocks", "seconds"])
        self.sequenceHLayout.addWidget(self.relativeTimeLockComboBox)
        self.mainVLayout.addLayout(self.sequenceHLayout)
        
        self.setLayout(self.mainVLayout)
        
    
    # Set input widget with transaction input (dict)
    def set_input(self, txin):
        
        self.prevoutTxidEdit.setText( txin['txid'] )
        self.prevoutIndexEdit.setText( str(txin['index']) )
        if 'value' in txin:
            self.prevoutValueEdit.setText( str(txin['value']) )
            
        self.sequenceEdit.setText( "{:0x}".format(txin['sequence']) )
            
        # TODO: sequence, unlocking_script, etc.
    
    # Get transaction input from widget
    def get_input(self):
        pass
        #return txin
        
    def enable_private_key_edit(self):
        if self.privateKeyCheckBox.isChecked():
            self.privateKeyEdit.setReadOnly(False)
            self.publicKeyEdit.setReadOnly(True)
        else:
            self.privateKeyEdit.setReadOnly(True)
            self.publicKeyEdit.setReadOnly(False)
            
    def enable_unlocking_script_edit(self):
        if self.unlockingScriptCheckBox.isChecked():
            self.unlockingScriptEdit.setReadOnly(False)
        else:
            self.unlockingScriptEdit.setReadOnly(True)
        

# TODO: init with output dict (as in Transaction class)        
class outputTab(QWidget):
    
    def __init__(self):
        super().__init__()
        
        self.initUI()
        
    def initUI(self):

        self.mainVLayout = QVBoxLayout()
        
        # Type 
        self.typeHLayout = QHBoxLayout()
        self.typeLabel = QLabel("Type")
        self.typeLabel.setAlignment(Qt.AlignCenter)
        self.typeHLayout.addWidget(self.typeLabel)
        self.typeComboBox = QComboBox()
        self.typeComboBox.addItems(["P2PKH", "nulldata"])
        self.typeHLayout.addWidget(self.typeComboBox)
        self.mainVLayout.addLayout(self.typeHLayout)
        
        # Amount
        self.amountHLayout = QHBoxLayout()
        self.amountLabel = QLabel("Amount")
        self.amountLabel.setAlignment(Qt.AlignCenter)
        self.amountHLayout.addWidget(self.amountLabel)
        self.amountEdit = QLineEdit()
        self.amountHLayout.addWidget(self.amountEdit)
        self.mainVLayout.addLayout(self.amountHLayout)
        
        # Address
        self.addressHLayout = QHBoxLayout()
        self.addressLabel = QLabel("Address")
        self.addressHLayout.addWidget(self.addressLabel)
        self.addressEdit = QLineEdit()
        self.addressHLayout.addWidget(self.addressEdit)
        self.mainVLayout.addLayout(self.addressHLayout)
        
        # Locking Script
        self.lockingScriptHLayout = QHBoxLayout()
        self.lockingScriptLabel = QLabel("Locking Script")
        self.lockingScriptLabel.setAlignment(Qt.AlignCenter)
        self.lockingScriptHLayout.addWidget(self.lockingScriptLabel)
        self.lockingScriptEdit = QLineEdit()
        self.lockingScriptHLayout.addWidget(self.lockingScriptEdit)
        self.editLockingScriptCheckbox = QCheckBox("Edit")
        self.lockingScriptHLayout.addWidget(self.editLockingScriptCheckbox)
        self.mainVLayout.addLayout(self.lockingScriptHLayout)
        
        self.setLayout(self.mainVLayout)
        
    # Set output widget with transaction output (dict)
    def set_output(self, txout):
        pass
    
    def get_output(self):
        pass


class txmWindow(QMainWindow):
    
    def __init__(self):
        super().__init__()
        
        self.initUI()
        
    def initUI(self):
        
        # Central Widget
        self.centralWidget = QWidget(self)
        self.mainVLayout = QVBoxLayout()
        
        # Version
        self.versionHLayout = QHBoxLayout()
        self.versionLabel = QLabel("Version")
        self.versionLabel.setAlignment(Qt.AlignCenter)
        self.versionHLayout.addWidget(self.versionLabel)
        self.versionComboBox = QComboBox()
        self.versionComboBox.addItems(["1", "2"])
        self.versionHLayout.addWidget(self.versionComboBox)
        self.mainVLayout.addLayout(self.versionHLayout)
        
        ''' Inputs '''
        
        # Inputs group box
        self.inputsGroupBox = QGroupBox()
        self.inputsGroupBox.setTitle("Inputs")
        self.inputsVLayout = QVBoxLayout()
        
        # Input tabs
        self.inputsTabWidget = QTabWidget()
        self.inputTabs = [ inputTab(), inputTab() ]
        for i, tab in enumerate(self.inputTabs):
            self.inputsTabWidget.addTab(tab, "Input {:d}".format(i+1))
        
        # Add and remove input tabs
        self.removeAddInputTabButtons = QWidget()
        self.inputTabButtonsHLayout = QHBoxLayout()
        self.removeInputTabButton = QPushButton(QIcon('icons/redminus.png'),"")
        self.inputTabButtonsHLayout.addWidget(self.removeInputTabButton)
        self.addInputTabButton = QPushButton(QIcon('icons/greenplus.png'),"")
        self.inputTabButtonsHLayout.addWidget(self.addInputTabButton)
        self.inputTabButtonsHLayout.setContentsMargins(0,0,0,0)
        self.removeAddInputTabButtons.setLayout(self.inputTabButtonsHLayout)
        self.inputsTabWidget.setCornerWidget(self.removeAddInputTabButtons, Qt.TopRightCorner)
        
        self.inputsVLayout.addWidget(self.inputsTabWidget)
        
        self.inputsGroupBox.setLayout(self.inputsVLayout)
        
        self.mainVLayout.addWidget(self.inputsGroupBox)
        
        ''' Outputs '''
        
        # Outputs group box
        self.outputsGroupBox = QGroupBox()
        self.outputsGroupBox.setTitle("Outputs")
        self.outputsVLayout = QVBoxLayout()
        
        # Output tabs
        self.outputsTabWidget = QTabWidget()
        self.outputTabs = [ outputTab(), outputTab() ]
        for i, tab in enumerate(self.outputTabs):
            self.outputsTabWidget.addTab(tab, "Output {:d}".format(i+1))
        
        
        # Add and remove output tabs
        self.removeAddOutputTabButtons = QWidget()
        self.outputTabButtonsHLayout = QHBoxLayout()
        self.removeOutputTabButton = QPushButton(QIcon('icons/redminus.png'),"")
        self.outputTabButtonsHLayout.addWidget(self.removeOutputTabButton)
        self.addOutputTabButton = QPushButton(QIcon('icons/greenplus.png'),"")
        self.outputTabButtonsHLayout.addWidget(self.addOutputTabButton)
        self.outputTabButtonsHLayout.setContentsMargins(0,0,0,0)
        self.removeAddOutputTabButtons.setLayout(self.outputTabButtonsHLayout)
        self.outputsTabWidget.setCornerWidget(self.removeAddOutputTabButtons, Qt.TopRightCorner)
        
        
        self.outputsVLayout.addWidget(self.outputsTabWidget)
        
        self.outputsGroupBox.setLayout(self.outputsVLayout)
        
        self.mainVLayout.addWidget(self.outputsGroupBox)
        
        # Locktime 
        self.locktimeHLayout = QHBoxLayout()
        self.locktimeLabel = QLabel("Locktime")
        self.locktimeLabel.setAlignment(Qt.AlignCenter)
        self.locktimeHLayout.addWidget(self.locktimeLabel)
        self.locktimeEdit = QLineEdit()
        self.locktimeHLayout.addWidget(self.locktimeEdit)
        self.enableAbsoluteTimeLockCheckBox = QCheckBox("Enable Absolute Time Lock")
        self.locktimeHLayout.addWidget(self.enableAbsoluteTimeLockCheckBox)
        self.absoluteTimeLockEdit = QLineEdit()
        self.locktimeHLayout.addWidget(self.absoluteTimeLockEdit)
        self.absoluteTimeLockComboBox = QComboBox()
        self.absoluteTimeLockComboBox.addItems(["blocks since genesis block", "seconds since 1/1/1970"])
        self.locktimeHLayout.addWidget(self.absoluteTimeLockComboBox)
        self.mainVLayout.addLayout(self.locktimeHLayout)
        
        # Transaction buttons
        self.txButtonsHLayout = QHBoxLayout()
        spacerItem = QSpacerItem(100,100, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.txButtonsHLayout.addItem(spacerItem)
        self.signTxButton = QPushButton("Sign Transaction")
        self.txButtonsHLayout.addWidget(self.signTxButton)
        self.loadTxButton = QPushButton("Load Transaction")
        self.txButtonsHLayout.addWidget(self.loadTxButton)
        self.saveTxButton = QPushButton("Save Transaction")
        self.txButtonsHLayout.addWidget(self.saveTxButton)
        self.mainVLayout.addLayout(self.txButtonsHLayout)
        
        # Set central widget layout
        self.centralWidget.setLayout(self.mainVLayout)
        
        # Example
        self.versionComboBox.setCurrentIndex(1)
        
        txin1 = {'txid':"0e4ec2caff2fbbd7d32cfb4c567e5729dec5304478e1299ec51902cc1ed8bfca", 'index':0, 'value':10250, 'sequence':0xffffffff}
        self.inputTabs[0].set_input(txin1)
        
        #self.inputTabs[0].prevoutTxidEdit.setText("0e4ec2caff2fbbd7d32cfb4c567e5729dec5304478e1299ec51902cc1ed8bfca")
        #self.inputTabs[0].prevoutIndexEdit.setText("0")
        #self.inputTabs[0].prevoutValueEdit.setText("100000")
        #self.inputTabs[0].sequenceEdit.setText("ffffffff")
        
        
        self.setCentralWidget(self.centralWidget)
        
        #self.setGeometry(100, 100, 600, 200)
        geometry = app.desktop().availableGeometry()
        self.setGeometry(geometry)
        self.setWindowTitle("TX Maker")
        self.setWindowIcon(QIcon('icons/bitcoincashlogo.png'))
        self.show()

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    app = QApplication(sys.argv)
    txm = txmWindow()
    sys.exit(app.exec_())
        
        
    

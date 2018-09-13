#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''

Get rid of the fiat money system.

'''

from util import get_price

from address import Address
from network import Network
from wallet import Wallet

from PyQt5.QtCore import Qt
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

class SlwWindow(QMainWindow):
    
    def __init__(self):
        super().__init__()
        
        self.initUI()
        self.initWallet()
        
    def initUI(self):
        
        balanceLabel = QLabel('Balance')
        balanceLabel.setAlignment(Qt.AlignCenter)
        self.balanceDisplay = QLabel('0.00000000 BCH')
        self.priceDisplay = QLabel('-.-- EUR')
        
        refreshButton = QPushButton(QIcon('icons/refresh.png'),"")
        
        recvLabel = QLabel('Receive')
        recvLabel.setAlignment(Qt.AlignCenter)
        self.recvEdit = QLineEdit()
        self.recvEdit.setReadOnly(True)
        
        genNewAddrButton = QPushButton("New")
        
        sendtoLabel = QLabel('Send to')
        sendtoLabel.setAlignment(Qt.AlignCenter)
        self.sendAddrEdit = QLineEdit()
        
        amountLabel = QLabel('Amount (BCH)')
        amountLabel.setAlignment(Qt.AlignCenter)
        self.amountEdit = QLineEdit()
        maxAmountButton = QPushButton("Max")
        
        showPhraseButton = QPushButton("Show Secret Phrase")
        hidePhraseButton = QPushButton("Hide Secret Phrase")
        sendButton = QPushButton(QIcon('icons/greenrightarrow.png'), "SEND")
        
        self.phraseEdit = QLineEdit()
        self.phraseEdit.setReadOnly(True)
        
        refreshButton.clicked.connect(self.refresh_balance)
        genNewAddrButton.clicked.connect(self.gen_new_recv_addr)
        maxAmountButton.clicked.connect(self.set_max_amount)
        sendButton.clicked.connect(self.send_transaction)
        showPhraseButton.clicked.connect(self.show_mnemonic)
        hidePhraseButton.clicked.connect(self.hide_mnemonic)
        
        w = QWidget(self)
        grid = QGridLayout()
        grid.setSpacing(20)
        
        grid.addWidget(balanceLabel, 0, 0)
        grid.addWidget(self.balanceDisplay, 0, 1, 1, 1)
        grid.addWidget(self.priceDisplay, 0, 2, 1, 1)
        grid.addWidget(refreshButton, 0, 3)
        grid.addWidget(recvLabel, 1, 0)
        grid.addWidget(self.recvEdit, 1, 1, 1, 4)
        grid.addWidget(genNewAddrButton, 1, 5)
        grid.addWidget(sendtoLabel, 2, 0)
        grid.addWidget(self.sendAddrEdit, 2, 1, 1, 5)
        grid.addWidget(amountLabel, 3,0)
        grid.addWidget(self.amountEdit, 3, 1, 1, 4)
        grid.addWidget(maxAmountButton, 3, 5)
        grid.addWidget(showPhraseButton, 4, 0, 1, 2)
        grid.addWidget(hidePhraseButton, 4, 2, 1, 2)
        grid.addWidget(sendButton, 4, 4, 1, 2)
        grid.addWidget(self.phraseEdit, 5, 0, 1, 6)
        
        
        w.setLayout(grid)
        
        self.setCentralWidget(w)
        
        self.setGeometry(100, 100, 600, 200)
        self.setWindowTitle('SL-Wallet')
        self.setWindowIcon(QIcon('icons/bitcoincashlogo.png'))
        self.show()
        
    def initWallet(self):
        self.wallet = Wallet.load( "wallet.json" )
        self.set_balance()
        self.set_recv_addr()
        self.set_price()
        
        self.wallet.start_network()
        
    def set_recv_addr(self):
        try:
            waddr = self.wallet.recv_addresses[-1].to_cash()
        except:
            waddr = None
        if waddr:
            self.recvEdit.setText( waddr )
            
    def gen_new_recv_addr(self):
        self.wallet.add_new_address( branch=0 )
        self.set_recv_addr()            
            
    def set_balance(self):
        try:
            balance = self.wallet.get_balance()
        except:
            balance = None
        if balance:
            self.balanceDisplay.setText( "{:.8f} BCH".format( balance / 1e8 ) )

    def refresh_balance(self):
        self.wallet.update_utxos()
        self.set_balance()
    
    # TODO
    def set_price(self):
        try:
            self.price = get_price()
        except:
            self.price = None
        if self.price:
            value = self.price * self.wallet.get_balance() / 1e8
            self.priceDisplay.setText( "{:.2f} EUR".format( value ) )
    
    def set_max_amount(self):
        try:
            max_amount = self.wallet.compute_max_amount()
        except:
            max_amount = None
        if max_amount:
            self.amountEdit.setText( "{:.8f}".format( max_amount / 1e8 ) )        
            
    def send_transaction(self):
        try:
            output_address = Address.from_string( self.sendAddrEdit.text().strip() )
            amount = int( float( self.amountEdit.text().strip() ) * 1e8 )
        except:
            output_address = None
            amount = None
        if (output_address is not None) & (amount is not None):
            try:
                rawtx, txid, fee = self.wallet.make_standard_transaction(output_address, amount)
            except:
                rawtx = None
            if rawtx:
                bch_amount = amount / 1e8
                bch_fee = fee / 1e8
                eur_amount = self.price * bch_amount
                eur_fee = self.price * bch_fee
                
                msg = "Do you want to send this transaction?\n\nOutput address: {}\nAmount: {:.8f} BCH ({:.2f} €)\nFee: {:.8f} BCH ({:.2f} €)".format(output_address.to_cash(), bch_amount, eur_amount, bch_fee, eur_fee)
                msgBox = QMessageBox.question(self, "Transaction Confirmation", msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                
                txsent = False
                if msgBox == QMessageBox.Yes:
                    for p in self.wallet.network.peers:
                        if p.state == 'connected':
                            p.send_tx( rawtx )
                            #self.wallet.add_new_transaction( rawtx, txid )
                            txsent = True
                            #break
                print("transaction has been sent: {}".format(txid.hex()) if txsent else "could not send transaction")
            
            
    def show_mnemonic(self):
        try:
            mnemonic = self.wallet.keystore.get_mnemonic()
        except:
            mnemonic = ""
            
        if mnemonic:
            self.phraseEdit.setText( mnemonic )
    
    def hide_mnemonic(self):
        self.phraseEdit.setText( "" )
        
    def closeEvent(self, event):
        self.wallet.save()
        self.wallet.stop_network()




if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
    
    app = QApplication(sys.argv)
    slw = SlwWindow()
    sys.exit(app.exec_())
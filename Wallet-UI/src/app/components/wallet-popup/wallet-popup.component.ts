import { Component } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';

@Component({
  selector: 'app-wallet-popup',
  templateUrl: './wallet-popup.component.html',
  styleUrls: ['./wallet-popup.component.css']
})
export class WalletPopupComponent {
  // selectedOption: string;
  options = ['Ethereum', 'Multivers'];
  walletName: string;
  password: string;

  constructor(
    private dialogRef: MatDialogRef<WalletPopupComponent>,
    // private http: HttpClient,
  ) {
    // this.selectedOption = '';
    this.walletName = '';
    this.password = '';
  }

  createWallet() {
    const body = {
      email: localStorage.getItem('email'),
      wallet_name: this.walletName,
      password: '123',
    };

    if (this.walletName  === 'Ethereum') {
      // this.backendService.sendData(this.selectedOption)
      //   .subscribe(response => {
      //     console.log('Backend response:', response);
      //   }, error => {
      //     console.error('Error sending data to backend:', error);
      //   });
    } else {
      // return this.http.post('http://localhost:/eth-wallet/send-eth', body);
    }
    this.dialogRef.close();
  }
}

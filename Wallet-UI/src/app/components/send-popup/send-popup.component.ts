import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { MatDialogRef } from '@angular/material/dialog';


@Component({
  selector: 'app-send-popup',
  templateUrl: './send-popup.component.html',
  styleUrls: ['./send-popup.component.css']
})
export class SendPopupComponent {
  email: string;
  password: string;
  user: string | undefined;
  amount: number;
  // loggedIn: boolean;

  constructor(private dialogRef: MatDialogRef<SendPopupComponent>,
    // private http: HttpClient,
    ) {
    this.email = '';
    this.password = '';
    this.amount = 0;
    // this.loggedIn = false;
  }

  send() {
    const body = {
      username: localStorage.getItem('user'),
      wallet_name: 'Ethereum',
      amount: 1,
      password: '123',
      receiver: 'erd1ld6er5zpdze3cynzkapur9qhzh826jje6n87g7tvdfrtszs8jn2qv44nqd',
      description: 'Debt',
      uploaded_json: {}
    }
    ;
    // return this.http.post('http://localhost:/eth-wallet/send-eth', body);
    this.dialogRef.close();
  }
}

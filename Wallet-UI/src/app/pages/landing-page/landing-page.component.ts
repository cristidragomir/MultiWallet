import { Component, OnInit } from '@angular/core';
import { WalletService, Wallet, Transaction } from 'src/app/services/wallet-service/wallet.service';
import { MatDialog } from '@angular/material/dialog';
import { ProfilePageComponent } from '../profile-page/profile-page.component';
import { Router } from '@angular/router';
import { WalletPopupComponent } from 'src/app/components/wallet-popup/wallet-popup.component';
import { SendPopupComponent } from 'src/app/components/send-popup/send-popup.component';

@Component({
  selector: 'app-landing-page',
  templateUrl: './landing-page.component.html',
  styleUrls: ['./landing-page.component.css']
})
export class LandingPageComponent implements OnInit {
  totalSold = 0;
  transactions: Transaction[] = [];
  isFirstTimeUser: boolean = false;
  dropdownOptions = [
    { value: 'option1', viewValue: 'Ethereum' },
    { value: 'option2', viewValue: 'Option 2' },
    { value: 'option3', viewValue: 'Option 3' }
  ];

  displayedColumns: string[] = ['description', 'amount'];
  dataSource: Transaction[] = [
    { id: 1, description: '3d7dd0f8e3f7822840003c00eb09a9f', amount: 1.82 },
    { id: 2, description: 'bc81bf46e1e3cf963f3c69ceebce087' , amount: 30},
  ];

  selectedOption: string | undefined;

  constructor(private walletService: WalletService,
    private dialog: MatDialog,
    private router: Router) {}

  ngOnInit(): void {
    this.walletService.totalSold$.subscribe((totalSold) => (this.totalSold = totalSold));
    this.walletService.transactions$.subscribe((transactions) => (this.transactions = transactions));

    this.isFirstTimeUser = localStorage.getItem('firstTimeUser') === 'true';
  
    if (this.isFirstTimeUser) {
      console.log('Welcome, first-time user!');
    } else {
      console.log('Welcome back!');
    }

    const defaultWallet: Wallet = { id: 1, name: 'Default Wallet' };
    this.walletService.setCurrentWallet(defaultWallet);
  }

  goToProfile() {
    this.router.navigate(['profile']);
  }

  openWalletDialog() {
    const dialogRef = this.dialog.open(WalletPopupComponent, {
    });

    dialogRef.afterClosed().subscribe(result => {
      console.log('Dialog result:', result);
    });
  }

  openSendDialog() {
    const dialogRef = this.dialog.open(SendPopupComponent, {
      width: '30%',
    });

    dialogRef.afterClosed().subscribe(result => {
      console.log('Dialog result:', result);
    });
  }
}

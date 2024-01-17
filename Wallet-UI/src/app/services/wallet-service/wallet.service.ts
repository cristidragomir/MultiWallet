import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface Wallet {
  id: number;
  name: string;
}

export interface Transaction {
  id: number;
  description: string;
  amount: number;
}

@Injectable({
  providedIn: 'root'
})
export class WalletService {
  private totalSoldSubject = new BehaviorSubject<number>(0);
  totalSold$ = this.totalSoldSubject.asObservable();

  private transactionsSubject = new BehaviorSubject<Transaction[]>([]);
  transactions$ = this.transactionsSubject.asObservable();

  constructor() { }

  setCurrentWallet(wallet: Wallet): void {
    const { totalSold, transactions } = this.getWalletData(wallet);
    
    this.totalSoldSubject.next(totalSold);
    this.transactionsSubject.next(transactions);
  }

  private getWalletData(wallet: Wallet): { totalSold: number; transactions: Transaction[] } {
    return {
      totalSold: 500,
      transactions: [
        { id: 1, amount: 100, description: 'Sale 1' },
        { id: 2, amount: 150, description: 'Sale 2' },
      ],
    };
  }
}

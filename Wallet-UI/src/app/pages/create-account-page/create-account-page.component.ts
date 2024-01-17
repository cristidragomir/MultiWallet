import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { SocialUser } from "@abacritt/angularx-social-login";
import { CreateAccountService } from 'src/app/services/create-account-service/create-account.service';

@Component({
  selector: 'app-create-account-page',
  templateUrl: './create-account-page.component.html',
  styleUrls: ['./create-account-page.component.css']
})
export class CreateAccountPageComponent {
  email: string;
  password: string;
  user: string | SocialUser | undefined; 

  constructor(private router: Router,
    // private createAccountService: CreateAccountService,
    ) {
    this.email = '';
    this.password = '';
    this.user = '';
  }
  createAccount() {
    const accountData = { email: this.email, password: this.password, user: this.user};
    localStorage.setItem('firstTimeUser', 'true');
    this.router.navigate(['home']);
    // this.createAccountService.sendNewAccountData(accountData).subscribe(
    //     (response) => {
    //       console.log('Login successful:', response);
    //     },
    //     (error) => {
    //       console.error('Login failed:', error);
    //     }
    //   );
  }

  createAccountloginWithGoogle() {
    localStorage.setItem('firstTimeUser', 'true');
    this.router.navigate(['home']);
  }
}

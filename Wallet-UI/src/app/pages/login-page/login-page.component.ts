import { Component, OnInit, Renderer2, ElementRef, AfterViewInit } from '@angular/core';
import { SocialAuthService } from "@abacritt/angularx-social-login";
import { Router } from '@angular/router';
import { SocialUser } from "@abacritt/angularx-social-login";
import { GoogleLoginProvider } from "@abacritt/angularx-social-login";

declare const gapi: any;

@Component({
  selector: 'app-login-page',
  templateUrl: './login-page.component.html',
  styleUrls: ['./login-page.component.css']
})
export class LoginPageComponent implements OnInit,AfterViewInit {
  username: string;
  password: string;
  user: SocialUser | undefined;
  loggedIn: boolean;
  private customGoogleSigninButton: ElementRef | undefined;

  constructor(
    private socialAuthService: SocialAuthService,
    private router: Router,
    private renderer: Renderer2
  ) {
    this.username = '';
    this.password = '';
    this.loggedIn = false;
  }

  ngOnInit(): void {
    this.socialAuthService.authState.subscribe((user) => {
      this.user = user;
      this.loggedIn = (user != null);
      console.log(this.user);
      this.router.navigate(['create-account']);
    });
  }

  ngAfterViewInit(): void {
    gapi.load('auth2', () => {
      const auth2 = gapi.auth2.init({
        client_id: '622882092746-sirv7ner8d5hl35021e0q4j91clqilim.apps.googleusercontent.com',
        cookiepolicy: 'single_host_origin',
      });
      this.attachSignin(document.getElementById('customBtn'), auth2);
    });
  }

  attachSignin(element: any, auth2: any) {
    auth2.attachClickHandler(element, {},
      (googleUser: any) => {
        // Handle successful sign-in
        console.log('Signed in: ' + googleUser.getBasicProfile().getName());
      }, (error: any) => {
        // Handle sign-in error
        console.error(JSON.stringify(error, undefined, 2));
      }
    );
  }

  createCustomGoogleButton(): void {
    // Create a button element dynamically
    const buttonElement = this.renderer.createElement('button');
    this.renderer.addClass(buttonElement, 'google-login-btn');
    this.renderer.setProperty(buttonElement, 'innerText', 'Login with Google');
    this.renderer.listen(buttonElement, 'click', () => this.loginWithGoogle());

    // Append the button to the DOM
    const containerElement = document.getElementById('customButtonContainer'); // Change 'customButtonContainer' to the actual container ID
    if (containerElement) {
      this.renderer.appendChild(containerElement, buttonElement);
      this.customGoogleSigninButton = new ElementRef(buttonElement);
    } else {
      console.error('Unable to find the custom button container element.');
    }
  }

  login() {
    console.log('Login clicked');
    this.router.navigate(['create-account']);
  }

  loginWithGoogle(): void {
    // Handle Google login logic here
    console.log('Login with Google button clicked');
  }

  googleSigninCallback(response: any): void {
    console.log('Google Sign-In response:', response);

    // Handle the sign-in response as needed, e.g., redirect to create-account
    this.router.navigate(['create-account']);
  }
}

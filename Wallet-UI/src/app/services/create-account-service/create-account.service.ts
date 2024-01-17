import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class CreateAccountService {
  createAccountURL: string = '';
  createAccountWithGoogleURL: string = '';

  constructor(private http: HttpClient) { }

  // sendNewAccountData(loginData: any): Observable<any> {
  //   return this.http.post(this.createAccountURL, loginData);
  // }

  // sendNewAccountWithGoogleData(googleLoginData: any): Observable<any> {
  //   return this.http.post(this.createAccountWithGoogleURL, googleLoginData);
  // }
}

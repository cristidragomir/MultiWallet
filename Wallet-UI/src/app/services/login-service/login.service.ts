import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class LoginService {
  loginURL: string = '';
  loginWithGoogleURL: string = '';

  constructor(private http: HttpClient) { }

  // sendLoginData(loginData: any): Observable<any> {
  //   return this.http.post(this.loginURL, loginData);
  // }

  // sendloginWithGoogleData(googleLoginData: any): Observable<any> {
  //   return this.http.post(this.loginWithGoogleURL, googleLoginData);
  // }
}

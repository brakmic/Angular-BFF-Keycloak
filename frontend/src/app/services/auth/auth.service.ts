import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { ToastrService } from 'ngx-toastr';
import { MatSnackBar } from '@angular/material/snack-bar';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);
  private toastr: ToastrService = inject(ToastrService);
  private snackBar = inject(MatSnackBar);

  private isLoggedIn = false;

  private apiUrl = '/api';
  private authUrl = '/auth';
  private serverUrl = 'https://localhost:3000';

  constructor() {
    this.refreshSessionStatus();
  }

  markLoggedIn(): void {
    this.isLoggedIn = true;
    this.toastr.success('You are now logged in!', 'Success');
  }

  markLoggedOut(): void {
    this.isLoggedIn = false;
    this.toastr.success('You have been logged out.', 'Success');
  }

  refreshSessionStatus(): void {
    // Check if we have a valid session
    this.http.get(`${this.apiUrl}/profile`, { withCredentials: true })
      .subscribe({
        next: (_res) => {
          this.isLoggedIn = true;
        },
        error: (_err) => {
          this.isLoggedIn = false;
        }
      });
  }

  isAuthenticated(): boolean {
    return this.isLoggedIn;
  }

  login(): void {
    const width = 500,
      height = 500;
    const left = window.screenX + (window.innerWidth - width) / 2;
    const top = window.screenY + (window.innerHeight - height) / 2;

    const authWindow = window.open(
      `${this.authUrl}/keycloak`,
      'kcLoginPopup',
      `width=${width},height=${height},left=${left},top=${top},resizable,scrollbars=yes,status=yes`
    );

    const receiveMessageFn = (event: MessageEvent) => {
      if (event.origin !== this.serverUrl) return;

      if (event.data?.type === 'LOGIN_SUCCESS') {
        this.markLoggedIn();
        if (authWindow) {
          authWindow.close();
        }
        this.snackBar.open('Successfully logged in!', 'Close', {
          duration: 3000,
        });
        window.removeEventListener('message', receiveMessageFn);
      }
    };
    window.addEventListener('message', receiveMessageFn);
  }

  logout(): void {
    const width = 500,
      height = 500;
    const left = window.screenX + (window.innerWidth - width) / 2;
    const top = window.screenY + (window.innerHeight - height) / 2;

    const logoutWindow = window.open(
      `${this.authUrl}/logout`,
      'kcLogoutPopup',
      `width=${width},height=${height},left=${left},top=${top},resizable,scrollbars=yes,status=yes`
    );

    const receiveLogoutMessage = (event: MessageEvent) => {
      if (event.origin !== this.serverUrl) return;

      if (event.data?.type === 'LOGOUT_SUCCESS') {
        this.markLoggedOut();
        if (logoutWindow) {
          logoutWindow.close();
        }
        this.snackBar.open('Successfully logged out.', 'Close', {
          duration: 3000,
        });
        window.removeEventListener('message', receiveLogoutMessage);
      }
    };

    window.addEventListener('message', receiveLogoutMessage);
  }
}

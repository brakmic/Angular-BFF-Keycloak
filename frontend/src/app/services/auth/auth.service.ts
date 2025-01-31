import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { ToastrService } from 'ngx-toastr';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Subject } from 'rxjs';

import { AppSettings, APP_SETTINGS } from 'app/app.config';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);
  private toastr: ToastrService = inject(ToastrService);
  private snackBar = inject(MatSnackBar);

  private isLoggedIn = false;
  public authStateChanged = new Subject<void>();

  private settings: AppSettings = inject(APP_SETTINGS);
  private apiUrl = this.settings.api.baseUrl;

  constructor() {
    this.refreshSessionStatus();
  }

  markLoggedIn(): void {
    this.isLoggedIn = true;
    this.authStateChanged.next();
    this.toastr.success('You are now logged in!', 'Success');
  }

  markLoggedOut(): void {
    this.isLoggedIn = false;
    this.authStateChanged.next();
    this.toastr.success('You have been logged out.', 'Success');
  }

  refreshSessionStatus(): void {
    // Check if we have a valid session
    this.http.get(`${this.apiUrl}/api/profile`, { withCredentials: true })
      .subscribe({
        next: (_res) => {
          this.isLoggedIn = true;
          this.authStateChanged.next();
        },
        error: (_err) => {
          this.isLoggedIn = false;
          this.authStateChanged.next();
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
      `${this.apiUrl}/auth/keycloak-init`,
      'kcLoginPopup',
      `width=${width},height=${height},left=${left},top=${top},resizable,scrollbars=yes,status=yes`
    );

    const receiveMessageFn = (event: MessageEvent) => {
      if (event.origin !== this.apiUrl) return;

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
      `${this.apiUrl}/auth/logout`,
      'kcLogoutPopup',
      `width=${width},height=${height},left=${left},top=${top},resizable,scrollbars=yes,status=yes`
    );

    const receiveLogoutMessage = (event: MessageEvent) => {
      if (event.origin !== this.apiUrl) return;

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

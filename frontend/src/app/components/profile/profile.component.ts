import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { ToastrService } from 'ngx-toastr';
import { MatCardModule } from '@angular/material/card';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { ReactiveFormsModule, FormGroup, FormControl } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatIconModule } from '@angular/material/icon';

import { KeycloakUser } from '../../models/keycloak-user.model';
import { UserProfile } from '../../models/user-profile.model';
import { MatListModule } from '@angular/material/list';

import { AppSettings, APP_SETTINGS } from 'app/app.config';

@Component({
  selector: 'ng-kc-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.scss'],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    MatCardModule,
    MatProgressSpinnerModule,
    MatFormFieldModule,
    MatInputModule,
    MatIconModule,
    MatListModule,
  ],
})
export class ProfileComponent implements OnInit {
  private http = inject(HttpClient);
  private toastr = inject(ToastrService);
  private settings: AppSettings = inject(APP_SETTINGS);
  private apiUrl = this.settings.api.baseUrl;

  profileForm: FormGroup;
  loading = true;

  constructor() {
    this.profileForm = new FormGroup({
      displayName: new FormControl({ value: '', disabled: true }),
      email: new FormControl({ value: '', disabled: true }),
      firstName: new FormControl({ value: '', disabled: true }),
      lastName: new FormControl({ value: '', disabled: true }),
    });
  }

  ngOnInit(): void {
    this.fetchProfile();
  }

  fetchProfile(): void {
    this.http
      .get<{ user: KeycloakUser }>(`${this.apiUrl}/api/profile`, {
        withCredentials: true,
      })
      .subscribe({
        next: (res) => {
          const rawUser = res.user;
          const user: UserProfile = {
            userId: rawUser.id,
            displayName: rawUser.displayName,
            email: rawUser._json.email,
            firstName: rawUser._json.given_name,
            lastName: rawUser._json.family_name,
          };

          this.profileForm.patchValue({
            displayName: user.displayName,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
          });

          this.loading = false;
        },
        error: (err) => {
          console.error('Error fetching profile:', err);
          this.toastr.error('Failed to load profile.', 'Error');
          this.loading = false;
        },
      });
  }
}

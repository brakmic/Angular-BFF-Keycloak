// product-list.component.ts
import { Component, OnInit, OnDestroy, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatCardModule } from '@angular/material/card';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatListModule } from '@angular/material/list';
import { MatIconModule } from '@angular/material/icon';
import { HttpClient } from '@angular/common/http';
import { Subscription } from 'rxjs';
import { Product } from '@models';
import { AppSettings, APP_SETTINGS } from 'app/app.config';

@Component({
  selector: 'ng-kc-product-list',
  templateUrl: './product-list.component.html',
  styleUrls: ['./product-list.component.scss'],
  imports: [
    CommonModule,
    MatCardModule,
    MatListModule,
    MatIconModule,
    MatProgressSpinnerModule
  ]
})
export class ProductListComponent implements OnInit, OnDestroy {
  products: Product[] = [];
  loading = true;
  error: string | null = null;
  private subscription!: Subscription;

  private settings: AppSettings = inject(APP_SETTINGS);
  private apiUrl = this.settings.api.baseUrl;

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.subscription = this.http.get<{ products: Product[] }>(`${this.apiUrl}/api/products`)
      .subscribe({
        next: (response) => {
          this.products = response.products;
          this.loading = false;
        },
        error: (err) => {
          this.error = 'Failed to load products. Please try again later.';
          this.loading = false;
          console.error('API Error:', err);
        }
      });
  }

  ngOnDestroy() {
    if (this.subscription) {
      this.subscription.unsubscribe();
    }
  }
}

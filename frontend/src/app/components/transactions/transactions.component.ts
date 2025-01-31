import { Component, inject, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { CommonModule } from '@angular/common';
import { MatCardModule } from '@angular/material/card';
import { MatListModule } from '@angular/material/list';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { DatePipe } from '@angular/common';
import { Transaction } from '@models';
import { AppSettings, APP_SETTINGS } from 'app/app.config';

@Component({
  selector: 'app-transactions',
  imports: [
    CommonModule,
    MatCardModule,
    MatListModule,
    MatIconModule,
    MatProgressSpinnerModule,
    DatePipe
  ],
  templateUrl: './transactions.component.html',
  styleUrls: ['./transactions.component.scss']
})
export class TransactionsComponent implements OnInit {
  transactions: Transaction[] = [];
  loading = true;
  error: string | null = null;

  private settings: AppSettings = inject(APP_SETTINGS);
  private apiUrl = this.settings.api.baseUrl;

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.http.get<{ transactions: Transaction[] }>(`${this.apiUrl}/api/transactions`)
      .subscribe({
        next: (response) => {
          this.transactions = response.transactions;
          this.loading = false;
        },
        error: (err) => {
          this.error = 'Failed to load transactions. Please try again later.';
          this.loading = false;
          console.error('Error loading transactions:', err);
        }
      });
  }

  getTransactionIcon(type: string): string {
    return type === 'credit' ? 'arrow_upward' : 'arrow_downward';
  }
}

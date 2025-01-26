import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { HttpTestingController } from '@angular/common/http/testing';
import { TransactionsComponent } from './transactions.component';
import { DatePipe } from '@angular/common';

describe('TransactionsComponent', () => {
  let component: TransactionsComponent;
  let fixture: ComponentFixture<TransactionsComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TransactionsComponent],
      providers: [
        DatePipe,
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(TransactionsComponent);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display loading spinner initially', () => {
    const spinner = fixture.nativeElement.querySelector('mat-spinner');
    expect(spinner).toBeTruthy();
  });

  it('should display transactions after load', () => {
    const mockData = {
      transactions: [{
        id: '1',
        date: '2024-01-01',
        amount: '100.00',
        currency: 'USD',
        merchant: 'Test Merchant',
        type: 'debit'
      }]
    };

    const req = httpMock.expectOne('/api/transactions');
    req.flush(mockData);
    fixture.detectChanges();

    const items = fixture.nativeElement.querySelectorAll('mat-list-item');
    expect(items.length).toBe(1);
    expect(items[0].textContent).toContain('Test Merchant');
  });

  it('should show error message on failure', () => {
    const req = httpMock.expectOne('/api/transactions');
    req.error(new ProgressEvent('error'));
    fixture.detectChanges();

    const error = fixture.nativeElement.querySelector('.error-message');
    expect(error).toBeTruthy();
    expect(error.textContent).toContain('Failed to load transactions');
  });
});

import { ErrorHandler, Injectable, Injector } from '@angular/core';
import { ToastrService } from 'ngx-toastr';

@Injectable({
  providedIn: 'root',
})
export class GlobalErrorHandler implements ErrorHandler {
  private injector: Injector;

  constructor(injector: Injector) {
    this.injector = injector;
  }

  handleError(error: any): void {
    console.error('Global Error Handler:', error);

    // Lazily inject ToastrService to avoid circular dependency
    const toastr = this.injector.get(ToastrService);
    toastr.error('An unexpected error occurred. Please try again.', 'Error');
  }
}

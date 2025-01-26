import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { provideAnimations } from '@angular/platform-browser/animations';
import { ToastrModule } from 'ngx-toastr';
import { importProvidersFrom } from '@angular/core';

import { APP_ROUTES } from './app/app.routes';
import { AppComponent } from './app/app.component';
import { GlobalErrorHandler } from './app/services/error-handler/error-handler.service';
import { ErrorHandler } from '@angular/core';

export function tokenGetter(): string | null {
  return localStorage.getItem('token');
}

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(APP_ROUTES),
    provideHttpClient(withInterceptorsFromDi()),
    provideAnimations(),
    importProvidersFrom(
      ToastrModule.forRoot({
        timeOut: 3000,
        positionClass: 'toast-bottom-right',
        preventDuplicates: true,
      })
    ),
    { provide: ErrorHandler, useClass: GlobalErrorHandler },
  ],
});

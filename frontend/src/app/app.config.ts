import { ApplicationConfig, InjectionToken, provideZoneChangeDetection } from '@angular/core';

// Custom configuration interface
export interface AppSettings {
  api: {
    baseUrl: string;
    endpoints: {
      users: string;
      products: string;
      transactions: string;
    };
  };
  features: {
    analyticsEnabled: boolean;
    cacheTTL: number;
  };
}

export const APP_SETTINGS = new InjectionToken<AppSettings>('app.settings');

const applicationSettings: AppSettings = {
  api: {
    baseUrl: 'https://backend.local.com:3000',
    endpoints: {
      users: '/api/profile',
      products: '/api/products',
      transactions: '/api/transactions'
    }
  },
  features: {
    analyticsEnabled: true,
    cacheTTL: 300
  }
};

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    { provide: APP_SETTINGS, useValue: applicationSettings }
  ]
};

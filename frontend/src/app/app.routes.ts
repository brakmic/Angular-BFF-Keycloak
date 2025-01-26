import { Routes } from '@angular/router';
import { NavRoute, ErrorRoute } from '@types';
import { authGuard } from '@guards';
import { AccessDeniedComponent, HomeComponent,
  ProductListComponent, ProfileComponent,
  TransactionsComponent } from '@components';

export const APP_ROUTES: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  {
    path: 'home',
    component: HomeComponent,
    data: {
      nav: {
        label: 'Home',
        icon: 'home',
        alwaysShow: true
      }
    }
  } as NavRoute,
  {
    path: 'profile',
    component: ProfileComponent,
    data: {
      nav: {
        label: 'Profile',
        icon: 'person',
        authRequired: true
      }
    },
    canActivate: [authGuard]
  } as NavRoute,
  {
    path: 'products',
    component: ProductListComponent,
    data: {
      nav: {
        label: 'Products',
        icon: 'shopping_cart',
        authRequired: true
      }
    },
    canActivate: [authGuard]
  } as NavRoute,
  {
    path: 'transactions',
    component: TransactionsComponent,
    data: {
      nav: {
        label: 'Transactions',
        icon: 'list_alt',
        authRequired: true
      }
    },
    canActivate: [authGuard]
  } as NavRoute,
  {
    path: 'access-denied',
    component: AccessDeniedComponent,
    data: {
      isErrorPage: true
    }
  } as ErrorRoute,
  { path: '**', redirectTo: '/home' }
];

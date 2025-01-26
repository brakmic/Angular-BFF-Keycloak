import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../../services/auth/auth.service';
import { MatSnackBar } from '@angular/material/snack-bar';

export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router: Router = inject(Router);
  const snackBar = inject(MatSnackBar);

  if (authService.isAuthenticated()) {
    return true;
  } else {
    snackBar.open('You must be logged in to access this page.', 'Login', {
      duration: 5000,
    }).onAction().subscribe(() => {
      authService.login();
    });

    router.navigate(['/home']);
    return false;
  }
};

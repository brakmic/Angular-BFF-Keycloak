import { Component, OnDestroy } from '@angular/core';
import { AuthService } from '../../services/auth/auth.service';
import { ThemeService } from '../../services/theme/theme.service';
import { MatSnackBar } from '@angular/material/snack-bar';
import { CommonModule } from '@angular/common';
import { Router, NavigationEnd, RouterLink, RouterLinkActive } from '@angular/router';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatButtonModule } from '@angular/material/button';
import { MatTabsModule } from '@angular/material/tabs';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { NavItem } from '@types';
import { filter, Subscription } from 'rxjs';
import { NavRoute } from '@types';

@Component({
  selector: 'ng-kc-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.scss'],
  imports: [
    CommonModule,
    RouterLink,
    RouterLinkActive,
    MatToolbarModule,
    MatButtonModule,
    MatTabsModule,
    MatIconModule,
    MatSnackBarModule,
  ],
})
export class NavbarComponent implements OnDestroy {
  brand = 'MyApp';
  navItems: NavItem[] = [];
  private routerSub: Subscription;
  private authSub: Subscription;

  constructor(
    public authService: AuthService,
    public themeService: ThemeService,
    private snackBar: MatSnackBar,
    private router: Router
  ) {
    this.routerSub = this.router.events
      .pipe(filter((event): event is NavigationEnd => event instanceof NavigationEnd))
      .subscribe(() => this.buildNavItems());
    // rebuild navbar when the authentication state changes
    this.authSub = this.authService.authStateChanged.subscribe(() => this.buildNavItems());

    this.buildNavItems();
  }

  private buildNavItems(): void {
    this.navItems = this.router.config
      .filter((route): route is NavRoute => {
        const hasNavData = route.data && 'nav' in route.data;
        return !!hasNavData && !this.isErrorRoute(route);
      })
      .map(route => ({
        path: `/${route.path}`,
        label: route.data.nav.label,
        icon: route.data.nav.icon,
        authRequired: route.data.nav.authRequired ?? false,
        alwaysShow: route.data.nav.alwaysShow ?? false
      }));
  }

  private isErrorRoute(route: any): boolean {
    return route.data?.isErrorPage || 
           route.path === '**' || 
           route.path === 'access-denied';
  }

  shouldShowNavItem(item: NavItem): boolean {
    if (item.alwaysShow) return true;
    return item.authRequired 
      ? this.authService.isAuthenticated()
      : !this.authService.isAuthenticated();
  }

  login(): void {
    this.authService.login();
  }

  logout(): void {
    this.authService.logout();
  }

  showAccessDeniedMessage(): void {
    const snackBarRef = this.snackBar.open(
      'You must be logged in to access this page.',
      'Login',
      { duration: 5000 }
    );

    snackBarRef.onAction().subscribe(() => this.login());
  }

  ngOnDestroy(): void {
    this.routerSub?.unsubscribe();
    this.authSub?.unsubscribe();
  }
}

import { Route } from '@angular/router';
import { NavData } from './nav-data';

export interface NavRoute extends Route {
  data: {
    nav: NavData
  };
}

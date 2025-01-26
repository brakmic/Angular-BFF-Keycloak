import { Route } from '@angular/router';

export interface ErrorRoute extends Route {
  data: {
    isErrorPage: true
  };
}

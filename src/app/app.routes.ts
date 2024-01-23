import { Routes } from '@angular/router';
import { EmployeeListComponent } from './employee-list/employee-list.component';
import { AuthGuard } from './guard/auth.guard';

export const routes: Routes = [
  {path: '', component: EmployeeListComponent, canActivate: [AuthGuard]},
  {path: '**', redirectTo: ''}  // if url is unknown - redirect to main page
];


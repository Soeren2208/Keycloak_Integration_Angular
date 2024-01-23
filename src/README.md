# Keycloak-Integration mit Single Sign On

### Fabrikmethode initializeKeycloak() in app.config.ts

Um sicherzustellen, dass Keycloak initialisiert wird, wenn die Anwendung gebootet wird, muss ein APP_INITIALIZER-Provider
hinzugefügt werden. Dieser Provider ruft die Fabrikfunktion initializeKeycloak() auf, die den Keycloak-Dienst so einrichtet,
dass er in der Anwendung verwendet werden kann. Im Gegensatz zur Version_1 wurde diese Funktion in app.config.ts implementiert,
anstatt in einer eigenen Datei (keycloak-init.factory.ts im Ordner init).

```
function initializeKeycloak(keycloak: KeycloakService) {
  return () =>
    keycloak.init({
      config: {
        url: 'https://keycloak.szut.dev/auth',
        realm: 'szut',
        clientId: 'employee-management-service-frontend'
      },
      initOptions: {
        onLoad: 'check-sso',
        silentCheckSsoRedirectUri:
          window.location.origin + '/assets/silent-check-sso.html'
      },
      //enableBearerInterceptor: true
    });
}
```
    
Die Funktion initializeKeycloak() ist für die Initialisierung des Keycloak-Service verantwortlich. Sie gibt eine Factory-Funktion zurück
(return () => ...), die Angular als Initialisierungs-Funktion (keycloa.init()) dient. Innerhalb der init-Funktion werden Konfigurationsoptionen
(URL, Name des Realm nd Client-Id ) für den Keycloak-Client festgelegt.
Die Option onLoad: 'check-sso' in der Keycloak-Initialisierung bedeutet, dass beim Laden der Anwendung überprüft wird, ob der Benutzer
bereits bei Keycloak angemeldet ist (Single Sign-On, SSO). Diese Überprüfung erfolgt, indem ein unsichtbarer iFrame (Login-Iframe) erstellt
wird, der versucht, sich beim Keycloak-Server zu authentifizieren, ohne die Benutzeroberfläche der Anwendung zu beeinträchtigen.
Folgend die grundlegenden Schritte, die durch onLoad: 'check-sso' ausgeführt werden:
1) Beim Laden der Anwendung erstellt Keycloak einen unsichtbaren iFrame.
2) Der iFrame versucht, sich bei Keycloak anzumelden, um den Authentifizierungsstatus des Benutzers zu überprüfen.
3) Wenn der Benutzer bereits bei Keycloak angemeldet ist (Single Sign-On), wird der iFrame erfolgreich authentifiziert.
4) Keycloak sendet eine Benachrichtigung an die Hauptanwendung (durch das unsichtbare iFrame), um mitzuteilen, dass der Benutzer 
authentifiziert ist.
5) Die Anwendung kann dann entsprechend reagieren, z.B. indem sie den Benutzer automatisch weiterleitet oder bestimmte Ressourcen 
bereitstellt.

Das HTML-Snippet silent-check-sso.html im assets-Ordner wird dabei als Quelle für den unsichtbaren iFrame verwendet. 

```
<html>
  <body>
    <script>
      parent.postMessage(location.href, location.origin);
    </script>
  </body>
</html>
```
Dieses Snippet führt JavaScript-Code aus, der die aktuelle URL an das Elternfenster sendet. Dieser Kommunikationsmechanismus ermöglicht 
es der Anwendung, Informationen über den Authentifizierungsstatus des Benutzers zu erhalten, ohne die Hauptbenutzeroberfläche zu stören.

### APP_INITIALIZER in app.config.ts

```
export const appConfig: ApplicationConfig = {
  providers: [provideRouter(routes),importProvidersFrom(KeycloakAngularModule),
    {
    provide: APP_INITIALIZER,
    useFactory: initializeKeycloak,
    multi: true,
    deps: [KeycloakService],
  }]
};
```

Die Konstante appConfig vom Typ ApplicationConfig dient zur Konfiguration der Angular-Anwendung.  

APP_INITIALIZER ist ein Token in Angular, das verwendet wird, um Funktionen zu registrieren, die vor dem Start der Anwendung
ausgeführt werden sollen. Diese Funktionen können dazu dienen, Initialisierungen durchzuführen, Daten zu laden oder andere 
Vorbereitungen zu treffen. Das APP_INITIALIZER-Token wird normalerweise in der Konfiguration
der Angular-Anwendung verwendet, um eine oder mehrere Initialisierungsfunktionen anzugeben. Hier wird APP_INITIALIZER so
konfiguriert, dass die initializeKeycloak-Factory-Funktion von oben als Initialisierungsfunktion für den Keycloak-Service 
verwendet wird. multi gibt an, dass es mehrere Anbieter desselben Tokens geben kann, useFactory gibt an, dass die 
Factory-Funktion von oben zur Initialisierung des Keycloak-Services verwendet werden soll; deps gibt an, welche Abhängigkeiten 
der Factory-Funktion übergeben werden sollen, in diesem Fall der benötigte KeycloakService.

Damit die Anwendung jedem Http-Request den Bearer-Token automatisch mitgibt und dieses nicht bei der Implementierung jeden Requests händisch
(siehe auskommentierte Methode unten) passieren muss, ist importProvidersFrom(KeycloakAngularModule) entscheidend. Hier werden die
Provider aus dem KeycloakAngularModule importiert. Dazu gehört der KeycloakService, der standardmäßig einen KeycloakBearerInterceptor
mitbringt. Dieser Interceptor fügt automatisch das Bearer-Token, das der Keycloak-Service nach erfolgreicher Authentifizierung hält, den 
Requests an. 
Beachte: enableBearerInterceptor: true ist im ersten Snippet auskommentiert, weil der KeycloakService standardmäßig als Bearer-Interceptor 
konfiguriert ist. Die Zeile würde diese Standardkonfiguration nur noch einmal sicherstellen, also dem Keycloak-Service mitteilen, dass er als
HTTP-Interceptor für Bearer-Token agieren soll.

### Auth-Guard

Der AuthGuard dient dazu, authentifizierte Routen in der Anwendung zu schützen. Er stellt Informationen zur Verfügung, um zu
sehen, ob der Benutzer eingeloggt ist sowie eine Liste von Rollen, die zu dem Benutzer gehören. Für die Keycloak-Integration
ist dafür KeycloakAuthGuard zu erweitern sowie die Methode isAccessAllowed() zu implementieren. 

```
export class AuthGuard extends KeycloakAuthGuard {
  constructor(protected override readonly router: Router, protected readonly keycloak: KeycloakService) {
    super(router, keycloak);
  }

  async isAccessAllowed(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot): Promise<boolean | UrlTree> {

    if (!this.authenticated) {
      await this.keycloak.login({
        redirectUri: window.location.origin + state.url,
      });
    }
    return this.authenticated;
  }
}
```
    
Die Erweiterung der Klasse KeycloakAuthGuard ermöglicht die Verwendung von Keycloak-spezifischen Funktionen in diesem Guard.
Die Methode isAccessAllowed() überprüft, ob der Benutzer Zugriff auf eine bestimmte Route haben sollte. 

route: ActivatedRouteSnapshot: Informationen über die zu schützende Route.
state: RouterStateSnapshot: Zustand des Routers.

Innerhalb dieser Methode wird überprüft, ob der Benutzer authentifiziert ist (this.authenticated). Wenn nicht, wird der 
Benutzer zur Keycloak-Login-Seite weitergeleitet (await this.keycloak.login(...)). Der redirectUri wird so konfiguriert, 
dass der Benutzer nach dem erfolgreichen Login zur ursprünglichen angeforderten URL zurückgeleitet wird.

Die Methode gibt true zurück, wenn der Zugriff erlaubt ist (der Benutzer ist authentifiziert), andernfalls false. 
Das Ergebnis ist vom Typ Promise<boolean | UrlTree>, um asynchrone Operationen zu unterstützen und im Falle einer 
Nichtauthentifizierung die Weiterleitung zur Login-Seite zu ermöglichen.

In diesem Fall fehlen die Rollen, könnten aber wie folgt hinzugefügt werden:

```
public async isAccessAllowed(
        route: ActivatedRouteSnapshot,
        state: RouterStateSnapshot
    ): Promise<boolean> {
        // Force the user to log in if currently unauthenticated.
        if (!this.authenticated) {
            await this.keycloak.login({
                redirectUri: window.location.origin + state.url,
            });
        }

        // Get the roles required from the route.
        const requiredRoles = route.data.roles;

        // Allow the user to proceed if no additional roles are required to access the route.
        if (!(requiredRoles instanceof Array) || requiredRoles.length === 0) {
            return true;
        }

        // Allow the user to proceed if all the required roles are present.
        return requiredRoles.every((role) => this.roles.includes(role));
    }
```

### Verwendung des Auth-Guard in app.routes.ts

Der AuthGuard wird dazu verwendet, den Zugriff auf die verschiedenen Routen zu steuern.  In diesem Beispiel wird der AuthGuard 
als canActivate-Guard für die Route mit der leeren Zeichenkette als Pfad ('') verwendet:

```
export const routes: Routes = [
  {path: '', component: EmployeeListComponent, canActivate: [AuthGuard]},
  {path: '**', redirectTo: ''}  // if url is unknown - redirect to main page
];
```
{ path: '' }: Diese Route ist mit dem leeren Pfad verbunden. Das bedeutet, dass EmployeeListComponent angezeigt wird, wenn die Haupt-URL 
aufgerufen wird. Der canActivate: [AuthGuard]-Teil gibt an, dass der AuthGuard vor dem Anzeigen dieser Komponente überprüfen sollte, ob der 
Benutzer authentifiziert ist und Zugriff hat.
{ path: '**', redirectTo: '' }: Diese Route fängt alle unbekannten URLs ab und leitet sie zum leeren Pfad ('') um.


### Programmatisches Hinzufügen des Bearer-Tokens, wenn der Standardmechanismus überschrieben wurde

```
async fetchData() {
  const bearerToken = await this.keycloakService.getToken();
  this.employees$ = this.http.get<Employee[]>('/backend', {
  headers: new HttpHeaders()
    .set('Content-Type', 'application/json')
    .set('Authorization', `Bearer ${bearerToken}`)
  });
}
```

### Alternative: ein eigener Interceptor

Alternativ zur Verwendung des Bearer-Interceptors des Keycloak-Service kann die Angular HttpInterceptor-Schnittstelle verwendet werden, 
um einen eigenen Interceptor zu erstellen. Dieser Interceptor ruft dann den Bearer-Token aus dem KeycloakService ab und fügt diesen dann den 
Authorization-Header zu jedem ausgehenden HTTP-Request hinzu. Die folgende Implementierung des HttpInterceptor-Ansatzes gibt einem mehr Kontrolle 
über die Token-Logik und ermöglicht, benutzerdefinierte Anpassungen vorzunehmen, wenn nötig.

```
import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';
import { KeycloakService } from 'keycloak-angular';

@Injectable()
export class KeycloakHttpInterceptor implements HttpInterceptor {

  constructor(private keycloakService: KeycloakService) { }

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // Token vom Keycloak-Service abrufen
    const token = this.keycloakService.getToken();

    // Wenn ein Token vorhanden ist, füge den Authorization-Header hinzu
    if (token) {
      request = request.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      });
    }

    // Den bearbeiteten Request an den nächsten Interceptor weitergeben
    return next.handle(request);
  }
}

import { APP_INITIALIZER, ApplicationConfig, HTTP_INTERCEPTORS } from '@angular/core';
import { provideRouter } from '@angular/router';
import { KeycloakService } from 'keycloak-angular';
import { routes } from './app.routes';
import { KeycloakHttpInterceptor } from './path-to-your-interceptor/KeycloakHttpInterceptor';

function initializeKeycloak(keycloak: KeycloakService) {
  return () =>
    keycloak.init({
      config: {
        url: 'https://keycloak.szut.dev/auth',
        realm: 'szut',
        clientId: 'employee-management-service-frontend'
      },
      initOptions: {
        onLoad: 'check-sso',
        silentCheckSsoRedirectUri: window.location.origin + '/assets/silent-check-sso.html'
      },
    });
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    {
      provide: APP_INITIALIZER,
      useFactory: initializeKeycloak,
      multi: true,
      deps: [KeycloakService]
    },
    // Hinzufügen des KeycloakHttpInterceptor als HTTP-Interceptor
    {
      provide: HTTP_INTERCEPTORS,
      useClass: KeycloakHttpInterceptor,
      multi: true,
      deps: [KeycloakService]
    }
  ]
};
```

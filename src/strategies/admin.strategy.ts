import {AuthenticationStrategy} from '@loopback/authentication';
import {service} from '@loopback/core';
import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {AutenticacionService} from '../services';

export class EstrategiaAdministrador implements AuthenticationStrategy {
  name: string = 'administrador';

  constructor(
    @service(AutenticacionService)
    public servicioAutenticacion: AutenticacionService
  ) { }

  async authenticate(request: Request): Promise<UserProfile | undefined> {
    let token = parseBearerToken(request);
    if (token) {
      let datos = this.servicioAutenticacion.ValidarTokenJWT(token)
      // Aquí harían la validación dependiendo del rol
      if (datos) {
        if (datos.data.rol == 'administrador') {
          let perfil: UserProfile = Object.assign({
            nombre: datos.data.nombre
          });
          return perfil
        } else {
          if (datos.data.rol == 'cliente') {
            let perfil: UserProfile = Object.assign({
              nombre: datos.data.nombre
            });
            return perfil;
          } else {
            return;
          }
        }
      } else {
        throw new HttpErrors[401]('El token estaba malo')
      }
    } else {
      throw new HttpErrors[401]('No sé incluyó el token Administrador')
    }
  }
}

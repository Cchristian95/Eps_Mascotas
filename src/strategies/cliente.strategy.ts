import { AuthenticationStrategy } from "@loopback/authentication";
import { service } from "@loopback/core";
import { Request, RedirectRoute, HttpErrors } from "@loopback/rest";
import { UserProfile } from "@loopback/security";
import { ParamsDictionary } from "express-serve-static-core";
import parseBearerToken from "parse-bearer-token";
import { ParsedQs } from "qs";
import { AutenticacionService } from "../services";

export class EstrategiaCliente implements AuthenticationStrategy {
    name: string = 'cliente';

    constructor(
        @service(AutenticacionService)
        public servicioAutenticacion: AutenticacionService
    ) { }

    async authenticate(request: Request): Promise<UserProfile | undefined> {
        let token = parseBearerToken(request);
        if (token) {
            let datos = this.servicioAutenticacion.ValidarTokenJWT(token)
            if (datos) {
                let perfil: UserProfile = Object.assign({
                    nombre: datos.data.nombre
                });
                return perfil;
            } else {
                throw new HttpErrors[401]('Token Incorrecto')
            }
        } else {
            throw new HttpErrors[401]('No se incluyó el Token para el cliente')
        }
    }
}

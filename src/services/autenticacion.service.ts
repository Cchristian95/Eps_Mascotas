import {injectable, /* inject, */ BindingScope} from '@loopback/core';
import {repository} from '@loopback/repository';
import {Usuario} from '../models';
import {UsuarioRepository} from '../repositories';
import {llaves} from '../config/llaves';
const generador = require('password-generator');
const cryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');

@injectable({scope: BindingScope.TRANSIENT})
export class AutenticacionService {
// Aqui vamos a poner las inyeccion del repositorio
  constructor(
    @repository(UsuarioRepository)
    public usuarioRepository : UsuarioRepository
  ) {}

  /*
   * Add service methods here
   */

  GenerarClave(){
    let clave = generador(8,false);
    return clave;

  }

  CifrarClave(clave:String){
    let claveCifrada = cryptoJS.MD5(clave).toString();
    return claveCifrada;
  }

  identificarUsuario(usuario: string, password: string){
    try{
      let p = this.usuarioRepository.findOne({where: {correo: usuario, password: password}});
      if (p){
        return p;
      }
      return false;
    }catch{
      return false;
    }
  }

  GeneradorTokenJWT(usuario: Usuario){
    let token = jwt.sign({
      data: {
        id: usuario.id,
        correo: usuario.correo,
        nombre: usuario.nombre
      }
    },
    llaves.claveJWT);
    return token;
  }

  ValidarTokenJWT(token:string){
    try{
      let datos = jwt.verify(token, llaves.claveJWT);
      return datos;
    }catch{
      return false;
    }
  }

}

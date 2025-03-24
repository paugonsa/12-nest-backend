import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { AuthService } from 'src/auth/auth.service';
import { JwtPayload } from 'src/auth/interfaces/jwt-payloads';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private jwtService: JwtService,
    private authService: AuthService
  ){}

  async canActivate(
    context: ExecutionContext ): Promise<boolean>{

      const request = context.switchToHttp().getRequest();
      const token = this.extratTokenFromHeader(request);

      if(!token ){
        throw new UnauthorizedException('No hay token en la petición');
      }

      try {
        const payload = await this.jwtService.verifyAsync<JwtPayload>(
          token, {secret: process.env.JWT_SEED! }
        );

        const user = await this.authService.findUserById(payload.id);
        if(!user) throw new UnauthorizedException('User does not exits');


        request['user'] = payload.id;

      }catch (error) {
        throw new UnauthorizedException();
      }
      
    return true;
  }

  private extratTokenFromHeader( request: Request): string | undefined {
    const [type, token ] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token: undefined;
  }
}

// src/auth/strategies/google-oauth.strategy.ts
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class GoogleOAuthStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleOAuthStrategy.name);

  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    const clientID = configService.get('GOOGLE_CLIENT_ID');
    const clientSecret = configService.get('GOOGLE_CLIENT_SECRET');
    const callbackURL = configService.get('GOOGLE_CALLBACK_URL');

    // Validate required configuration
    if (!clientID || !clientSecret || !callbackURL) {
      throw new Error(
        'Google OAuth configuration missing. Please check GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_CALLBACK_URL environment variables.'
      );
    }

    super({
      clientID,
      clientSecret,
      callbackURL,
      scope: ['email', 'profile'],
      passReqToCallback: false, // ✅ Required property
    });

    this.logger.log('✅ Google OAuth Strategy initialized');
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    this.logger.log(`🔧 Google OAuth attempt for: ${profile.emails?.[0]?.value}`);
    
    try {
      const { name, emails, photos } = profile;
      
      if (!emails || !emails[0]) {
        throw new Error('No email provided by Google');
      }

      const user = {
        email: emails[0].value,
        firstName: name?.givenName || 'Google',
        lastName: name?.familyName || 'User',
        picture: photos?.[0]?.value,
        accessToken,
        refreshToken,
      };

      const result = await this.authService.validateOrCreateUserFromOAuth(user);
      this.logger.log(`✅ Google OAuth successful for: ${user.email}`);
      done(null, result);
    } catch (error) {
      this.logger.error(`❌ Google OAuth validation error: ${error}`);
      done(error, false);
    }
  }
}
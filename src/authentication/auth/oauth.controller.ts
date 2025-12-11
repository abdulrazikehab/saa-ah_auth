// src/auth/oauth.controller.ts
import { 
  Controller, 
  Get, 
  UseGuards, 
  Req, 
  Res, 
  Post, 
  Body,
  Logger 
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { JwtAuthGuard } from '../guard/jwt-auth.guard';
import { AuthService } from './auth.service';

@Controller('auth') // Changed from 'auth/oauth' to 'auth' to match /auth/google expectation
export class OAuthController {
  private readonly logger = new Logger(OAuthController.name);

  constructor(private authService: AuthService) {}

  // GET /auth/oauth/google
  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    this.logger.log('🔧 Initiating Google OAuth flow');
    return { message: 'Redirecting to Google OAuth' };
  }

// src/auth/oauth.controller.ts
@Get('oauth/google/callback')
@UseGuards(AuthGuard('google'))
async googleAuthRedirect(@Req() req: any, @Res() res: Response) {
  try {
    this.logger.log('🔧 Google OAuth callback received');
    
    if (!req.user) {
      throw new Error('No user data from Google OAuth');
    }

    const result = req.user;
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    
    // Validate required fields
    if (!result.accessToken || !result.refreshToken) {
      this.logger.error('❌ Missing tokens in OAuth result');
      const errorUrl = `${frontendUrl}/auth/login?error=authentication_failed`;
      return res.redirect(errorUrl);
    }

    // Build redirect URL with proper encoding
    const redirectParams = new URLSearchParams({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      setupPending: String(result.setupPending || false),
      userId: result.id,
      tenantId: result.tenantId
    });

    const redirectUrl = `${frontendUrl}/oauth/callback?${redirectParams.toString()}`;
    
    this.logger.log(`✅ Google OAuth successful, redirecting to frontend`);
    this.logger.debug(`Redirect URL: ${redirectUrl.replace(/accessToken=([^&]+)/, 'accessToken=***')}`);
    
    res.redirect(redirectUrl);
  } catch (error) {
    this.logger.error(`❌ Google OAuth callback error: ${error}`);
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    const errorUrl = `${frontendUrl}/auth/login?error=oauth_failed`;
    res.redirect(errorUrl);
  }
}

  // POST /auth/oauth/mock-google-auth
  @Post('mock-google-auth')
  async mockGoogleAuth(@Body() mockData: {
    email: string;
    firstName: string;
    lastName: string;
    picture?: string;
  }) {
    this.logger.log('🔧 Mock Google OAuth called with:', mockData.email);
    
    if (!mockData.email) {
      throw new Error('Email is required');
    }

    // This simulates what happens after Google OAuth callback
    return this.authService.validateOrCreateUserFromOAuth({
      email: mockData.email,
      firstName: mockData.firstName || 'Mock',
      lastName: mockData.lastName || 'User',
      picture: mockData.picture
    });
  }

  // POST /auth/oauth/complete-setup
  @Post('complete-setup')
  @UseGuards(JwtAuthGuard)
  async completeSetup(
    @Req() req: any,
    @Body() setupData: { storeName: string; subdomain: string }
  ) {
    this.logger.log(`🔧 Completing OAuth setup for user: ${req.user.id}`);
    
    if (!setupData.storeName || !setupData.subdomain) {
      throw new Error('Store name and subdomain are required');
    }

    return this.authService.completeOAuthSetup(req.user.id, setupData);
  }

  // GET /auth/oauth/providers
  @Get('providers')
  getOAuthProviders() {
    const isGoogleConfigured = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
    
    this.logger.log(`🔧 OAuth providers check - Google: ${isGoogleConfigured ? 'Enabled' : 'Disabled'}`);
    
    return {
      google: {
        enabled: isGoogleConfigured,
        authUrl: '/auth/oauth/google'
      }
    };
  }

  // GET /auth/oauth/config-check
  @Get('config-check')
  checkOAuthConfig() {
    const config = {
      GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID ? '✅ Set' : '❌ Missing',
      GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET ? '✅ Set' : '❌ Missing', 
      GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL ? '✅ Set' : '❌ Missing',
      FRONTEND_URL: process.env.FRONTEND_URL ? '✅ Set' : '❌ Missing',
    };

    return {
      message: 'OAuth Configuration Check',
      configured: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
      config,
    };
  }
}
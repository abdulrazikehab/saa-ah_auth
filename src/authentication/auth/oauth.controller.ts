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
import { PrismaService } from '../../prisma/prisma.service';

@Controller('auth') // Main route prefix
export class OAuthController {
  private readonly logger = new Logger(OAuthController.name);

  constructor(
    private authService: AuthService,
    private prismaService: PrismaService,
  ) {}

  // GET /google (for Login/Signup pages)
  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    this.logger.log('🔧 Initiating Google OAuth flow');
    return { message: 'Redirecting to Google OAuth' };
  }

  // GET /auth/oauth/google (alternative route)
  @Get('oauth/google')
  @UseGuards(AuthGuard('google'))
  async googleAuthOAuth() {
    this.logger.log('🔧 Initiating Google OAuth flow (via /oauth/google)');
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
    
    // Validate required fields
    if (!result.accessToken || !result.refreshToken) {
      this.logger.error('❌ Missing tokens in OAuth result');
      const fallbackUrl = this.getFallbackFrontendUrl();
      const errorUrl = `${fallbackUrl}/auth/login?error=authentication_failed`;
      return res.redirect(errorUrl);
    }

    // Always use main domain for OAuth callback (not tenant subdomain)
    // OAuth callbacks should always go to the main domain: https://saeaa.com/oauth/callback
    const frontendUrl = this.getMainDomainFrontendUrl();
    this.logger.log(`✅ Using main domain for OAuth callback: ${frontendUrl}`);

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
    const fallbackUrl = this.getFallbackFrontendUrl();
    const errorUrl = `${fallbackUrl}/auth/login?error=oauth_failed`;
    res.redirect(errorUrl);
  }
}

/**
 * Build tenant-specific frontend URL based on subdomain
 */
private buildTenantFrontendUrl(subdomain: string): string {
  const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
  const url = new URL(baseUrl);
  const hostname = url.hostname;
  const protocol = url.protocol;
  const port = url.port || (protocol === 'https:' ? '443' : '80');

  // Handle localhost (development)
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    const portPart = port && port !== '80' && port !== '443' ? `:${port}` : '';
    return `${protocol}//${subdomain}.localhost${portPart}`;
  }

  // Handle production domains (saeaa.com, saeaa.net)
  if (hostname.includes('saeaa.com')) {
    const portPart = port && port !== '80' && port !== '443' ? `:${port}` : '';
    return `${protocol}//${subdomain}.saeaa.com${portPart}`;
  }

  if (hostname.includes('saeaa.net')) {
    const portPart = port && port !== '80' && port !== '443' ? `:${port}` : '';
    return `${protocol}//${subdomain}.saeaa.net${portPart}`;
  }

  // Fallback: use subdomain pattern with original hostname
  const portPart = port && port !== '80' && port !== '443' ? `:${port}` : '';
  return `${protocol}//${subdomain}.${hostname}${portPart}`;
}

/**
 * Get fallback frontend URL when tenant subdomain cannot be determined
 */
private getFallbackFrontendUrl(): string {
  return process.env.FRONTEND_URL || 'http://localhost:5173';
}

/**
 * Get main domain frontend URL (always use main domain, not tenant subdomain)
 * For OAuth callbacks, we always redirect to the main domain
 */
private getMainDomainFrontendUrl(): string {
  const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
  const url = new URL(baseUrl);
  const hostname = url.hostname;
  const protocol = url.protocol;
  const port = url.port || (protocol === 'https:' ? '443' : '80');
  
  // For localhost, return as-is
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    const portPart = port && port !== '80' && port !== '443' ? `:${port}` : '';
    return `${protocol}//localhost${portPart}`;
  }

  // For production, always use main domain (saeaa.com or saeaa.net)
  // Remove any subdomain prefix (e.g., saeaa.saeaa.com -> saeaa.com)
  if (hostname.includes('saeaa.com')) {
    // Extract main domain (saeaa.com)
    const portPart = port && port !== '80' && port !== '443' ? `:${port}` : '';
    return `${protocol}//saeaa.com${portPart}`;
  }

  if (hostname.includes('saeaa.net')) {
    // Extract main domain (saeaa.net)
    const portPart = port && port !== '80' && port !== '443' ? `:${port}` : '';
    return `${protocol}//saeaa.net${portPart}`;
  }

  // For other domains, remove subdomain if present
  const parts = hostname.split('.');
  if (parts.length > 2) {
    // Has subdomain, use main domain (last two parts)
    const mainDomain = parts.slice(-2).join('.');
    const portPart = port && port !== '80' && port !== '443' ? `:${port}` : '';
    return `${protocol}//${mainDomain}${portPart}`;
  }

  // Already main domain, return as-is
  const portPart = port && port !== '80' && port !== '443' ? `:${port}` : '';
  return `${protocol}//${hostname}${portPart}`;
}

  // POST /auth/oauth/mock-google-auth
  @Post('oauth/mock-google-auth')
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
  @Post('oauth/complete-setup')
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
  @Get('oauth/providers')
  getOAuthProviders() {
    const isGoogleConfigured = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
    
    this.logger.log(`🔧 OAuth providers check - Google: ${isGoogleConfigured ? 'Enabled' : 'Disabled'}`);
    
    return {
      google: {
        enabled: isGoogleConfigured,
        authUrl: '/google'
      }
    };
  }

  // GET /auth/oauth/config-check
  @Get('oauth/config-check')
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
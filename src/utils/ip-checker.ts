/**
 * IP Geolocation and VPN Detection Utility
 * Uses ipgeolocation.io for accurate location data
 */

import { Logger } from '@nestjs/common';

const logger = new Logger('IpChecker');

// Get API key from environment variable
const IP_GEOLOCATION_API_KEY = process.env.IP_GEOLOCATION_API_KEY || 'e649fc71bbd4406fbe1e574f6c39026a';

export interface IpCheckResult {
  isVpn: boolean;
  isProxy: boolean;
  isTor: boolean;
  isDatacenter: boolean;
  country?: string;
  countryCode?: string;
  city?: string;
  region?: string;
  zipCode?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  isp?: string;
  organization?: string;
  riskScore: number;
  message?: string;
}

export interface GeoLocation {
  ip: string;
  country: string;
  countryCode: string;
  city: string;
  region: string;
  zipCode: string;
  latitude: number;
  longitude: number;
  timezone: string;
  isp: string;
  organization: string;
  isVpn: boolean;
  isProxy: boolean;
  isTor: boolean;
  isDatacenter: boolean;
}

// Type for ipgeolocation.io response
interface IpGeolocationResponse {
  message?: string;
  country_name?: string;
  country_code2?: string;
  city?: string;
  state_prov?: string;
  zipcode?: string;
  latitude?: string;
  longitude?: string;
  time_zone?: { name?: string };
  isp?: string;
  organization?: string;
  security?: {
    is_proxy?: boolean;
    is_vpn?: boolean;
    is_tor?: boolean;
    is_bot?: boolean;
    is_cloud_provider?: boolean;
    is_anonymous?: boolean;
  };
}

// Type for ip-api.com response
interface IpApiResponse {
  status: string;
  message?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  regionName?: string;
  city?: string;
  zip?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isp?: string;
  org?: string;
  as?: string;
  proxy?: boolean;
  hosting?: boolean;
}

/**
 * Check IP using ipgeolocation.io (requires API key)
 */
async function checkWithIpGeolocation(ip: string): Promise<IpCheckResult | null> {
  try {
    if (!IP_GEOLOCATION_API_KEY) {
      logger.warn('IP_GEOLOCATION_API_KEY not configured, falling back to ip-api.com');
      return null;
    }

    const response = await fetch(
      `https://api.ipgeolocation.io/ipgeo?apiKey=${IP_GEOLOCATION_API_KEY}&ip=${ip}&include=security`
    );
    const data = await response.json() as IpGeolocationResponse;

    if (data.message) {
      logger.warn(`ipgeolocation.io error for ${ip}: ${data.message}`);
      return null;
    }

    const security = data.security || {};
    const isProxy = security.is_proxy === true;
    const isVpn = security.is_vpn === true;
    const isTor = security.is_tor === true;
    const isBot = security.is_bot === true;
    const isDatacenter = security.is_cloud_provider === true || security.is_anonymous === true;

    return {
      isVpn,
      isProxy,
      isTor,
      isDatacenter,
      country: data.country_name,
      countryCode: data.country_code2,
      city: data.city,
      region: data.state_prov,
      zipCode: data.zipcode,
      latitude: data.latitude ? parseFloat(data.latitude) : undefined,
      longitude: data.longitude ? parseFloat(data.longitude) : undefined,
      timezone: data.time_zone?.name,
      isp: data.isp,
      organization: data.organization,
      riskScore: (isVpn ? 50 : 0) + (isProxy ? 40 : 0) + (isTor ? 60 : 0) + (isDatacenter ? 30 : 0) + (isBot ? 40 : 0),
      message: isVpn || isProxy || isTor ? 'VPN/Proxy detected' : undefined,
    };
  } catch (error) {
    logger.error('Error checking IP with ipgeolocation.io:', error);
    return null;
  }
}

/**
 * Check IP using ip-api.com (free, no API key needed, 45 requests/minute)
 */
async function checkWithIpApi(ip: string): Promise<IpCheckResult | null> {
  try {
    const response = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting`
    );
    const data = await response.json() as IpApiResponse;

    if (data.status === 'fail') {
      logger.warn(`IP API check failed for ${ip}: ${data.message}`);
      return null;
    }

    const isProxy = data.proxy === true;
    const isDatacenter = data.hosting === true;

    return {
      isVpn: isProxy || isDatacenter,
      isProxy,
      isTor: false,
      isDatacenter,
      country: data.country,
      countryCode: data.countryCode,
      city: data.city,
      region: data.regionName,
      zipCode: data.zip,
      latitude: data.lat,
      longitude: data.lon,
      timezone: data.timezone,
      isp: data.isp,
      organization: data.org,
      riskScore: (isProxy ? 50 : 0) + (isDatacenter ? 30 : 0),
      message: isProxy ? 'Proxy/VPN detected' : isDatacenter ? 'Datacenter IP detected' : undefined,
    };
  } catch (error) {
    logger.error('Error checking IP with ip-api.com:', error);
    return null;
  }
}

/**
 * Check IP reputation and get geolocation
 * Tries ipgeolocation.io first, falls back to ip-api.com
 */
export async function checkIpReputation(ip: string): Promise<IpCheckResult> {
  // Default result
  const defaultResult: IpCheckResult = {
    isVpn: false,
    isProxy: false,
    isTor: false,
    isDatacenter: false,
    riskScore: 0,
  };

  // Skip local/private IPs
  if (!ip || ip === 'unknown' || ip === '127.0.0.1' || ip === '::1' || 
      ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
    logger.log(`Skipping IP check for local/private IP: ${ip}`);
    return {
      ...defaultResult,
      message: 'Local/private IP - no geolocation available',
    };
  }

  // Try ipgeolocation.io first (more accurate)
  let result = await checkWithIpGeolocation(ip);
  
  // Fall back to ip-api.com
  if (!result) {
    result = await checkWithIpApi(ip);
  }

  if (result) {
    if (result.isVpn || result.isProxy || result.isTor) {
      logger.warn(`🔴 VPN/Proxy detected for IP: ${ip} (ISP: ${result.isp}, Country: ${result.country})`);
    } else {
      logger.log(`✅ IP check passed for: ${ip} (${result.city}, ${result.country})`);
    }
    return result;
  }

  return defaultResult;
}

/**
 * Get full geolocation data for an IP
 */
export async function getGeoLocation(ip: string): Promise<GeoLocation | null> {
  const result = await checkIpReputation(ip);
  
  if (!result.country) {
    return null;
  }

  return {
    ip,
    country: result.country || 'Unknown',
    countryCode: result.countryCode || 'XX',
    city: result.city || 'Unknown',
    region: result.region || 'Unknown',
    zipCode: result.zipCode || '',
    latitude: result.latitude || 0,
    longitude: result.longitude || 0,
    timezone: result.timezone || 'UTC',
    isp: result.isp || 'Unknown',
    organization: result.organization || 'Unknown',
    isVpn: result.isVpn,
    isProxy: result.isProxy,
    isTor: result.isTor,
    isDatacenter: result.isDatacenter,
  };
}

/**
 * Quick check if IP is suspicious (for rate limiting)
 */
export async function isIpSuspicious(ip: string): Promise<boolean> {
  const result = await checkIpReputation(ip);
  return result.isVpn || result.isProxy || result.isTor || result.riskScore > 50;
}

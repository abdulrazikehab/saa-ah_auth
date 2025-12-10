/**
 * User-Agent Parser Utility
 * Parses user-agent strings to extract OS, browser, and device info
 */

export interface DeviceInfo {
  os: string;
  browser: string;
  device: string;
}

/**
 * Parse User-Agent string to extract device information
 */
export function parseUserAgent(userAgent: string | undefined | null): DeviceInfo {
  if (!userAgent) {
    return { os: 'Unknown', browser: 'Unknown', device: 'Unknown' };
  }

  const ua = userAgent.toLowerCase();

  // Detect OS
  let os = 'Unknown';
  if (ua.includes('windows nt 10') || ua.includes('windows nt 11')) {
    os = 'Windows 10/11';
  } else if (ua.includes('windows nt 6.3')) {
    os = 'Windows 8.1';
  } else if (ua.includes('windows nt 6.2')) {
    os = 'Windows 8';
  } else if (ua.includes('windows nt 6.1')) {
    os = 'Windows 7';
  } else if (ua.includes('windows')) {
    os = 'Windows';
  } else if (ua.includes('mac os x')) {
    os = 'macOS';
  } else if (ua.includes('iphone')) {
    os = 'iOS';
  } else if (ua.includes('ipad')) {
    os = 'iPadOS';
  } else if (ua.includes('android')) {
    os = 'Android';
  } else if (ua.includes('linux')) {
    os = 'Linux';
  } else if (ua.includes('ubuntu')) {
    os = 'Ubuntu';
  } else if (ua.includes('chrome os') || ua.includes('cros')) {
    os = 'Chrome OS';
  }

  // Detect Browser
  let browser = 'Unknown';
  if (ua.includes('edg/') || ua.includes('edge/')) {
    browser = 'Edge';
  } else if (ua.includes('opr/') || ua.includes('opera')) {
    browser = 'Opera';
  } else if (ua.includes('chrome') && !ua.includes('chromium')) {
    browser = 'Chrome';
  } else if (ua.includes('safari') && !ua.includes('chrome')) {
    browser = 'Safari';
  } else if (ua.includes('firefox')) {
    browser = 'Firefox';
  } else if (ua.includes('msie') || ua.includes('trident')) {
    browser = 'Internet Explorer';
  } else if (ua.includes('brave')) {
    browser = 'Brave';
  } else if (ua.includes('vivaldi')) {
    browser = 'Vivaldi';
  }

  // Detect Device Type
  let device = 'Desktop';
  if (ua.includes('mobile') || ua.includes('android') && !ua.includes('tablet')) {
    device = 'Mobile';
  } else if (ua.includes('tablet') || ua.includes('ipad')) {
    device = 'Tablet';
  } else if (ua.includes('tv') || ua.includes('smarttv')) {
    device = 'Smart TV';
  } else if (ua.includes('bot') || ua.includes('crawler') || ua.includes('spider')) {
    device = 'Bot';
  }

  return { os, browser, device };
}

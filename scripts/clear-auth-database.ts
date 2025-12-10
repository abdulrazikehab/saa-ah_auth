import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function clearAuthDatabase() {
  console.log('🗑️  Starting app-auth database cleanup...');

  try {
    console.log('Deleting sessions...');
    await prisma.session.deleteMany({});
    
    console.log('Deleting refresh tokens...');
    await prisma.refreshToken.deleteMany({});
    
    console.log('Deleting password resets...');
    await prisma.passwordReset.deleteMany({});
    
    console.log('Deleting login attempts...');
    await prisma.loginAttempt.deleteMany({});
    
    console.log('Deleting rate limits...');
    await prisma.rateLimit.deleteMany({});
    
    console.log('Deleting security events...');
    await prisma.securityEvent.deleteMany({});
    
    console.log('Deleting audit logs...');
    await prisma.auditLog.deleteMany({});
    
    console.log('Deleting staff permissions...');
    await prisma.staffPermission.deleteMany({});
    
    console.log('Deleting merchant verifications...');
    await prisma.merchantVerification.deleteMany({});
    
    console.log('Deleting merchant limits...');
    await prisma.merchantLimits.deleteMany({});
    
    console.log('Deleting customers...');
    await prisma.customer.deleteMany({});
    
    console.log('Deleting users...');
    await prisma.user.deleteMany({});
    
    console.log('Deleting tenants...');
    await prisma.tenant.deleteMany({});
    
    console.log('✅ app-auth database cleared successfully!');
    console.log('📝 All users and tenants have been deleted!');
  } catch (error) {
    console.error('❌ Error clearing app-auth database:', error);
  } finally {
    await prisma.$disconnect();
  }
}

clearAuthDatabase();

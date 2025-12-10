import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function createDefaultTenant() {
  try {
    console.log('🔍 Checking for default tenant...');
    
    const existingTenant = await prisma.tenant.findUnique({
      where: { id: 'default' },
    });

    if (existingTenant) {
      console.log('✅ Default tenant already exists');
      return;
    }

    console.log('📝 Creating default tenant...');
    
    const tenant = await prisma.tenant.create({
      data: {
        id: 'default',
        name: 'Default Store',
        subdomain: 'default',
        plan: 'STARTER',
        status: 'ACTIVE',
        settings: JSON.stringify({
          storeName: 'Default Store',
          currency: 'SAR',
          language: 'ar',
        }),
      },
    });

    console.log('✅ Default tenant created successfully:', tenant.id);
  } catch (error) {
    console.error('❌ Error creating default tenant:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

createDefaultTenant();

import { Prisma } from '@prisma/client';
import { EncryptionUtil } from '../utils/encryption.util';
import { v4 as uuidv4 } from 'uuid';

export function EncryptionMiddleware(params: Prisma.MiddlewareParams, next: (params: Prisma.MiddlewareParams) => Promise<any>) {
  if (params.action === 'create' || params.action === 'createMany') {
    const data = params.args.data;
    
    const handleSingleData = (item: any) => {
        if (!item.id) {
            const rawId = uuidv4();
            item.id = EncryptionUtil.encryptDeterministic(rawId);
        } else {
            if (item.id.length < 50) {
                item.id = EncryptionUtil.encryptDeterministic(item.id);
            }
        }
    };

    if (Array.isArray(data)) {
        data.forEach(handleSingleData);
    } else if (data) {
        handleSingleData(data);
    }
  }

  return next(params);
}

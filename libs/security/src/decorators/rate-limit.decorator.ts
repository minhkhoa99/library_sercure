import { SetMetadata } from '@nestjs/common';

import { RATE_LIMIT_METADATA } from '../constants/security.constants';
import type { SecurityPolicy } from '../types/security-policy.types';

export const RateLimit = (policy: SecurityPolicy) => SetMetadata(RATE_LIMIT_METADATA, policy);

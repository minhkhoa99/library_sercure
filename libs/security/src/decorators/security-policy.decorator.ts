import { SetMetadata } from '@nestjs/common';

import { SECURITY_POLICY_METADATA } from '../constants/security.constants';

export const SecurityPolicy = (policyName: string) =>
  SetMetadata(SECURITY_POLICY_METADATA, policyName);

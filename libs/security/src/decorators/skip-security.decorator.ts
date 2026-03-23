import { SetMetadata } from '@nestjs/common';

import { SKIP_SECURITY_METADATA } from '../constants/security.constants';

export const SkipSecurity = () => SetMetadata(SKIP_SECURITY_METADATA, true);

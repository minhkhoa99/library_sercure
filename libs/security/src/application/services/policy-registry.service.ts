import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import type { SecurityPolicy } from '../../types/security-policy.types';

export class PolicyRegistryService {
  constructor(private readonly options: SecurityModuleOptions) {}

  get(name: string): SecurityPolicy | undefined {
    return this.options.policies[name];
  }

  list(): SecurityPolicy[] {
    return Object.values(this.options.policies);
  }
}

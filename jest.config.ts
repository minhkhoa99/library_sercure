import type { Config } from 'jest';

const config: Config = {
  projects: [
    {
      displayName: 'unit',
      rootDir: '.',
      moduleFileExtensions: ['js', 'json', 'ts'],
      testRegex: '.*\\.spec\\.ts$',
      transform: {
        '^.+\\.(t|j)s$': ['ts-jest', { tsconfig: 'tsconfig.json' }],
      },
      collectCoverageFrom: ['libs/security/src/**/*.ts'],
      coverageDirectory: 'coverage',
      testEnvironment: 'node',
      moduleNameMapper: {
        '^@lib-sercure/security$': '<rootDir>/libs/security/src',
        '^@lib-sercure/security/(.*)$': '<rootDir>/libs/security/src/$1',
      },
    },
  ],
};

export default config;

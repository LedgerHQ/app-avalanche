const os = require('os')

// Jest runs test files on (cores - 1) workers, so a 2-core CI runner ran the
// 13 files one after another and the suite took close to an hour. The tests
// mostly wait on the emulator rather than use the CPU, so keep at least 3
// workers; machines with more cores keep jest's default.
const maxWorkers = Math.max(3, os.availableParallelism() - 1)

module.exports = {
  maxWorkers,
  preset: 'ts-jest',
  testEnvironment: 'node',
  transformIgnorePatterns: ['node_modules/(?!(\\.pnpm/)?(@ethereumjs|@noble|get-port)[+/@])'],
  transform: {
    '^.+\\.[jt]sx?$': 'ts-jest',
  },
  globalSetup: './jest/globalsetup.ts',
  globalTeardown: './jest/globalteardown.ts',
  setupFilesAfterEnv: ['./jest/setup.ts'],
  reporters: ['default', ['summary', { summaryThreshold: 1 }]],
}

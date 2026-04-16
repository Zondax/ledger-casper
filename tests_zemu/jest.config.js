module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    // ts-jest is inherited from the preset for .ts/.tsx; wire babel-jest
    // for .js/.mjs so @babel/preset-env (.babelrc) can rewrite ESM-only
    // node_modules (e.g. get-port) to CJS before Jest loads them.
    '^.+\\.[jt]sx?$': 'ts-jest',
    '^.+\\.m?js$': 'babel-jest',
  },
  transformIgnorePatterns: [
    // Most node_modules skip transform for speed; ESM-only packages that
    // CJS consumers (e.g. @zondax/zemu) require must be allowed through
    // so babel can compile them to CJS.
    'node_modules/(?!(get-port)/)',
  ],
}

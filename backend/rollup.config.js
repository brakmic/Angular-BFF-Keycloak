import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import { addJsExtension } from './rollup-plugins/add-js-extension.js';
import { isExternal } from './rollup-plugins/is-external.js';
import dts from 'rollup-plugin-dts';

export default [
  // ESM build
  {
    input: 'dist/esm/index.js',
    output: {
      dir: 'lib/esm',
      format: 'esm',
      preserveModules: false,
      entryFileNames: '[name].js',
      hoistTransitiveImports: false
    },
    external: isExternal,
    plugins: [
      resolve({ 
        extensions: ['.js'],
        rootDir: 'dist/esm'
      }),
      commonjs(),
      addJsExtension()
    ]
  },
  // CJS build
  {
    input: 'dist/cjs/index.js',
    output: {
      dir: 'lib/cjs',
      format: 'cjs',
      preserveModules: false,
      exports: 'auto',
      entryFileNames: '[name].js',
      hoistTransitiveImports: false
    },
    external: isExternal,
    plugins: [
      resolve({ 
        extensions: ['.js'],
        rootDir: 'dist/cjs',
        preferBuiltins: true
      }),
      commonjs()
    ]
  },
  // Type Declarations build
  {
    input: 'lib/types/index.d.ts',
    output: {
      file: 'lib/esm/index.d.ts',
      format: 'esm'
    },
    external: [
      'fs', 'path', 'https', 'http', 'url',
      'crypto', 'stream', 'zlib', 'os',
      'querystring', 'events', 'buffer'
    ],
    plugins: [
      dts()
    ]
  }
];
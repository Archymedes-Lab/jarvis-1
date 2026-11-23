import { describe, expect, test } from 'bun:test';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
const require = createRequire(import.meta.url);
const merge = require('deepmerge');

function attack(fn: typeof merge) {
  const target = JSON.parse('{"__proto__":{"synthetic_polluted":true}}');
  return fn(target, {});
}

describe('installed deepmerge local security patch', () => {
  test('target-copy poisoning is rejected by behavior', () => {
    const result = attack(merge);
    expect(result.synthetic_polluted).toBeUndefined();
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
    expect(({} as any).synthetic_polluted).toBeUndefined();
  });
  test('null-prototype sources and nested merges cannot change result prototypes', () => {
    const source = Object.assign(Object.create(null), JSON.parse('{"__proto__":{"synthetic_polluted":true}}'));
    for (const result of [merge(Object.create(null), source), merge({nested:{}}, {nested:source}).nested,
                          merge.all([source, {}])]) {
      expect(result.synthetic_polluted).toBeUndefined();
      expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
    }
  });
  test('normal Svelte config semantics, symbols and array override still work', () => {
    const symbol = Symbol('metadata');
    const a = { compilerOptions:{dev:true}, files:['a'], [symbol]:{one:1} };
    const b = { compilerOptions:{css:'external'}, files:['b'], [symbol]:{two:2} };
    const result = merge(a,b,{arrayMerge:(_:unknown[],source:unknown[])=>source});
    expect(result.compilerOptions).toEqual({dev:true,css:'external'});
    expect(result.files).toEqual(['b']);
    expect(result[symbol]).toEqual({one:1,two:2});
    expect(a.files).toEqual(['a']);
  });
  test('negative control catches the original assignment vulnerability', () => {
    let source = readFileSync(require.resolve('deepmerge'), 'utf8');
    source = source.replace(/Object\.defineProperty\(destination, key, \{[\s\S]*?\}\)/,
                            'destination[key] = value');
    const module = {exports:{}};
    runInNewContext(source, {module, exports:module.exports, require});
    expect(attack(module.exports).synthetic_polluted).toBe(true);
  });
});

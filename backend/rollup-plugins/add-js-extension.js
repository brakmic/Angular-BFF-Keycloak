export function addJsExtension() {
  return {
    name: 'add-js-extension',
    renderChunk(code) {
      const pattern = /((?:from|import)\s+['"])(\.{1,2}\/[^'"]+?)(['"])/g;
      const fixed = code.replace(pattern, (match, p1, p2, p3) => {
        if (/\.[a-zA-Z0-9]+$/.test(p2)) return match;
        return `${p1}${p2}.js${p3}`;
      });
      return { code: fixed, map: null };
    }
  };
}

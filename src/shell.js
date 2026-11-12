// Split a shell command into words, the way sh would before running it:
// quotes come off, backslash escapes resolve, and ; | & ( ) become separate
// operator entries ({ op }). No expansion: `$VAR` stays the literal `$VAR`,
// which is how a reference is told apart from a pasted value.

const OPERATORS = new Set([';', '|', '&', '(', ')']);

export function tokenize(command) {
  const s = String(command);
  const out = [];
  let word = '';
  let inWord = false;
  const end = () => {
    if (inWord) out.push(word);
    word = '';
    inWord = false;
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "'") {
      const close = s.indexOf("'", i + 1);
      const stop = close < 0 ? s.length : close;
      word += s.slice(i + 1, stop);
      inWord = true;
      i = stop + 1;
    } else if (c === '"') {
      inWord = true;
      i += 1;
      while (i < s.length && s[i] !== '"') {
        if (s[i] === '\\' && i + 1 < s.length && '"\\$`\n'.includes(s[i + 1])) {
          word += s[i + 1];
          i += 2;
        } else {
          word += s[i];
          i += 1;
        }
      }
      i += 1;
    } else if (c === '\\' && i + 1 < s.length) {
      word += s[i + 1];
      inWord = true;
      i += 2;
    } else if (/\s/.test(c)) {
      end();
      i += 1;
    } else if (OPERATORS.has(c)) {
      end();
      let op = c;
      if ((c === '&' || c === '|') && s[i + 1] === c) {
        op += c;
        i += 1;
      }
      out.push({ op });
      i += 1;
    } else {
      word += c;
      inWord = true;
      i += 1;
    }
  }
  end();
  return out;
}

/** Words grouped into simple commands, split at operators. */
export function commands(tokens) {
  const groups = [[]];
  for (const t of tokens) {
    if (typeof t === 'string') groups[groups.length - 1].push(t);
    else if (groups[groups.length - 1].length) groups.push([]);
  }
  return groups.filter((g) => g.length);
}

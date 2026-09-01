import { CountermeasureType } from '../types';

export interface Token {
  text: string;
  type: 'keyword' | 'ip' | 'port' | 'action' | 'comment' | 'string' | 'key' | 'value' | 'flag' | 'default';
}

export function tokenizeCode(content: string, type: CountermeasureType): Token[][] {
  const lines = content.split('\n');

  return lines.map((line) => {
    if (line.trim().startsWith('#') || line.trim().startsWith('//') || line.trim().startsWith('!')) {
      return [{ text: line, type: 'comment' }];
    }

    if (type === 'stix_bundle' || (content.trim().startsWith('{') && content.trim().endsWith('}'))) {
      return tokenizeJsonLine(line);
    }

    const tokens: Token[] = [];
    // Split on whitespace or specific delimiters while keeping tokens
    const parts = line.split(/(\s+|[=,;:])/);

    for (const part of parts) {
      if (!part) continue;

      if (/^\s+$/.test(part)) {
        tokens.push({ text: part, type: 'default' });
      } else if (part.startsWith('-') || part.startsWith('--')) {
        tokens.push({ text: part, type: 'flag' });
      } else if (
        ['DROP', 'REJECT', 'ACCEPT', 'DENY', 'BLOCK', 'alert', 'pass', 'deny', 'permit'].includes(part.toUpperCase())
      ) {
        tokens.push({ text: part, type: 'action' });
      } else if (
        [
          'iptables',
          'nft',
          'add',
          'rule',
          'table',
          'chain',
          'ip',
          'ip6',
          'tcp',
          'udp',
          'icmp',
          'access-list',
          'extended',
          'in',
          'out',
          'CNAME',
          'A',
          'SOA',
          'TTL',
          'sid',
          'rev',
          'msg',
          'classtype',
        ].includes(part)
      ) {
        tokens.push({ text: part, type: 'keyword' });
      } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/.test(part)) {
        tokens.push({ text: part, type: 'ip' });
      } else if (/^\d{2,5}$/.test(part) && ['80', '443', '8080', '53', '22', '445', '3389', '8888'].includes(part)) {
        tokens.push({ text: part, type: 'port' });
      } else if (part.startsWith('"') || part.endsWith('"')) {
        tokens.push({ text: part, type: 'string' });
      } else {
        tokens.push({ text: part, type: 'default' });
      }
    }

    return tokens;
  });
}

function tokenizeJsonLine(line: string): Token[] {
  const tokens: Token[] = [];
  const parts = line.split(/(".*?"|[:,{}[\]]|\s+)/g);

  for (const part of parts) {
    if (!part) continue;

    if (/^\s+$/.test(part)) {
      tokens.push({ text: part, type: 'default' });
    } else if (part.startsWith('"') && part.endsWith('"')) {
      if (line.indexOf(part) < line.indexOf(':') && line.includes(':')) {
        tokens.push({ text: part, type: 'key' });
      } else {
        tokens.push({ text: part, type: 'string' });
      }
    } else if (['{', '}', '[', ']', ':', ','].includes(part)) {
      tokens.push({ text: part, type: 'keyword' });
    } else if (['true', 'false', 'null'].includes(part) || /^\d+(\.\d+)?$/.test(part)) {
      tokens.push({ text: part, type: 'value' });
    } else {
      tokens.push({ text: part, type: 'default' });
    }
  }

  return tokens;
}

export function getTokenColor(type: Token['type']): string {
  switch (type) {
    case 'keyword':
      return 'text-cyan-400 font-semibold';
    case 'action':
      return 'text-red-400 font-bold';
    case 'ip':
      return 'text-amber-300 font-mono';
    case 'port':
      return 'text-purple-400 font-mono';
    case 'comment':
      return 'text-slate-500 italic';
    case 'string':
      return 'text-emerald-300';
    case 'flag':
      return 'text-blue-400';
    case 'key':
      return 'text-cyan-300';
    case 'value':
      return 'text-amber-400';
    case 'default':
    default:
      return 'text-slate-200';
  }
}

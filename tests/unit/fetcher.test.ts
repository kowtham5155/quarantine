import { describe, expect, it } from 'vitest';

import { isBlockedAddress, resolvePublicHost, safeFetch } from '@/lib/net/fetcher';

/**
 * Zero live network. Everything here either tests the pure address classifier
 * or points the fetcher at a literal address, which it must refuse before any
 * socket is opened.
 */

describe('isBlockedAddress — IPv4', () => {
  const blocked = [
    '0.0.0.0',
    '0.0.0.1',
    '10.0.0.1',
    '10.255.255.254',
    '100.64.0.1', // carrier-grade NAT
    '127.0.0.1',
    '127.1.2.3',
    '169.254.169.254', // AWS/GCP/Azure metadata
    '169.254.0.1',
    '172.16.0.1',
    '172.31.255.254',
    '192.0.0.1',
    '192.0.2.5',
    '192.168.0.1',
    '192.168.255.254',
    '198.18.0.1',
    '198.51.100.5',
    '203.0.113.5',
    '224.0.0.1', // multicast
    '239.255.255.255',
    '240.0.0.1',
    '255.255.255.255',
  ];

  for (const address of blocked) {
    it(`blocks ${address}`, () => {
      expect(isBlockedAddress(address)).toBe(true);
    });
  }

  const allowed = [
    '1.1.1.1',
    '8.8.8.8',
    '104.16.0.1',
    '151.101.1.1', // fastly, where the npm registry lives
    '172.15.255.255', // just below the RFC1918 block
    '172.32.0.1', // just above it
    '100.63.255.255', // just below CGNAT
    '100.128.0.1', // just above it
    '223.255.255.255', // just below multicast
  ];

  for (const address of allowed) {
    it(`allows ${address}`, () => {
      expect(isBlockedAddress(address)).toBe(false);
    });
  }
});

describe('isBlockedAddress — IPv6', () => {
  const blocked = [
    '::1', // loopback
    '::', // unspecified
    '::ffff:127.0.0.1', // IPv4-mapped loopback
    '::ffff:169.254.169.254', // IPv4-mapped metadata
    '::ffff:10.0.0.1',
    '::127.0.0.1', // IPv4-compatible loopback
    'fe80::1', // link-local
    'FE80::1', // case must not matter
    'fc00::1', // unique local
    'fd12:3456::1',
    'ff02::1', // multicast
    '64:ff9b::7f00:1', // NAT64 wrapping loopback
    '2002:7f00:0001::1', // 6to4 wrapping loopback
  ];

  for (const address of blocked) {
    it(`blocks ${address}`, () => {
      expect(isBlockedAddress(address)).toBe(true);
    });
  }

  it('allows a public v6 address', () => {
    expect(isBlockedAddress('2606:4700:4700::1111')).toBe(false);
    expect(isBlockedAddress('2001:4860:4860::8888')).toBe(false);
  });

  /**
   * A transition address is judged by the IPv4 it carries, not by its prefix.
   * On a NAT64-only network a DNS64 resolver synthesises `64:ff9b::` records
   * for every name, GitHub's included — blanket-blocking the prefix takes the
   * provenance check offline on a network that is behaving normally.
   */
  it('allows an embedded IPv4 address that is itself public', () => {
    expect(isBlockedAddress('64:ff9b::14cf:4955')).toBe(false); // 20.207.73.85, api.github.com
    expect(isBlockedAddress('64:ff9b::b9c7:6c85')).toBe(false); // 185.199.108.133
    expect(isBlockedAddress('2002:8bc7:6c85::1')).toBe(false); // 6to4 over 139.199.108.133
    expect(isBlockedAddress('::ffff:8.8.8.8')).toBe(false);
  });

  it('still refuses an embedded IPv4 address that is private', () => {
    expect(isBlockedAddress('64:ff9b::a9fe:a9fe')).toBe(true); // 169.254.169.254, metadata
    expect(isBlockedAddress('64:ff9b::c0a8:1')).toBe(true); // 192.168.0.1
    expect(isBlockedAddress('64:ff9b::a00:1')).toBe(true); // 10.0.0.1
    expect(isBlockedAddress('2002:ac10:1::1')).toBe(true); // 6to4 over 172.16.0.1
    expect(isBlockedAddress('::ffff:169.254.169.254')).toBe(true);
  });
});

describe('isBlockedAddress — non-addresses', () => {
  it('refuses anything that is not an IP literal', () => {
    for (const value of ['', 'localhost', 'example.com', '127.0.0.1.evil.com', '0x7f000001']) {
      expect(isBlockedAddress(value)).toBe(true);
    }
  });

  it('refuses decimal and octal encodings of loopback', () => {
    // These are not valid IP literals, so isIP rejects them and the classifier
    // refuses. The important property is that they are never treated as public.
    for (const value of ['2130706433', '0177.0.0.1', '127.1']) {
      expect(isBlockedAddress(value)).toBe(true);
    }
  });
});

describe('resolvePublicHost with a literal address', () => {
  it('refuses loopback without touching DNS', async () => {
    await expect(resolvePublicHost('127.0.0.1')).rejects.toThrow(/private address/i);
  });

  it('refuses the cloud metadata address', async () => {
    await expect(resolvePublicHost('169.254.169.254')).rejects.toThrow(/private address/i);
  });

  it('accepts a public literal', async () => {
    await expect(resolvePublicHost('1.1.1.1')).resolves.toMatchObject({
      hostname: '1.1.1.1',
      addresses: [{ address: '1.1.1.1', family: 4 }],
    });
  });
});

describe('safeFetch URL validation', () => {
  it('refuses a non-http scheme', async () => {
    for (const url of ['file:///etc/passwd', 'ftp://example.com/x', 'gopher://example.com']) {
      await expect(safeFetch(url)).rejects.toThrow(/http and https/i);
    }
  });

  it('refuses a URL with embedded credentials', async () => {
    await expect(safeFetch('https://user:pass@example.com/')).rejects.toThrow(/credentials/i);
  });

  it('refuses a malformed URL', async () => {
    await expect(safeFetch('not a url')).rejects.toThrow(/not valid/i);
  });

  it('refuses a private host before opening a socket', async () => {
    await expect(safeFetch('http://127.0.0.1:1/')).rejects.toThrow(/private address/i);
    await expect(safeFetch('http://169.254.169.254/latest/meta-data/')).rejects.toThrow(
      /private address/i,
    );
    await expect(safeFetch('http://[::1]:1/')).rejects.toThrow(/private address/i);
  });
});

/** @vitest-environment node */
import { describe, it, expect } from 'vitest'
import {
  parseAsn1,
  parseAsn1All,
  decodeOid,
  decodeString,
  decodeInteger,
  findChild,
  findContext,
} from '../src/asn1-parser.js'

describe('asn1-parser', () => {
  describe('parseAsn1 — basic structures', () => {
    it('parses a simple INTEGER', () => {
      // DER: 02 01 05 → INTEGER, length 1, value 5
      const data = new Uint8Array([0x02, 0x01, 0x05])
      const node = parseAsn1(data)
      expect(node.tag).toBe(0x02)
      expect(node.constructed).toBe(false)
      expect(node.contentLength).toBe(1)
      expect(node.content[0]).toBe(5)
    })

    it('parses a SEQUENCE with children', () => {
      // SEQUENCE { INTEGER(3), INTEGER(7) }
      // 30 06 02 01 03 02 01 07
      const data = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x07])
      const node = parseAsn1(data)
      expect(node.tag).toBe(0x30)
      expect(node.constructed).toBe(true)
      expect(node.children).toHaveLength(2)
      expect(node.children[0].content[0]).toBe(3)
      expect(node.children[1].content[0]).toBe(7)
    })

    it('handles multi-byte length encoding', () => {
      // INTEGER with 128 bytes of content: 02 81 80 <128 zeros>
      const content = new Uint8Array(128).fill(0xaa)
      const data = new Uint8Array([0x02, 0x81, 0x80, ...content])
      const node = parseAsn1(data)
      expect(node.tag).toBe(0x02)
      expect(node.contentLength).toBe(128)
    })

    it('identifies context-specific tags', () => {
      // [0] EXPLICIT with a child: A0 03 02 01 02
      const data = new Uint8Array([0xa0, 0x03, 0x02, 0x01, 0x02])
      const node = parseAsn1(data)
      expect(node.tagClass).toBe(2) // context-specific
      expect(node.tagNumber).toBe(0)
      expect(node.constructed).toBe(true)
      expect(node.children[0].content[0]).toBe(2)
    })
  })

  describe('decodeOid', () => {
    it('decodes RSA OID (1.2.840.113549.1.7.2)', () => {
      // OID for signedData: 06 09 2A 86 48 86 F7 0D 01 07 02
      const oidBytes = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02])
      expect(decodeOid(oidBytes)).toBe('1.2.840.113549.1.7.2')
    })

    it('decodes CN OID (2.5.4.3)', () => {
      // 06 03 55 04 03
      const oidBytes = new Uint8Array([0x55, 0x04, 0x03])
      expect(decodeOid(oidBytes)).toBe('2.5.4.3')
    })

    it('decodes CR root OID (2.16.188.1.1.1)', () => {
      // 2.16.188 → first byte: 2*40 + 16 = 96 (0x60), then 188 = 0x81 0x3c
      const oidBytes = new Uint8Array([0x60, 0x81, 0x3c, 0x01, 0x01, 0x01])
      expect(decodeOid(oidBytes)).toBe('2.16.188.1.1.1')
    })
  })

  describe('decodeString', () => {
    it('decodes UTF8String', () => {
      const content = new TextEncoder().encode('GUILLERMO CHAVARRIA')
      const node = {
        tag: 0x0c,
        constructed: false,
        tagClass: 0,
        tagNumber: 0x0c,
        nodeStart: 0,
        contentOffset: 0,
        contentLength: content.length,
        content,
        children: [],
      }
      expect(decodeString(node)).toBe('GUILLERMO CHAVARRIA')
    })

    it('decodes PrintableString', () => {
      const content = new TextEncoder().encode('CR')
      const node = {
        tag: 0x13,
        constructed: false,
        tagClass: 0,
        tagNumber: 0x13,
        nodeStart: 0,
        contentOffset: 0,
        contentLength: content.length,
        content,
        children: [],
      }
      expect(decodeString(node)).toBe('CR')
    })
  })

  describe('decodeInteger', () => {
    it('decodes small integer to hex', () => {
      const content = new Uint8Array([0x01, 0x02, 0x03])
      const node = {
        tag: 0x02,
        constructed: false,
        tagClass: 0,
        tagNumber: 2,
        nodeStart: 0,
        contentOffset: 0,
        contentLength: 3,
        content,
        children: [],
      }
      expect(decodeInteger(node)).toBe('010203')
    })
  })

  describe('findChild / findContext', () => {
    it('findChild locates by tag', () => {
      const parent = parseAsn1(new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x03, 0x06, 0x01, 0x01]))
      const oid = findChild(parent, 0x06)
      expect(oid).toBeDefined()
      expect(oid!.tag).toBe(0x06)
    })

    it('findContext locates context-specific tag', () => {
      // SEQUENCE { [0] { INTEGER(5) }, INTEGER(3) }
      const data = new Uint8Array([0x30, 0x08, 0xa0, 0x03, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03])
      const parent = parseAsn1(data)
      const ctx = findContext(parent, 0)
      expect(ctx).toBeDefined()
      expect(ctx!.tagNumber).toBe(0)
    })
  })

  // SOC-199. `parseAsn1All` is documented "parse all top-level nodes from a
  // byte range (for parsing certificate sets)" and returns an array, but it
  // `break`ed unconditionally on the first iteration, so it returned at most
  // one node for any input. It shipped in 0.1.0 with no coverage at all.
  //
  // Every case below that expects more than one node fails against the
  // pre-fix implementation. A single-element fixture does not: it passes
  // either way, which is how a function that parses one of N was mistaken
  // for one that parses N.
  describe('parseAsn1All — SOC-199', () => {
    it('parses THREE concatenated INTEGERs, not just the first', () => {
      // 02 01 05 | 02 01 06 | 02 01 07
      const data = new Uint8Array([0x02, 0x01, 0x05, 0x02, 0x01, 0x06, 0x02, 0x01, 0x07])
      const nodes = parseAsn1All(data)
      expect(nodes).toHaveLength(3)
      expect(nodes.map((n) => n.content[0])).toEqual([5, 6, 7])
    })

    it('parses a certificate-SET shape: two concatenated SEQUENCEs', () => {
      // 30 03 02 01 01 | 30 03 02 01 02
      const data = new Uint8Array([
        0x30, 0x03, 0x02, 0x01, 0x01,
        0x30, 0x03, 0x02, 0x01, 0x02,
      ])
      const nodes = parseAsn1All(data)
      expect(nodes).toHaveLength(2)
      expect(nodes.every((n) => n.tag === 0x30)).toBe(true)
      expect(nodes.map((n) => n.children[0].content[0])).toEqual([1, 2])
    })

    it('reports the correct nodeStart for every element after the first', () => {
      const data = new Uint8Array([0x02, 0x01, 0x05, 0x02, 0x01, 0x06, 0x02, 0x01, 0x07])
      expect(parseAsn1All(data).map((n) => n.nodeStart)).toEqual([0, 3, 6])
    })

    it('advances correctly past a long-form length header', () => {
      // 04 81 80 <128 bytes> | 02 01 09
      const long = new Uint8Array([0x04, 0x81, 0x80, ...new Array(128).fill(0xaa), 0x02, 0x01, 0x09])
      const nodes = parseAsn1All(long)
      expect(nodes).toHaveLength(2)
      expect(nodes[0].contentLength).toBe(128)
      expect(nodes[1].content[0]).toBe(9)
    })

    it('returns a single node for a single element (control — passes either way)', () => {
      expect(parseAsn1All(new Uint8Array([0x02, 0x01, 0x05]))).toHaveLength(1)
    })

    it('returns an empty array for empty input', () => {
      expect(parseAsn1All(new Uint8Array([]))).toEqual([])
    })

    it('terminates on a zero-length element rather than looping forever', () => {
      // 05 00 (NULL) twice: a zero-content element must still advance by its header
      const nodes = parseAsn1All(new Uint8Array([0x05, 0x00, 0x05, 0x00]))
      expect(nodes).toHaveLength(2)
    })
  })
})

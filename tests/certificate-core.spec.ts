import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import {
  parseCertificate,
  hexToBytes,
  bytesToHex,
  cleanSignerName,
  extractPkcs7Hex,
  buildChain,
} from '../src/certificate-core.js'
import type { CertificateInfo } from '../src/types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

/**
 * Fixture: `tests/fixtures/leaf.der` is a real DER-encoded X.509 certificate,
 * derived from the CR trust store PEM
 * `attestto-trust/countries/cr/current/CA SINPE - PERSONA FISICA v2.pem`
 * (`openssl x509 -outform DER`). It is a CA certificate, so `isCa` is true —
 * that is fine for exercising generic field extraction.
 */
function loadLeafDer(): Uint8Array {
  return new Uint8Array(readFileSync(join(__dirname, 'fixtures', 'leaf.der')))
}

describe('parseCertificate(der)', () => {
  const der = loadLeafDer()
  const info = parseCertificate(der)

  it('extracts a non-empty commonName', () => {
    expect(info.commonName).toBeTruthy()
    expect(info.commonName).not.toBe('Unknown')
  })

  it('extracts a non-empty issuerCommonName', () => {
    expect(info.issuerCommonName).toBeTruthy()
    expect(info.issuerCommonName).not.toBe('Unknown')
  })

  it('extracts validFrom and validTo', () => {
    expect(info.validFrom).not.toBeNull()
    expect(info.validTo).not.toBeNull()
    // ISO-ish date strings
    expect(info.validFrom).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(info.validTo).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  it('returns arrays for subjectAltNames, policyOids and keyUsage', () => {
    expect(Array.isArray(info.subjectAltNames)).toBe(true)
    expect(Array.isArray(info.policyOids)).toBe(true)
    expect(Array.isArray(info.keyUsage)).toBe(true)
    expect(Array.isArray(info.extKeyUsage)).toBe(true)
  })

  it('captures a non-empty rawDerHex round-tripping the input', () => {
    expect(info.rawDerHex).toBeTruthy()
    expect(info.rawDerHex).toBe(bytesToHex(der))
  })

  it('extracts a non-empty serialNumber', () => {
    expect(info.serialNumber).toBeTruthy()
  })

  it('defaults role to end-entity', () => {
    expect(info.role).toBe('end-entity')
  })

  it('populates generic fields from this CA cert (policyOids + keyUsage + isCa)', () => {
    expect(info.policyOids.length).toBeGreaterThan(0)
    expect(info.keyUsage.length).toBeGreaterThan(0)
    expect(info.isCa).toBe(true)
  })

  it('throws on non-certificate DER input', () => {
    // A simple SEQUENCE { INTEGER(1) } — not a Certificate
    expect(() => parseCertificate(hexToBytes('3003020101'))).toThrow()
  })
})

describe('hexToBytes / bytesToHex', () => {
  it('converts hex string to Uint8Array', () => {
    expect(hexToBytes('deadbeef')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  it('handles uppercase hex', () => {
    expect(hexToBytes('DEADBEEF')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  it('handles empty string', () => {
    expect(hexToBytes('')).toEqual(new Uint8Array([]))
  })

  it('round-trips through bytesToHex (lowercase)', () => {
    expect(bytesToHex(hexToBytes('DEADBEEF'))).toBe('deadbeef')
  })
})

describe('extractPkcs7Hex', () => {
  it('extracts hex blob from /Contents field', () => {
    const pdfText = '<< /Type /Sig /Contents <AABBCCDD> /SubFilter /adbe.pkcs7.detached >>'
    expect(extractPkcs7Hex(pdfText, 0, pdfText.length)).toBe('AABBCCDD')
  })

  it('strips whitespace from hex blob', () => {
    const pdfText = '<< /Contents <AA BB CC DD EE FF> >>'
    expect(extractPkcs7Hex(pdfText, 0, pdfText.length)).toBe('AABBCCDDEEFF')
  })

  it('returns null when no /Contents found', () => {
    const pdfText = '<< /Type /Sig /SubFilter /adbe.pkcs7.detached >>'
    expect(extractPkcs7Hex(pdfText, 0, pdfText.length)).toBeNull()
  })
})

describe('cleanSignerName', () => {
  it('strips backslash escapes from PDF encoding', () => {
    expect(cleanSignerName('GUILLERMO CHAVARRIA CRUZ \\(FIRMA\\)')).toBe(
      'GUILLERMO CHAVARRIA CRUZ (FIRMA)',
    )
  })

  it('handles names without escapes', () => {
    expect(cleanSignerName('John Doe')).toBe('John Doe')
  })

  it('handles multiple escaped characters', () => {
    expect(cleanSignerName('Test \\(A\\) \\(B\\)')).toBe('Test (A) (B)')
  })
})

describe('buildChain', () => {
  function cert(partial: Partial<CertificateInfo>): CertificateInfo {
    return {
      commonName: '',
      organization: null,
      organizationalUnit: null,
      country: null,
      serialNumber: '',
      issuerCommonName: '',
      issuerOrganization: null,
      validFrom: null,
      validTo: null,
      isCa: false,
      policyOids: [],
      email: null,
      subjectAltNames: [],
      keyUsage: [],
      extKeyUsage: [],
      role: 'end-entity',
      rawDerHex: '',
      ...partial,
    }
  }

  it('returns empty for empty input', () => {
    expect(buildChain([])).toEqual([])
  })

  it('assigns roles and links signer → intermediate → root', () => {
    const root = cert({ commonName: 'Root CA', issuerCommonName: 'Root CA', isCa: true })
    const intermediate = cert({
      commonName: 'Intermediate CA',
      issuerCommonName: 'Root CA',
      isCa: true,
    })
    const signer = cert({ commonName: 'Signer', issuerCommonName: 'Intermediate CA', isCa: false })

    const chain = buildChain([root, intermediate, signer])

    expect(root.role).toBe('root')
    expect(intermediate.role).toBe('intermediate')
    expect(signer.role).toBe('end-entity')
    expect(chain.map((c) => c.commonName)).toEqual(['Signer', 'Intermediate CA', 'Root CA'])
  })

  it('uses signerIdentifier to disambiguate multiple end-entity certs', () => {
    const real = cert({
      commonName: 'Real Signer',
      issuerCommonName: 'CA',
      serialNumber: 'aa',
      isCa: false,
    })
    const ancillary = cert({
      commonName: 'Service Cert',
      issuerCommonName: 'CA',
      serialNumber: 'bb',
      isCa: false,
    })

    buildChain([real, ancillary], { issuerCN: 'CA', serial: 'aa' })

    expect(real.role).toBe('end-entity')
    expect(ancillary.role).toBe('intermediate')
  })
})

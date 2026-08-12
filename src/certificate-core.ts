/**
 * Generic X.509 certificate parsing — PKCS#7 SignedData extraction and
 * single-leaf certificate field extraction.
 *
 * No external dependencies — uses the minimal ASN.1 parser in `./asn1-parser.js`.
 * This layer is jurisdiction-agnostic: it extracts only generic X.509 fields.
 * National-PKI / did:pki enrichment lives in higher-level consumers.
 *
 * Structure parsing only — no cryptographic verification is performed here.
 */

import {
  parseAsn1,
  decodeOid,
  decodeString,
  decodeTime,
  decodeInteger,
  findContext,
  ASN1_TAG,
  type Asn1Node,
} from './asn1-parser.js'
import type { CertificateInfo, SignerIdentifier } from './types.js'

// ── Known OIDs ────────────────────────────────────────────────────

const RDN_OIDS: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'title',
  '1.2.840.113549.1.9.1': 'email',
}

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2'

// ── Key Usage / Extended Key Usage ───────────────────────────────

/** Key Usage bit flags (2.5.29.15) — bit position → label */
const KEY_USAGE_BITS: string[] = [
  'Digital Signature',
  'Non-Repudiation',
  'Key Encipherment',
  'Data Encipherment',
  'Key Agreement',
  'Certificate Signing',
  'CRL Signing',
  'Encipher Only',
  'Decipher Only',
]

/** Extended Key Usage OIDs (2.5.29.37) → human label */
const EKU_OIDS: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'Server Authentication',
  '1.3.6.1.5.5.7.3.2': 'Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'Email Protection',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
  '1.3.6.1.4.1.311.10.3.12': 'Document Signing',
  '2.16.840.1.101.2.1.11.10': 'Smart Card Login',
}

// ── Hex Blob Extraction ───────────────────────────────────────────

/**
 * Extract the hex-encoded PKCS#7 blob from a PDF /Contents field.
 * Returns null if not found.
 */
export function extractPkcs7Hex(
  pdfText: string,
  sigDictStart: number,
  sigDictEnd: number,
): string | null {
  const dict = pdfText.substring(sigDictStart, sigDictEnd)
  const match = dict.match(/\/Contents\s*<([0-9a-fA-F\s]+)>/)
  if (!match) return null
  return match[1].replace(/\s/g, '')
}

/**
 * Convert hex string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

/**
 * Convert Uint8Array to hex string (lowercase, no separators).
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

// ── PKCS#7 / CMS Parsing ─────────────────────────────────────────

/**
 * Parse a PKCS#7 SignedData structure and extract all embedded certificates.
 * Also extracts the SignerInfo issuer+serial to correctly identify the signer cert
 * when multiple non-CA certificates are present (e.g., CAdES with system + person certs).
 */
export function parsePkcs7Certificates(derBytes: Uint8Array): {
  certs: CertificateInfo[]
  signerIdentifier: SignerIdentifier | null
} {
  try {
    const root = parseAsn1(derBytes)

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT }
    if (root.tag !== ASN1_TAG.SEQUENCE || root.children.length < 2) {
      return { certs: [], signerIdentifier: null }
    }

    const contentTypeNode = root.children[0]
    if (contentTypeNode.tag !== ASN1_TAG.OID) {
      return { certs: [], signerIdentifier: null }
    }

    const contentType = decodeOid(contentTypeNode.content)
    if (contentType !== OID_SIGNED_DATA) {
      return { certs: [], signerIdentifier: null }
    }

    // content [0] EXPLICIT → contains the SignedData SEQUENCE
    const contentWrapper = root.children[1]
    if (contentWrapper.tagClass !== 2 || contentWrapper.tagNumber !== 0) {
      return { certs: [], signerIdentifier: null }
    }

    const signedData = contentWrapper.children[0]
    if (!signedData || signedData.tag !== ASN1_TAG.SEQUENCE) {
      return { certs: [], signerIdentifier: null }
    }

    // SignedData ::= SEQUENCE {
    //   version, digestAlgorithms, encapContentInfo,
    //   certificates [0] IMPLICIT,  <-- what we want
    //   crls [1] IMPLICIT (optional),
    //   signerInfos SET
    // }

    // Find certificates [0] IMPLICIT — tag 0xA0
    const certsNode = findContext(signedData, 0)
    if (!certsNode) {
      return { certs: [], signerIdentifier: null }
    }

    // Parse each certificate in the set
    const certs: CertificateInfo[] = []
    for (const child of certsNode.children) {
      try {
        const cert = parseCertificateNode(child)
        if (cert) {
          // Capture the raw DER bytes of THIS certificate so downstream
          // consumers can re-decode and verify it cryptographically.
          const certEnd = child.contentOffset + child.contentLength
          const rawDer = derBytes.subarray(child.nodeStart, certEnd)
          cert.rawDerHex = bytesToHex(rawDer)
          certs.push(cert)
        }
      } catch {
        // Best-effort: skip certificates that fail to parse.
      }
    }

    // Extract SignerInfo issuer+serial to identify the actual signer cert.
    // signerInfos is the last SET in SignedData.
    // SignerInfo ::= SEQUENCE { version, sid SignerIdentifier, ... }
    // SignerIdentifier ::= CHOICE { issuerAndSerialNumber IssuerAndSerialNumber }
    // IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
    let signerIdentifier: SignerIdentifier | null = null
    try {
      const signerInfosNode = signedData.children.find(
        (c) => c.tag === ASN1_TAG.SET && c !== signedData.children[1],
      )
      if (signerInfosNode && signerInfosNode.children.length > 0) {
        const firstSignerInfo = signerInfosNode.children[0]
        if (firstSignerInfo.tag === ASN1_TAG.SEQUENCE && firstSignerInfo.children.length >= 2) {
          // Skip version (INTEGER), next should be issuerAndSerialNumber (SEQUENCE)
          const sidNode = firstSignerInfo.children[1]
          if (sidNode.tag === ASN1_TAG.SEQUENCE && sidNode.children.length >= 2) {
            const issuerFields = parseRdnSequence(sidNode.children[0])
            const serial = decodeInteger(sidNode.children[1])
            signerIdentifier = {
              issuerCN: issuerFields.CN || issuerFields.O || '',
              serial,
            }
          }
        }
      }
    } catch {
      // Best-effort: SignerInfo identifier is optional.
    }

    return { certs, signerIdentifier }
  } catch {
    return { certs: [], signerIdentifier: null }
  }
}

// ── X.509 Certificate Parsing ─────────────────────────────────────

/**
 * Parse ONE X.509 leaf certificate's DER into a generic `CertificateInfo`.
 *
 * Extracts subject/issuer DN, validity, and standard extensions (SAN, keyUsage,
 * extKeyUsage, basicConstraints→isCa, certificatePolicies→policyOids), and
 * captures the raw DER as hex. `role` defaults to `'end-entity'`.
 *
 * Only generic X.509 fields are returned — national-PKI enrichments are the
 * responsibility of higher-level consumers.
 */
export function parseCertificate(der: Uint8Array): CertificateInfo {
  const node = parseAsn1(der)
  const info = parseCertificateNode(node)
  if (!info) {
    throw new Error('parseCertificate: input is not a valid X.509 Certificate SEQUENCE')
  }
  info.rawDerHex = bytesToHex(der)
  return info
}

/**
 * Parse a single X.509 certificate from its already-decoded ASN.1 node.
 * Returns null if the node is not a Certificate SEQUENCE.
 *
 * `rawDerHex` is left as `''` here — callers fill it in from the source bytes.
 */
function parseCertificateNode(node: Asn1Node): CertificateInfo | null {
  if (node.tag !== ASN1_TAG.SEQUENCE) return null

  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  const tbs = node.children[0]
  if (!tbs || tbs.tag !== ASN1_TAG.SEQUENCE) return null

  // TBSCertificate ::= SEQUENCE {
  //   version [0] EXPLICIT INTEGER,
  //   serialNumber INTEGER,
  //   signature AlgorithmIdentifier,
  //   issuer Name,
  //   validity SEQUENCE { notBefore, notAfter },
  //   subject Name,
  //   subjectPublicKeyInfo,
  //   ... extensions [3] ...
  // }

  let idx = 0

  // version [0] EXPLICIT (optional — v1 certs don't have it)
  if (tbs.children[idx]?.tagClass === 2 && tbs.children[idx]?.tagNumber === 0) {
    idx++
  }

  // serialNumber
  const serialNode = tbs.children[idx++]
  const serialNumber = serialNode ? decodeInteger(serialNode) : ''

  // signature (AlgorithmIdentifier) — skip
  idx++

  // issuer Name
  const issuerNode = tbs.children[idx++]
  const issuerFields = issuerNode ? parseRdnSequence(issuerNode) : {}

  // validity
  const validityNode = tbs.children[idx++]
  let validFrom: string | null = null
  let validTo: string | null = null
  if (validityNode && validityNode.children.length >= 2) {
    try {
      validFrom = decodeTime(validityNode.children[0])
    } catch {
      /* ignore */
    }
    try {
      validTo = decodeTime(validityNode.children[1])
    } catch {
      /* ignore */
    }
  }

  // subject Name. Read without advancing: this is the last positional field
  // this parser wants. Next in the TBSCertificate would be subjectPublicKeyInfo,
  // which is not read here, and extensions are located below by their context
  // tag rather than by position, so nothing reads `idx` again. Two dead
  // advances used to sit here; eslint 10 promoted `no-useless-assignment`,
  // which is what surfaced them. Anyone resuming the positional walk must
  // start from `idx + 1` (subjectPublicKeyInfo).
  const subjectNode = tbs.children[idx]
  const subjectFields = subjectNode ? parseRdnSequence(subjectNode) : {}

  // Parse extensions [3] for BasicConstraints, policies, SAN, key usage
  let isCa = false
  const policyOids: string[] = []
  const subjectAltNames: string[] = []
  const keyUsage: string[] = []
  const extKeyUsage: string[] = []

  const extensionsWrapper = findContext(tbs, 3)
  if (extensionsWrapper && extensionsWrapper.children.length > 0) {
    const extensions = extensionsWrapper.children[0]
    if (extensions) {
      for (const ext of extensions.children) {
        parseExtension(ext, {
          isCa: (v) => (isCa = v),
          policyOids,
          subjectAltNames,
          keyUsage,
          extKeyUsage,
        })
      }
    }
  }

  return {
    commonName: subjectFields['CN'] || 'Unknown',
    organization: subjectFields['O'] || null,
    organizationalUnit: subjectFields['OU'] || null,
    country: subjectFields['C'] || null,
    serialNumber,
    issuerCommonName: issuerFields['CN'] || 'Unknown',
    issuerOrganization: issuerFields['O'] || null,
    validFrom,
    validTo,
    email: subjectFields['email'] || null,
    isCa,
    policyOids,
    subjectAltNames,
    keyUsage,
    extKeyUsage,
    role: 'end-entity', // Will be assigned by chain builder
    rawDerHex: '', // Filled in by the caller from the source bytes
  }
}

/**
 * Parse a Name (RDN SEQUENCE) into a field map.
 */
function parseRdnSequence(node: Asn1Node): Record<string, string> {
  const fields: Record<string, string> = {}

  // Name ::= SEQUENCE OF RelativeDistinguishedName
  // RDN ::= SET OF AttributeTypeAndValue
  // ATV ::= SEQUENCE { type OID, value ANY }
  for (const rdn of node.children) {
    if (rdn.tag !== ASN1_TAG.SET) continue
    for (const atv of rdn.children) {
      if (atv.tag !== ASN1_TAG.SEQUENCE || atv.children.length < 2) continue
      const oidNode = atv.children[0]
      const valueNode = atv.children[1]
      if (oidNode.tag !== ASN1_TAG.OID) continue

      const oid = decodeOid(oidNode.content)
      const fieldName = RDN_OIDS[oid] || oid
      const value = decodeString(valueNode)
      fields[fieldName] = value
    }
  }

  return fields
}

/**
 * Parse a single generic X.509 extension.
 */
function parseExtension(
  ext: Asn1Node,
  out: {
    isCa: (v: boolean) => void
    policyOids: string[]
    subjectAltNames: string[]
    keyUsage: string[]
    extKeyUsage: string[]
  },
): void {
  if (ext.tag !== ASN1_TAG.SEQUENCE || ext.children.length < 2) return

  const oidNode = ext.children[0]
  if (oidNode.tag !== ASN1_TAG.OID) return
  const oid = decodeOid(oidNode.content)

  // Find the extension value (OCTET STRING — may be 2nd or 3rd child depending on critical flag)
  const valueNode = ext.children.find((c) => c.tag === ASN1_TAG.OCTET_STRING)
  if (!valueNode) return

  try {
    const inner = parseAsn1(valueNode.content)

    // 2.5.29.19 = BasicConstraints
    if (oid === '2.5.29.19') {
      if (inner.tag === ASN1_TAG.SEQUENCE) {
        const caNode = inner.children[0]
        if (caNode && caNode.tag === 0x01 && caNode.content[0] !== 0) {
          out.isCa(true)
        }
      }
    }

    // 2.5.29.32 = CertificatePolicies
    if (oid === '2.5.29.32') {
      if (inner.tag === ASN1_TAG.SEQUENCE) {
        for (const policyInfo of inner.children) {
          if (policyInfo.tag === ASN1_TAG.SEQUENCE && policyInfo.children.length > 0) {
            const policyOid = policyInfo.children[0]
            if (policyOid.tag === ASN1_TAG.OID) {
              out.policyOids.push(decodeOid(policyOid.content))
            }
          }
        }
      }
    }

    // 2.5.29.17 = SubjectAlternativeName
    if (oid === '2.5.29.17') {
      if (inner.tag === ASN1_TAG.SEQUENCE) {
        for (const name of inner.children) {
          if (name.tagClass === 2) {
            out.subjectAltNames.push(decodeString(name))
          }
        }
      }
    }

    // 2.5.29.15 = KeyUsage (BIT STRING)
    if (oid === '2.5.29.15') {
      if (inner.tag === ASN1_TAG.BIT_STRING && inner.content.length >= 2) {
        const unusedBits = inner.content[0]
        const bytes = inner.content.slice(1)
        for (let byteIdx = 0; byteIdx < bytes.length; byteIdx++) {
          for (let bit = 7; bit >= 0; bit--) {
            const bitPos = byteIdx * 8 + (7 - bit)
            if (bitPos >= KEY_USAGE_BITS.length) break
            // Skip unused trailing bits in the last byte
            if (byteIdx === bytes.length - 1 && 7 - bit < unusedBits) continue
            if (bytes[byteIdx] & (1 << bit)) {
              out.keyUsage.push(KEY_USAGE_BITS[bitPos])
            }
          }
        }
      }
    }

    // 2.5.29.37 = ExtendedKeyUsage (SEQUENCE OF OID)
    if (oid === '2.5.29.37') {
      if (inner.tag === ASN1_TAG.SEQUENCE) {
        for (const ekuOid of inner.children) {
          if (ekuOid.tag === ASN1_TAG.OID) {
            const oidStr = decodeOid(ekuOid.content)
            out.extKeyUsage.push(EKU_OIDS[oidStr] || oidStr)
          }
        }
      }
    }
  } catch {
    // Extension parsing is best-effort
  }
}

// ── Chain Builder ─────────────────────────────────────────────────

/**
 * Build the certificate chain from signer to root.
 * Assigns roles: end-entity, intermediate, root.
 *
 * When `signerIdentifier` is provided (from PKCS#7 SignerInfo), uses it to
 * disambiguate between multiple non-CA certificates (e.g., CAdES signatures
 * that embed both a system/service cert and the actual person's cert).
 */
export function buildChain(
  certs: CertificateInfo[],
  signerIdentifier?: SignerIdentifier | null,
): CertificateInfo[] {
  if (certs.length === 0) return []

  // Identify roles
  for (const cert of certs) {
    if (cert.commonName === cert.issuerCommonName) {
      cert.role = 'root'
    } else if (cert.isCa) {
      cert.role = 'intermediate'
    } else {
      cert.role = 'end-entity'
    }
  }

  // When multiple end-entity certs exist, use SignerInfo to pick the real signer.
  // The SignerInfo contains the issuer+serial of the cert that actually signed.
  const endEntities = certs.filter((c) => c.role === 'end-entity')
  if (endEntities.length > 1 && signerIdentifier) {
    const matched = endEntities.find(
      (c) =>
        c.serialNumber === signerIdentifier.serial ||
        (c.issuerCommonName === signerIdentifier.issuerCN &&
          c.serialNumber === signerIdentifier.serial),
    )
    if (matched) {
      // Demote all other end-entities — they are ancillary certs (service certs, TSA, etc.)
      for (const ee of endEntities) {
        if (ee !== matched) {
          ee.role = 'intermediate' // keeps the chain logic working
        }
      }
    }
  }

  // Find the end-entity (signer) certificate
  const signer = certs.find((c) => c.role === 'end-entity')
  if (!signer) {
    // All are CAs — return sorted by chain
    return certs
  }

  // Build chain: signer → intermediate(s) → root
  const chain: CertificateInfo[] = [signer]
  let current = signer
  const maxDepth = certs.length // prevent infinite loops

  for (let i = 0; i < maxDepth; i++) {
    if (current.commonName === current.issuerCommonName) break // reached root
    const issuer = certs.find((c) => c.commonName === current.issuerCommonName && c !== current)
    if (!issuer) break
    chain.push(issuer)
    current = issuer
  }

  return chain
}

// ── Clean Display Name ────────────────────────────────────────────

/**
 * Clean up signer name — remove backslash escapes from PDF encoding.
 * e.g. "GUILLERMO CHAVARRIA CRUZ \\(FIRMA\\)" → "GUILLERMO CHAVARRIA CRUZ (FIRMA)"
 */
export function cleanSignerName(name: string): string {
  return name.replace(/\\(.)/g, '$1')
}

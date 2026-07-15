/**
 * Shared types for generic X.509 certificate parsing.
 */

export type { Asn1Node } from './asn1-parser.js'

/**
 * Generic X.509 certificate fields extracted from a single leaf certificate.
 *
 * National-PKI-specific enrichments (e.g. CR Firma Digital `subjectSerialNumber`,
 * `profesion`, `numeroColegiado`) are intentionally NOT part of this interface —
 * they are layered on top by higher-level consumers.
 */
export interface CertificateInfo {
  /** Subject Common Name */
  commonName: string
  /** Subject Organization */
  organization: string | null
  /** Subject Organizational Unit */
  organizationalUnit: string | null
  /** Subject Country */
  country: string | null
  /** Serial number (hex) */
  serialNumber: string
  /** Issuer Common Name */
  issuerCommonName: string
  /** Issuer Organization */
  issuerOrganization: string | null
  /** Validity — not before */
  validFrom: string | null
  /** Validity — not after */
  validTo: string | null
  /** Whether this is a CA certificate (from Basic Constraints) */
  isCa: boolean
  /** Certificate policy OIDs */
  policyOids: string[]
  /** Subject email (from RDN OID 1.2.840.113549.1.9.1) */
  email: string | null
  /** Subject Alternative Names (if present) */
  subjectAltNames: string[]
  /** Key Usage flags (from extension 2.5.29.15) */
  keyUsage: string[]
  /** Extended Key Usage OID labels (from extension 2.5.29.37) */
  extKeyUsage: string[]
  /** Position in chain: 'end-entity' | 'intermediate' | 'root' */
  role: 'end-entity' | 'intermediate' | 'root'
  /**
   * Raw DER bytes of this certificate as a hex string. Captured at parse time
   * so downstream consumers can re-decode the cert (e.g. with pkijs) and run
   * real cryptographic chain validation against bundled trust anchors.
   */
  rawDerHex: string
}

/** Issuer + serial extracted from PKCS#7 SignerInfo — identifies the actual signer cert */
export interface SignerIdentifier {
  issuerCN: string
  serial: string
}

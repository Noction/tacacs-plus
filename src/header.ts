import { Buffer } from 'node:buffer'
import { notImplemented } from './utils'

export interface Versions {
  majorVersion: MajorVersion
  minorVersion: MinorVersion
}
export interface BaseHeaderRecord {
  majorVersion: MajorVersion
  minorVersion: MinorVersion
  flags: Flag
  length: number
  seqNo: number
  sessionId: number
  type: HeaderType
}

export interface UnknownHeader {
  majorVersion: number
  minorVersion: number
  flags: number
  length: number
  seqNo: number
  sessionId: number
  type: number
}

export function createVersionByte({ majorVersion, minorVersion }: Versions) {
  return ((majorVersion & 0xF) << 4) | (minorVersion & 0xF)
}

export const HEADER_TYPES = {
  TAC_PLUS_AUTHEN: 0x01,
  TAC_PLUS_AUTHOR: 0x02,
  TAC_PLUS_ACCT: 0x03,
} as const

export const ALLOWED_HEADER_TYPES = Object.values(HEADER_TYPES)

export type HeaderType = typeof ALLOWED_HEADER_TYPES[number]

function isHeaderType(maybeType: number): maybeType is HeaderType {
  return (ALLOWED_HEADER_TYPES as number[]).includes(maybeType)
}

export const FLAGS = {
  TAC_PLUS_UNENCRYPTED_FLAG: 0x01,
  TAC_PLUS_SINGLE_CONNECT_FLAG: 0x04,
} as const

export const ALLOWED_FLAGS = Object.values(FLAGS)

function isFlag(maybeFlag: number): maybeFlag is Flag {
  return (ALLOWED_FLAGS as number[]).includes(maybeFlag)
}

export type Flag = typeof FLAGS[keyof typeof FLAGS]

export const MAJOR_VERSIONS = {
  TAC_PLUS_MAJOR_VER_DEFAULT: 0x0,
  TAC_PLUS_MAJOR_VER: 0xC,
} as const

const ALLOWED_MAJOR_VERSIONS = Object.values(MAJOR_VERSIONS)

type MajorVersion = typeof ALLOWED_MAJOR_VERSIONS[number]

function isMajorVersion(maybeMajorVersion: number): maybeMajorVersion is MajorVersion {
  return (ALLOWED_MAJOR_VERSIONS as number[]).includes(maybeMajorVersion)
}

export const MINOR_VERSIONS = {
  TAC_PLUS_MINOR_VER_DEFAULT: 0x0,
  TAC_PLUS_MINOR_VER_ONE: 0x1,
} as const

const ALLOWED_MINOR_VERSIONS = Object.values(MINOR_VERSIONS)

type MinorVersion = typeof ALLOWED_MINOR_VERSIONS[number]

function isMinorVersion(maybeMinorVersion: number): maybeMinorVersion is MinorVersion {
  return (ALLOWED_MINOR_VERSIONS as number[]).includes(maybeMinorVersion)
}

function validateHeader({ majorVersion, minorVersion, flags, type, length, seqNo, sessionId }: UnknownHeader) {
  if (!isMajorVersion(majorVersion)) {
    throw new Error('Invalid major version')
  }

  if (!isMinorVersion(minorVersion)) {
    throw new Error('Invalid minor version')
  }

  if (!isHeaderType(type)) {
    throw new Error('Invalid header type')
  }

  if (!isFlag(flags)) {
    throw new Error('Invalid flag')
  }

  return {
    majorVersion,
    minorVersion,
    flags,
    type,
    length,
    seqNo,
    sessionId,
  }
}

export type Secret = string | null

export type HeaderRecord =
  & BaseHeaderRecord
  & Record<'isEncrypted' | 'isSingleConnection', boolean>

export class Header {
  readonly #majorVersion: HeaderRecord['majorVersion']
  readonly #minorVersion: HeaderRecord['minorVersion']
  readonly #type: HeaderType
  readonly #flags: Flag
  readonly #seqNo: number
  readonly #sessionId: number
  readonly #length: number

  constructor(unknownHeader: UnknownHeader) {
    const {
      majorVersion,
      minorVersion,
      type,
      flags,
      seqNo,
      sessionId,
      length,
    } = validateHeader(unknownHeader)

    this.#majorVersion = majorVersion
    this.#minorVersion = minorVersion
    this.#type = type
    this.#flags = flags
    this.#seqNo = seqNo
    this.#sessionId = sessionId
    this.#length = length
  }

  get version() {
    return createVersionByte({
      majorVersion: this.#majorVersion,
      minorVersion: this.#minorVersion,
    })
  }

  get sessionId() {
    return this.#sessionId
  }

  get length() {
    return this.#length
  }

  get seqNo() {
    return this.#seqNo
  }

  get isEncrypted() {
    return !((this.#flags & FLAGS.TAC_PLUS_UNENCRYPTED_FLAG) === FLAGS.TAC_PLUS_UNENCRYPTED_FLAG)
  }

  get isSingleConnection() {
    return ((this.#flags & FLAGS.TAC_PLUS_SINGLE_CONNECT_FLAG) === FLAGS.TAC_PLUS_UNENCRYPTED_FLAG)
  }

  get type() {
    return this.#type
  }

  toBuffer() {
    const buffer = Buffer.alloc(Header.SIZE)

    const versionByte = createVersionByte({
      majorVersion: this.#majorVersion,
      minorVersion: this.#minorVersion,
    })

    buffer.writeUInt8(versionByte, 0)
    buffer.writeUInt8(this.#type, 1)
    buffer.writeUInt8(this.#seqNo, 2)
    buffer.writeUInt8(this.#flags, 3)
    buffer.writeUInt32BE(this.#sessionId, 4)
    buffer.writeUInt32BE(this.#length, 8)

    return buffer
  }

  /**
   * @throws Error
   * @param raw
   */
  static decode(raw: Buffer): Header {
    if (raw.length !== Header.SIZE) {
      throw new Error(`Header size must be ${Header.SIZE}, but received ${raw.length}`)
    }

    let offset = 0

    const versionByte = raw.subarray(offset, 1).readUInt8(0)
    offset += 1

    const majorVersion = ((versionByte >> 4) & 0xF)
    const minorVersion = (versionByte & 0xF)

    const type = raw.subarray(offset, 2).readUInt8(0)
    offset += 1

    const seqNo = raw.subarray(offset, 3).readUInt8(0)
    if (seqNo === 255) {
      notImplemented('SeqNo is 255, you should handle restart the session')
    }
    offset += 1

    const flags = raw.subarray(offset, 4).readUint8(0)
    offset += 1

    const sessionId = raw.subarray(offset, 8).readUInt32BE(0)
    offset += 4

    const length = raw.subarray(offset, 12).readUInt32BE(0)

    return new Header({
      majorVersion,
      minorVersion,
      type,
      flags,
      seqNo,
      sessionId,
      length,
    })
  }

  toFormatted() {
    return JSON.stringify({
      majorVersion: this.#majorVersion,
      minorVersion: this.#minorVersion,
      type: this.#type,
      flags: this.#flags,
      seqNo: this.#seqNo,
      sessionId: this.#sessionId,
      length: this.#length,
    }, null, 2)
  }

  static readonly SIZE = 12
  static readonly DEFAULT_HEADER: BaseHeaderRecord = {
    majorVersion: MAJOR_VERSIONS.TAC_PLUS_MAJOR_VER_DEFAULT,
    minorVersion: MINOR_VERSIONS.TAC_PLUS_MINOR_VER_DEFAULT,
    type: 0,
    seqNo: 0x1,
    flags: FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
    sessionId: 0x0,
    length: 0x0,
  }
}

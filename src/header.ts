import { Buffer } from 'node:buffer'

// TODO(lwvemike): remove before release
function todo(message: string) {
  throw new Error(`TODO: ${message}`)
}

interface Versions {
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

function createVersionByte({ majorVersion, minorVersion }: Versions) {
  return ((majorVersion & 0xF) << 4) | (minorVersion & 0xF)
}

export const HEADER_TYPES = {
  // TODO(lwvemike): maybe is not valid
  TAC_DEFAULT: 0x00,
  TAC_PLUS_AUTHEN: 0x01, // Authentication
  TAC_PLUS_AUTHOR: 0x02, // Authorization
  TAC_PLUS_ACCT: 0x03, // Accounting
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

type HeaderRecord =
  & BaseHeaderRecord
  & Record<'isEncrypted' | 'isSingleConnection', boolean>

export class Header {
  /**
   * @throws Error
   * @param raw
   */
  static decode(raw: Buffer): HeaderRecord {
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
      todo('SeqNo is 255, you should handle restart the session')
    }
    offset += 1

    const flags = raw.subarray(offset, 4).readUint8(0)
    offset += 1

    const sessionId = raw.subarray(offset, 8).readUInt32BE(0)
    offset += 4

    const length = raw.subarray(offset, 12).readUInt32BE(0)

    const header = validateHeader({
      majorVersion,
      minorVersion,
      flags,
      type,
      length,
      seqNo,
      sessionId,
    })

    return {
      ...header,
      isEncrypted: !((header.flags & FLAGS.TAC_PLUS_UNENCRYPTED_FLAG) === FLAGS.TAC_PLUS_UNENCRYPTED_FLAG),
      isSingleConnection: ((header.flags & FLAGS.TAC_PLUS_SINGLE_CONNECT_FLAG) === FLAGS.TAC_PLUS_UNENCRYPTED_FLAG),
    }
  }

  static create(unknownHeader: UnknownHeader = Header.DEFAULT_HEADER): Buffer {
    const buffer = Buffer.alloc(Header.SIZE)

    const {
      majorVersion,
      minorVersion,
      type,
      flags,
      seqNo,
      sessionId,
      length,
    } = validateHeader(unknownHeader)

    const versionByte = createVersionByte({ majorVersion, minorVersion })

    buffer.writeUInt8(versionByte, 0)
    buffer.writeUInt8(type, 1)
    buffer.writeUInt8(seqNo, 2)
    buffer.writeUInt8(flags, 3)
    buffer.writeUInt32BE(sessionId, 4)
    buffer.writeUInt32BE(length, 8)

    return buffer
  }

  static readonly SIZE = 12
  static readonly DEFAULT_HEADER: BaseHeaderRecord = {
    majorVersion: MAJOR_VERSIONS.TAC_PLUS_MAJOR_VER_DEFAULT,
    minorVersion: MINOR_VERSIONS.TAC_PLUS_MINOR_VER_DEFAULT,
    type: HEADER_TYPES.TAC_DEFAULT,
    seqNo: 0x1,
    flags: FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
    sessionId: 0x0,
    length: 0x0,
  }
}

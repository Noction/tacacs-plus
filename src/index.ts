import type { Buffer } from 'node:buffer'

class TacacsPlusError extends Error {
  constructor(message: string) {
    super(`[@noction/tacacs-plus] ${message}`)
  }
}

const _DEFAULT_PORT = 49
const _TAC_PLUS_MAJOR_VER = 0xC
const _TAC_PLUS_MINOR_VER_DEFAULT = 0x0
const _TAC_PLUS_MINOR_VER_ONE = 0x1

export enum Flags {
  TAC_PLUS_UNENCRYPTED_FLAG = 0x01,
  TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04,
}

export enum PacketType {
  TAC_PLUS_AUTHEN = 0x01, // Authentication
  TAC_PLUS_AUTHOR = 0x02, // Authorization
  TAC_PLUS_ACCT = 0x03, // Accounting
}

export class Header {
  #majorVersion: number // 4 bits
  #minorVersion: number // 4 bits
  #type: PacketType // 1 byte
  #seqNo: number // 1 byte
  #flags: Flags// 1 byte
  #sessionId: number // 4 bytes
  #length: number // 4 bytes

  constructor(
    majorVersion: number,
    minorVersion: number,
    type: PacketType,
    seqNo: number,
    flags: number,
    sessionId: number,
    length: number,
  ) {
    this.#majorVersion = majorVersion
    this.#minorVersion = minorVersion
    this.#type = type
    this.#seqNo = seqNo
    this.#flags = flags
    this.#sessionId = sessionId
    this.#length = length
  }

  /**
   * @throws TacacsPlusError
   * @param raw
   * @returns
   */
  static decodeHeader(raw: Buffer) {
    if (raw.length !== Header.SIZE) {
      throw new TacacsPlusError(`Header size must be ${Header.SIZE}, but received ${raw.length}`)
    }

    let offset = 0

    const versionByte = raw.subarray(offset, 1).readUInt8(0)
    offset += 1

    const majorVersion = ((versionByte >> 4) & 0xF)
    const minorVersion = (versionByte & 0xF)

    const type = raw.subarray(offset, 2).readUInt8(0)
    offset += 1

    const seqNo = raw.subarray(offset, 3).readUInt8(0)
    offset += 1

    const flags = raw.subarray(offset, 4).readUint8(0)
    offset += 1

    const sessionId = raw.subarray(offset, 8).readUInt32BE(0)
    offset += 4

    const length = raw.subarray(offset, 12).readUInt32BE(0)

    return new Header(
      majorVersion,
      minorVersion,
      type,
      seqNo,
      flags,
      sessionId,
      length,
    )
  }

  get majorVersion(): number {
    return this.#majorVersion
  }

  get minorVersion(): number {
    return this.#minorVersion
  }

  get type(): PacketType {
    return this.#type
  }

  get seq_no(): number {
    return this.#seqNo
  }

  get flags(): number {
    return this.#flags
  }

  get session_id(): number {
    return this.#sessionId
  }

  get length(): number {
    return this.#length
  }

  static readonly SIZE = 12
}

import { Buffer } from 'node:buffer'
import type { Secret } from './header'
import { HEADER_TYPES, Header } from './header'
import { Authentication } from './authentication'
import { isOdd } from './helpers'
import { notImplemented } from './utils'

export class Packet {
  readonly #header: Header
  readonly #bodyBuffer: Buffer
  readonly #secret: Secret

  constructor(header: Header, bodyBuffer: Buffer, secret: Secret) {
    this.#header = header
    this.#bodyBuffer = bodyBuffer
    this.#secret = secret
  }

  get body() {
    if (this.#header.isEncrypted) {
      return this.encrypt(this.#bodyBuffer)
    }

    return this.#bodyBuffer
  }

  get header() {
    return this.#header
  }

  toBuffer() {
    return Buffer.concat([this.#header.toBuffer(), this.body])
  }

  static decodePacket(raw: Buffer) {
    const headerBuffer = raw.subarray(0, Header.SIZE)
    const header = Header.decode(headerBuffer)

    const body = raw.subarray(Header.SIZE, Header.SIZE + header.length)

    let data = body
    if (header.isEncrypted) {
      // TODO(lwvemike): handle encryption
      data = body
    }

    if (header.type === HEADER_TYPES.TAC_PLUS_AUTHEN) {
      const shouldAuthContinue = isOdd(header.seqNo)
      if (header.seqNo === 1) {
        notImplemented('Authentication start')
      }

      if (shouldAuthContinue) {
        notImplemented('Authentication continue')
      }

      return Authentication.decodeAuthReply(data, header.length)
    }

    if (header.type === HEADER_TYPES.TAC_PLUS_AUTHOR) {
      notImplemented('Authorization')
    }
    else if (header.type === HEADER_TYPES.TAC_PLUS_ACCT) {
      notImplemented('Accounting')
    }
  }

  // private encrypt(bodyBuffer: Buffer): Buffer {
  //   const bodyLength = bodyBuffer.length

  //   const unhashed = Buffer.concat([
  //     Buffer.alloc(4),
  //     Buffer.from(this.#secret ?? '', 'utf8'),
  //     Buffer.alloc(1),
  //     Buffer.alloc(1),
  //   ])

  //   unhashed.writeUInt32BE(this.#header.sessionId, 0)
  //   unhashed.writeUInt8(this.#header.version, 4)
  //   unhashed.writeUInt8(this.#header.seqNo, 5)

  //   let pad = createHash('md5')
  //     .update(unhashed)
  //     .digest()

  //   while (pad.length < bodyLength) {
  //     const digested = createHash('md5')
  //       .update(pad)
  //       .digest()

  //     pad = Buffer.concat([pad, digested])
  //   }

  //   pad = pad.subarray(0, bodyLength)

  //   const packetBody = Buffer.alloc(bodyLength)

  //   for (let i = 0; i < bodyLength; i += 1) {
  //     packetBody[i] = bodyBuffer[i] ^ pad[i]
  //   }

  //   return packetBody
  // }
}

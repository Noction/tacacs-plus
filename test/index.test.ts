import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { FLAGS, HEADER_TYPES, Header } from '../src/header'

describe('@noction/tacacs-plus', () => {
  describe('header', () => {
    describe('decodeHeader', () => {
      it('should decode a valid header', () => {
        const buffer = Buffer.from([
          0x12,
          0x01,
          0x42,
          FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
          0x00,
          0x00,
          0x00,
          0x01,
          0x00,
          0x00,
          0x00,
          0x0C,
        ])

        const header = Header.decode(buffer)

        expect(header.majorVersion).toBe(1)
        expect(header.minorVersion).toBe(2)
        expect(header.type).toBe(HEADER_TYPES.TAC_PLUS_AUTHEN)
        expect(header.seqNo).toBe(66)
        expect(header.flags).toBe(FLAGS.TAC_PLUS_UNENCRYPTED_FLAG)
        expect(header.sessionId).toBe(1)
        expect(header.length).toBe(12)

        expect(header.isEncrypted).toBe(false)
        expect(header.isSingleConnection).toBe(false)
      })

      it('should throw an error for an invalid header size', () => {
        const invalidBuffer = Buffer.from([0x00, 0x01])

        expect(() => Header.decode(invalidBuffer)).toThrowError(
          'Header size must be 12, but received 2',
        )
      })
    })

    describe('create', () => {
      it('should create a valid header with default values', () => {
        const defaultHeader = Header.create()

        expect(defaultHeader).toBeInstanceOf(Buffer)
        expect(defaultHeader.length).toBe(Header.SIZE)
      })

      it('should create a custom header with specified values', () => {
        const customHeader = Header.create({
          majorVersion: 1,
          minorVersion: 2,
          type: HEADER_TYPES.TAC_PLUS_ACCT,
          seqNo: 42,
          flags: FLAGS.TAC_PLUS_SINGLE_CONNECT_FLAG,
          sessionId: 123456,
          length: 100,
        })

        expect(customHeader).toBeInstanceOf(Buffer)
        expect(customHeader.length).toBe(Header.SIZE)
      })
    })
  })
})

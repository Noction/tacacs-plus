import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { Header, PacketType } from '../src'

describe('@noction/tacacs-plus', () => {
  describe('header', () => {
    it('should decode a valid header', () => {
      const buffer = Buffer.from([
        0x12,
        0x01,
        0x42,
        0x10,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x0C,
      ])

      const header = Header.decodeHeader(buffer)

      expect(header.majorVersion).toBe(1)
      expect(header.minorVersion).toBe(2)
      expect(header.type).toBe(PacketType.TAC_PLUS_AUTHEN)
      expect(header.seq_no).toBe(66)
      expect(header.flags).toBe(16)
      expect(header.session_id).toBe(1)
      expect(header.length).toBe(12)
    })

    it('should throw an error for an invalid header size', () => {
      const invalidBuffer = Buffer.from([0x00, 0x01])

      expect(() => Header.decodeHeader(invalidBuffer)).toThrowError(
        'Header size must be 12, but received 2',
      )
    })
  })
})
